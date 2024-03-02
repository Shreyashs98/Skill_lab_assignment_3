import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import session from 'express-session';
import NodeCache from 'node-cache';
import nodemailer from 'nodemailer';
import randomize from 'randomatic';
import dotenv from 'dotenv';

const cache = new NodeCache();
const app = express();

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  role: { type: String, enum: ['user', 'specialUser', 'author'], default: 'user' },
  otp: String,
});

const User = mongoose.model('User', userSchema);

dotenv.config();

mongoose.connect('mongodb://0.0.0.0:27017/Blogs');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'itsme31121999',
    pass: 'wvyu anxe rdrc dmhi',
  },
});

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error'));

db.once('open', () => {
  console.log('MongoDB connected');
});

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'shreyashs',
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => res.render('home.ejs'));
app.get('/login', (req, res) => res.render('login.ejs'));
app.get('/register', (req, res) => res.render('register.ejs'));
app.get('/logout', (req, res) => req.logout(() => res.redirect('/')));

app.get('/secrets', async (req, res) => {
  try {
    const foundUsers = await User.find({ feedback: { $ne: null } });
    if (foundUsers) {
      console.log(foundUsers);
      res.render('secrets.ejs', { usersWithSecrets: foundUsers });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);

app.get(
  '/auth/google/secrets',
  passport.authenticate('google', {
    successRedirect: '/secrets',
    failureRedirect: '/login',
  })
);

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/secrets',
    failureRedirect: '/login',
  })
);

app.post('/register', async (req, res) => {
  const { username: email, password, role } = req.body;

  try {
    const user = await User.findOne({ email });
    if (user) return res.redirect('/login');

    const otp = randomize('0', 6);
    console.log("OTP is ",otp);
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OTP for Registration',
      text: `Your OTP for registration is: ${otp}`,
    };

    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        console.error('Error sending OTP:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      const hash = await bcrypt.hash(password, Number(process.env.SALTROUNDS) || 10);
      const newUser = new User({
        _id: new mongoose.Types.ObjectId(),
        email,
        password: hash,
        role,
        otp,
      });

      await newUser.save();
      res.redirect('/login');
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/submit', (req, res) => {
  console.log(req.user, 'submitUser');
  if (req.isAuthenticated()) res.render('submit.ejs');
  else res.redirect('/login');
});

app.post('/submit', async (req, res) => {
  if (req.isAuthenticated()) {
    console.log(req.body);
    console.log(req.user, 'user');

    try {
      if (!req.body || !req.body.secret)
        return res.status(400).json({ error: 'Bad Request. Missing secret in request body.' });

      const updatedUser = await User.findOneAndUpdate(
        { googleId: req.user.googleId },
        { $set: { feedback: req.body.secret } },
        { new: true }
      );

      console.log(updatedUser, 'updatedUser');
      res.send('feedback updated');
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.get('/verify-otp', (req, res) => {
  const email = req.query.email;
  res.render('verify-otp.ejs', { email });
});

app.post('/verify-otp', async (req, res) => {
  const email = req.body.email;
  const userOTP = req.body.otp;

  try {
    const user = await User.findOne({ email });
    if (user && user.otp === userOTP) {
      await User.updateOne({ email }, { $set: { otp: null } });
      req.login(user, (err) => {
        if (err) {
          console.error('Error during login:', err);
        } else {
          res.redirect('/secrets');
        }
      });
    } else {
      res.redirect('/login');
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


passport.use(
  'local',
  new LocalStrategy(async (email, password, cb) => {
    try {
      const user = await User.findOne({ email });

      if (user) {
        const valid = await bcrypt.compare(password, user.password);
        return valid ? cb(null, user) : cb(null, false);
      } else {
        return cb(null, false, { message: 'User not found' });
      }
    } catch (err) {
      console.error(err, 'local error');
      return cb(err);
    }
  })
);

passport.use(
  'google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(accessToken);
        console.log(profile);
        const user = await User.findOne({ email: profile.email });

        if (!user) {
          const newUser = new User({
            email: profile.email,
            googleId: profile.id,
          });
          await newUser.save();
          return cb(null, newUser);
        } else {
          return cb(null, user);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => cb(null, String(user._id)));

passport.deserializeUser(async (id, cb) => {
  try {
    const user = await User.findById(id);
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
