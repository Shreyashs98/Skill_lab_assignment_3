# Skill Lab Assignment 3

## Setup

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Shreyashs98/Skill_lab_assignment_3.git
    ```

2. **Install dependencies:**

    ```bash
    npm install
    ```

3. **Create a `.env` file in the root directory with the following content:**

    ```env
    SALTROUNDS=10
    GOOGLE_CLIENT_ID='your-google-client-id'
    GOOGLE_CLIENT_SECRET='your-google-client-secret'
    ```

    Make sure to replace `'your-google-client-id'` and `'your-google-client-secret'` with your actual Google OAuth credentials.

## Run

4. **Start the application:**

    ```bash
    npm start
    ```

    The server will run on `http://localhost:3000` by default.

## OTP Verification

To check OTP verification, open `localhost:3000` in Chrome, then register using a real email and a fake password with the role set as 'user'. You will receive an OTP to your email. Enter your email and the received OTP during login.

---
