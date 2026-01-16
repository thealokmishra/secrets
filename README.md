# Authentication & Secrets App

A full authentication-focused web application demonstrating local authentication, Google OAuth 2.0, session handling, using Passport.js and CRUD operations.

Users can register, log in, authenticate via Google, and create or update a personal secret displayed on the homepage.  
This project is designed to showcase real-world authentication flows and backend logic rather than UI complexity.

---

## Live Demo

👉 **Live App:** [https://secrets-oa7h.onrender.com]

---

## How to use

- Open the live link
- Register yourself with any test email and a password or signup using Google account (100% Secure)
- Login using email & password or Google
- Add or Update your secret

## Features

- User registration and login using Passport.js (Local Strategy)
- Authentication with Google OAuth 2.0
- Secure session handling with persistent storage
- Create, read, and update user secrets (CRUD)
- Protected routes for authenticated users only
- Environment-based configuration for local and production setups

---

## Tech Stack

- **Backend:** Node.js, Express.js
- **Authentication:** Passport.js, Google OAuth 2.0, bCrypt
- **Database:** PostgreSQL (Neon)
- **Templating Engine:** EJS
- **Frontend:** HTML, CSS, Bootstrap
- **Session Management:** express-session
- **Environment Variables:** dotenv

---

## Authentication Flow

- Users can register using email and password
- Existing users can log in with local credentials
- Users can authenticate using Google OAuth
- Sessions persist across page refreshes
- Authenticated users can submit and update a personal secret
- Secrets are stored securely in the database and rendered on the homepage

---

## Future Improvements

-Password reset and email verification
-Role-based access control
-Improved validation and error handling
-UI and accessibility enhancements

---

## Author

Built by **Alok Mishra**
Portfolio project showcasing authentication and full-stack fundamentals.

