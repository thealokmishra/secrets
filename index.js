import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
const { Pool } = pg;

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.set("view engine", "ejs");

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const result = await db.query("SELECT NOW()");
console.log(result.rows);


app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  // 1. Check if the user is logged in
  if (req.isAuthenticated()) {

    // 2. Access the secret from req.user (which Passport fetched from the DB)
    const userSecret = req.user.secret;

    if (userSecret === null || userSecret === "") {   //if userSecret is null or empty string

      res.render("secrets.ejs", { prompt: "Please update your secret", secretData: "" });  //render secretData prompt to add secret
    } else {
      res.render("secrets.ejs", { prompt: "My secret is", secretData: userSecret }); // 4. If exists, pass the actual secret from the DB (we dont need to query each time because we have it in req.user passport handles it by deserializeUser)
    }

  } else {
    // 5. If not authenticated, send them back to login
    res.redirect("/login");
  }
});

//TODO: Add a get route for the submit button
//Think about how the logic should work with authentication.

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// app.post(
//   "/login",
//   passport.authenticate("local", {
//     successRedirect: "/secrets",
//     failureRedirect: "/login",
//   })
// );

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }

    // If authentication fails (user not found or password wrong)
    if (!user) {
      return res.render("login", {
        errorMessage: "Please enter correct email and password"
      });
    }

    // If authentication succeeds, manually log in the user
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.redirect("/secrets");
    });
  })(req, res, next);
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

//TODO: Create the post route for submit.
//Handle the submitted data and add it to the database
app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;
  const username = req.user.email; // The email of the logged-in user

  try {
    // We update the existing user's row
    await db.query("UPDATE users SET secret = $1 WHERE email = $2", [
      submittedSecret,
      username,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.error(err);
    res.send("Error saving secret.");
  }
});


// local login strategy
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      console.log(err);
    }
  })
);


// Google OAuth strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      // callbackURL: "http://localhost:3000/auth/google/secrets",
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Serialize user to store in session
passport.serializeUser((user, cb) => {
  cb(null, user.id);
});


// Deserialize user from session
passport.deserializeUser(async (id, cb) => {
  try {
    // We take the ID from the cookie and find the LATEST data in the DB
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];

    // Passport now attaches this fresh user object to 'req.user'
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port http://localhost:${port}`);
});
