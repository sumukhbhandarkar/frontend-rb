const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LinkedInStrategy = require("passport-linkedin-oauth2").Strategy;

require("dotenv").config();

const LINKEDIN_KEY = process.env.LINKEDIN_CLIENT_ID;
const LINKEDIN_SECRET = process.env.LINKEDIN_CLIENT_SECRET;
const LINKEDIN_CALLBACK_URL =
  process.env.LINKEDIN_CALLBACK_URL ||
  "http://localhost:3000/auth/linkedin/callback";

passport.use(
  new LinkedInStrategy(
    {
      clientID: LINKEDIN_KEY,
      clientSecret: LINKEDIN_SECRET,
      callbackURL: LINKEDIN_CALLBACK_URL,
      scope: ["r_liteprofile"],
    },
    function (accessToken, refreshToken, profile, done) {
      // Here, you would look up or create the user in your DB
      return done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

const app = express();
const PORT = process.env.PORT || 3000;

app.use(
  session({
    secret: "referbuddy_secret",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, "public")));

app.get("/auth/linkedin", passport.authenticate("linkedin"));

app.get(
  "/auth/linkedin/callback",
  passport.authenticate("linkedin", { failureRedirect: "/signup.html" }),
  function (req, res) {
    // Successful authentication, redirect to dashboard
    res.redirect("/dashboard.html");
  }
);

app.get("/profile", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/signup.html");
  }
  res.send(
    `<h1>LinkedIn Profile</h1><pre>${JSON.stringify(
      req.user,
      null,
      2
    )}</pre><a href="/">Home</a>`
  );
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
