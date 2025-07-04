// Required dependencies: axios, jsonwebtoken, pg, express-session, connect-pg-simple, nodemailer
const express = require("express");
const path = require("path");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const nodemailer = require("nodemailer");
require("dotenv").config();

const CLIENT_ID = process.env.LINKEDIN_CLIENT_ID;
const CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET;
const REDIRECT_URI = process.env.LINKEDIN_CALLBACK_URL;
const SCOPE = "openid profile email";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(
  session({
    store: new pgSession({
      pool: pool,
      tableName: "session",
    }),
    secret: "referbuddy_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // true in production, false in dev
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: "lax",
    },
  })
);

app.use(express.json()); // for parsing JSON bodies

// Serve all static files except dashboard.html
app.use((req, res, next) => {
  if (req.path === "/dashboard.html") return next();
  express.static(path.join(__dirname, "public"))(req, res, next);
});

app.get("/auth/linkedin", (req, res) => {
  const authUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&scope=${encodeURIComponent(SCOPE)}`;
  res.redirect(authUrl);
});

app.get("/auth/linkedin/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send("Missing code");
  }
  try {
    // Exchange code for tokens
    const tokenResponse = await axios.post(
      "https://www.linkedin.com/oauth/v2/accessToken",
      null,
      {
        params: {
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
        },
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );
    const { id_token } = tokenResponse.data;
    if (!id_token) {
      return res.status(500).send("No id_token returned by LinkedIn");
    }
    // Decode the id_token to get user info
    const decoded = jwt.decode(id_token);
    // Store user in Postgres
    await pool.query(
      `INSERT INTO users (linkedin_id, name, email, picture)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (linkedin_id) DO UPDATE
         SET name = EXCLUDED.name, email = EXCLUDED.email, picture = EXCLUDED.picture`,
      [decoded.sub, decoded.name, decoded.email, decoded.picture]
    );
    // Set session
    req.session.user = {
      id: decoded.sub,
      name: decoded.name,
      email: decoded.email,
      picture: decoded.picture,
    };
    // Redirect to dashboard
    res.redirect("/dashboard.html");
  } catch (err) {
    console.error(
      "LinkedIn OAuth error:",
      err.response ? err.response.data : err
    );
    res
      .status(500)
      .send(
        "OAuth Error: " +
          (err.response ? JSON.stringify(err.response.data) : err.message)
      );
  }
});

// Protect dashboard.html
app.get("/dashboard.html", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/signup.html");
  }
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// Redirect logged-in users to dashboard on / or /index.html
app.get(["/", "/index.html"], (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard.html");
  }
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Email OTP sign-in endpoints
app.post("/auth/email/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ success: false, message: "Email required." });
  // Generate 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  req.session.otp = otp;
  req.session.otpEmail = email;
  // Send OTP email
  try {
    // Configure nodemailer (use your SMTP or Gmail credentials)
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Refer Buddy OTP",
      text: `Your OTP for Refer Buddy sign-in is: ${otp}`,
    });
    res.json({ success: true });
  } catch (err) {
    console.error("OTP email error:", err);
    res.json({ success: false, message: "Failed to send OTP email." });
  }
});

app.post("/auth/email/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp)
    return res.json({ success: false, message: "Email and OTP required." });
  if (req.session.otp !== otp || req.session.otpEmail !== email) {
    return res.json({ success: false, message: "Invalid OTP." });
  }
  // OTP is valid, log in user
  try {
    // Check if user exists
    let userRes = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    let user = userRes.rows[0];
    if (!user) {
      // Create user with just email
      const insertRes = await pool.query(
        "INSERT INTO users (email) VALUES ($1) RETURNING *",
        [email]
      );
      user = insertRes.rows[0];
    }
    req.session.user = {
      id: user.id || user.linkedin_id,
      name: user.name || "",
      email: user.email,
      picture: user.picture || "",
    };
    // Clear OTP from session
    delete req.session.otp;
    delete req.session.otpEmail;
    res.json({ success: true });
  } catch (err) {
    console.error("OTP verify error:", err);
    res.json({ success: false, message: "Server error." });
  }
});

// Fallback for all other routes
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

// Global error handler for better debugging
app.use((err, req, res, next) => {
  console.error("Global error:", err);
  res.status(500).send("Internal Server Error: " + err.message);
});
