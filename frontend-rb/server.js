// Required dependencies: axios, jsonwebtoken, pg, express-session, connect-pg-simple, nodemailer, multer
const express = require("express");
const path = require("path");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const nodemailer = require("nodemailer");
const multer = require("multer");
const fs = require("fs");
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
app.use(express.urlencoded({ extended: true })); // for parsing form data

// Serve all static files except subscription.html
app.use((req, res, next) => {
  if (req.path === "/subscription.html") return next();
  express.static(path.join(__dirname, "public"))(req, res, next);
});

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Multer setup for resume uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + ext);
  },
});
const upload = multer({
  storage: storage,
  fileFilter: function (req, file, cb) {
    const allowed = [
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only PDF, DOC, and DOCX files are allowed."));
    }
  },
  limits: { fileSize: 1 * 1024 * 1024 }, // 1MB limit
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
    res.redirect("/subscription.html");
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

// Protect subscription.html
app.get("/subscription.html", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/signup.html");
  }
  res.sendFile(path.join(__dirname, "public", "subscription.html"));
});

// Redirect logged-in users to subscription.html on / or /index.html
app.get(["/", "/index.html"], (req, res) => {
  if (req.session.user) {
    return res.redirect("/subscription.html");
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

app.post("/upload-resume", upload.single("resume"), async (req, res) => {
  if (!req.file) {
    return res.json({ success: false, message: "No file uploaded." });
  }

  try {
    const fileUrl = "/uploads/" + req.file.filename;

    // Save the resume URL to the user's account if they're logged in
    if (req.session.user) {
      const userId = req.session.user.id;
      await pool.query(
        "UPDATE users SET resume_url = $1 WHERE id = $2 OR linkedin_id = $2",
        [fileUrl, userId]
      );
    }

    res.json({ success: true, name: req.file.originalname, url: fileUrl });
  } catch (err) {
    console.error("Error saving resume URL:", err);
    res.json({ success: false, message: "Failed to save resume URL." });
  }
});

// Error handling middleware for multer file size limit
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.json({
        success: false,
        message: "File size too large. Please upload a file smaller than 1MB.",
      });
    }
  }
  next(error);
});

// Get user account details
app.get("/api/user/account", async (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "Not authenticated" });
  }

  try {
    const userId = req.session.user.id;
    let userRes;
    if (!isNaN(userId)) {
      // Numeric ID
      userRes = await pool.query(
        `SELECT first_name, last_name, bio, title, experience, location, relocate, resume_url 
         FROM users WHERE id = $1`,
        [userId]
      );
    } else {
      // LinkedIn ID (string)
      userRes = await pool.query(
        `SELECT first_name, last_name, bio, title, experience, location, relocate, resume_url 
         FROM users WHERE linkedin_id = $1`,
        [userId]
      );
    }

    if (userRes.rows.length === 0) {
      return res.json({ success: false, message: "User not found" });
    }

    const user = userRes.rows[0];
    res.json({
      success: true,
      data: {
        firstName: user.first_name || "",
        lastName: user.last_name || "",
        bio: user.bio || "",
        title: user.title || "",
        experience: user.experience || 0,
        location: user.location || "",
        relocate: user.relocate || false,
        resumeUrl: user.resume_url || "",
      },
    });
  } catch (err) {
    console.error("Error fetching user account:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Save user account details
app.post("/api/user/account", async (req, res) => {
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, message: "Not authenticated" });
  }

  try {
    const userId = req.session.user.id;
    const {
      firstName,
      lastName,
      bio,
      title,
      experience,
      location,
      relocate,
      resumeUrl,
    } = req.body;

    let updateRes;
    if (!isNaN(userId)) {
      // Numeric ID
      updateRes = await pool.query(
        `UPDATE users 
         SET first_name = $1, last_name = $2, bio = $3, title = $4, 
             experience = $5, location = $6, relocate = $7, resume_url = $8
         WHERE id = $9`,
        [
          firstName,
          lastName,
          bio,
          title,
          experience,
          location,
          relocate,
          resumeUrl,
          userId,
        ]
      );
    } else {
      // LinkedIn ID (string)
      updateRes = await pool.query(
        `UPDATE users 
         SET first_name = $1, last_name = $2, bio = $3, title = $4, 
             experience = $5, location = $6, relocate = $7, resume_url = $8
         WHERE linkedin_id = $9`,
        [
          firstName,
          lastName,
          bio,
          title,
          experience,
          location,
          relocate,
          resumeUrl,
          userId,
        ]
      );
    }

    res.json({ success: true, message: "Account details saved successfully" });
  } catch (err) {
    console.error("Error saving user account:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// API endpoint to get all companies
app.get("/api/companies", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, logo_url, tags FROM companies"
    );
    res.json({ success: true, companies: result.rows });
  } catch (err) {
    console.error("Error fetching companies:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Serve uploaded files statically
app.use("/uploads", express.static(uploadDir));

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
