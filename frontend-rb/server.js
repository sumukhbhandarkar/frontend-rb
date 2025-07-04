// Required dependencies: axios, jsonwebtoken, pg
const express = require("express");
const path = require("path");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
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

app.use(express.static(path.join(__dirname, "public")));

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
