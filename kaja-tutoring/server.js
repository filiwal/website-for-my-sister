// server.js
require('dotenv').config(); // Load .env variables

const express = require("express");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session setup
app.use(
  session({
    secret: process.env.SESSION_SECRET ? process.env.SESSION_SECRET.trim() : "replace_with_long_random_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// Serve static files from /public
app.use(express.static(path.join(__dirname, "public")));

// Login endpoint
app.post("/login", (req, res) => {
  const { passcode } = req.body;
  if (!passcode) return res.status(400).json({ ok: false, error: "Missing passcode" });

  if (passcode.trim() !== process.env.ADMIN_PASS.trim()) {
    return res.status(401).json({ ok: false, error: "Incorrect password" });
  }

  req.session.isAdmin = true;
  res.json({ ok: true });
});

// Logout endpoint
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

// Protected admin content
app.get("/admin/content", (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(403).json({ ok: false, error: "Not authorized" });
  }

  res.json({
    ok: true,
    html: `
      <h2>Welcome, Kaja 👋</h2>
      <p>This is the protected admin area. You can safely add editing tools here later.</p>
      <form id="logout-form"><button type="button" onclick="logout()">Log out</button></form>
      <script>
        async function logout(){
          await fetch('/logout', { method: 'POST' });
          location.reload();
        }
      </script>
    `
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`🔑 Admin password: "${process.env.ADMIN_PASS.trim()}"`);
});
