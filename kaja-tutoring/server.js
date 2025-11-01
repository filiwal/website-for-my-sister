// server.js
require('dotenv').config();
const fs = require('fs');
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

function loadAdminPass() {
  if (process.env.ADMIN_PASS && process.env.ADMIN_PASS.trim()) return process.env.ADMIN_PASS.trim();
  if (process.env.ADMIN_PASS_FILE) {
    try { return fs.readFileSync(process.env.ADMIN_PASS_FILE, 'utf8').trim(); } catch(e){}
  }
  const candidates = [
    '/run/secrets/admin_pass',
    '/run/secrets/ADMIN_PASS',
    '/etc/kaja/admin_pass',
    '/etc/kaja/ADMIN_PASS'
  ];
  for (const p of candidates) {
    try {
      const v = fs.readFileSync(p, 'utf8').trim();
      if (v) return v;
    } catch(e){}
  }
  return null;
}

const ADMIN_PASS = loadAdminPass();
if (!ADMIN_PASS) {
  console.error('Admin password not found. Set ADMIN_PASS environment variable or place secret in a file (e.g. /run/secrets/admin_pass).');
  process.exit(1);
}

let ADMIN_HASH = null;

// Middleware to parse JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session setup
app.use(
  session({
    secret: process.env.SESSION_SECRET || "replace_with_long_random_secret",
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
app.post("/login", async (req, res) => {
  const { passcode } = req.body;
  if (!passcode) return res.status(400).json({ ok: false, error: "Missing passcode" });

  if (!ADMIN_HASH) return res.status(500).json({ ok: false, error: "Server not ready" });

  const isMatch = await bcrypt.compare(passcode, ADMIN_HASH);
  if (!isMatch) return res.status(401).json({ ok: false, error: "Incorrect password" });

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
  if (!req.session.isAdmin) return res.status(403).json({ ok: false, error: "Not authorized" });

  res.json({
    ok: true,
    html: `
      <h2>Welcome, Kaja 👋</h2>
      <p>This is the protected admin area.</p>
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

async function init() {
  ADMIN_HASH = await bcrypt.hash(ADMIN_PASS, 12);
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

init();
