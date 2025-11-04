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

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "replace_with_long_random_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60,
    },
  })
);

app.use(express.static(path.join(__dirname, "public")));

app.post("/login", async (req, res) => {
  const { passcode } = req.body;
  if (!passcode) return res.status(400).json({ ok: false, error: "Missing passcode" });

  if (!ADMIN_HASH) return res.status(500).json({ ok: false, error: "Server not ready" });

  const isMatch = await bcrypt.compare(passcode, ADMIN_HASH);
  if (!isMatch) return res.status(401).json({ ok: false, error: "Incorrect password" });

  req.session.isAdmin = true;
  res.json({ ok: true });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

app.get("/admin/content", (req, res) => {
  if (!req.session.isAdmin) return res.status(403).json({ ok: false, error: "Not authorized" });

  res.json({
    ok: true,
    html: `
      <h2>Welcome,</h2>
      <p>This is the protected admin area.</p>
      <p2>What are you doing here?</p2>
      <div style="text-align: center; margin-top: 20px;">
        <img src="https://static0.gamerantimages.com/wordpress/wp-content/uploads/2024/07/doakes-on-the-trail-1.jpg?q=49&fit=contain&w=750&h=422&dpr=2" style="width: 250px; height: auto; border-radius: 8px;">
      </div>
      <form id="logout-form" style="text-align: center; margin-top: 15px;">
        <button type="button" onclick="logout()">Log out</button>
      </form>
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
