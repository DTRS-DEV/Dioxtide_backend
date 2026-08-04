// DIOXTIDE — auth backend
//
// Deployable to Render as a Web Service. Handles signup/login and stores
// users in a local JSON file (users.json). Passwords are never stored or
// returned in plain text — only a bcrypt hash. Only someone with the admin
// key (set as an env var on Render) can list users at all, and even then
// they only get the bcrypt hash, not the real password. Every other part
// of the app — the signed-in user themselves included — only ever sees a
// username, never an email address, once authenticated.
//
// Endpoints:
//   POST /api/signup          { username, email, password } -> { token, username }
//   POST /api/login           { emailOrUsername, password } -> { token, username }
//   GET  /api/me              (Authorization: Bearer <token>) -> { username }
//   GET  /api/admin/users     (x-admin-key header) -> full user list, owner only
//
// Idea: Shorya Sisodiya (DTRS AI INC).  Code: Claude.

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY; // set this in Render's environment settings — never hardcode it

const DB_FILE = path.join(__dirname, 'users.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

// --- tiny JSON-file datastore -------------------------------------------
// Simple and dependency-free (no native modules to compile on Render).
// NOTE: Render's free tier has an ephemeral filesystem — data here can be
// wiped on redeploy/restart. Fine for getting started; if you need real
// persistence, swap this for Render's managed Postgres later (the API
// surface above won't need to change, just these two functions).
function loadJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function loadUsers() { return loadJSON(DB_FILE); }
function saveUsers(users) { saveJSON(DB_FILE, users); }
function loadSessions() { return loadJSON(SESSIONS_FILE); }
function saveSessions(sessions) { saveJSON(SESSIONS_FILE, sessions); }

function issueToken(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  const sessions = loadSessions();
  sessions.push({ token, userId, createdAt: new Date().toISOString() });
  saveSessions(sessions);
  return token;
}

function getUserByToken(token) {
  const sessions = loadSessions();
  const session = sessions.find((s) => s.token === token);
  if (!session) return null;
  const users = loadUsers();
  return users.find((u) => u.id === session.userId) || null;
}

// --- middleware ----------------------------------------------------------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  const user = getUserByToken(token);
  if (!user) return res.status(401).json({ error: 'Invalid or expired token' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) return res.status(500).json({ error: 'Admin key not configured on the server' });
  const key = req.headers['x-admin-key'];
  if (key !== ADMIN_KEY) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// --- routes ----------------------------------------------------------------
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body || {};

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are all required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }

  const users = loadUsers();
  const emailTaken = users.some((u) => u.email.toLowerCase() === email.toLowerCase());
  const usernameTaken = users.some((u) => u.username.toLowerCase() === username.toLowerCase());
  if (emailTaken) return res.status(409).json({ error: 'That email is already registered.' });
  if (usernameTaken) return res.status(409).json({ error: 'That username is taken.' });

  const passwordHash = await bcrypt.hash(password, 10); // one-way hash — the plain password is never stored

  const newUser = {
    id: crypto.randomUUID(),
    username,
    email,
    passwordHash,
    createdAt: new Date().toISOString(),
  };
  users.push(newUser);
  saveUsers(users);

  const token = issueToken(newUser.id);
  res.json({ token, username: newUser.username });
});

app.post('/api/login', async (req, res) => {
  const { emailOrUsername, password } = req.body || {};
  if (!emailOrUsername || !password) {
    return res.status(400).json({ error: 'Enter your email/username and password.' });
  }

  const users = loadUsers();
  const user = users.find(
    (u) =>
      u.email.toLowerCase() === emailOrUsername.toLowerCase() ||
      u.username.toLowerCase() === emailOrUsername.toLowerCase()
  );
  if (!user) return res.status(401).json({ error: 'Incorrect email/username or password.' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Incorrect email/username or password.' });

  const token = issueToken(user.id);
  res.json({ token, username: user.username });
});

// The signed-in user only ever gets their own username back — never their
// stored email or password hash, even though it's their own account.
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username });
});

// Owner-only: full user records, including email and the (hashed, never
// plain-text) password. Requires the x-admin-key header to match ADMIN_KEY.
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers().map((u) => ({
    id: u.id,
    username: u.username,
    email: u.email,
    passwordHash: u.passwordHash,
    createdAt: u.createdAt,
  }));
  res.json({ users });
});

app.get('/', (req, res) => {
  res.send('DIOXTIDE auth backend is running.');
});

app.listen(PORT, () => {
  console.log(`DIOXTIDE backend listening on port ${PORT}`);
});
