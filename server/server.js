const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
require('dotenv').config();

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.FIREBASE_DATABASE_URL || 'https://hexamech-2c6f5-default-rtdb.firebaseio.com';
const DATA_PATH = process.env.FIREBASE_DATA_PATH || '/hexamech/data';
const SESSION_TTL = process.env.SESSION_TTL || '12h';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');
const LOGIN_WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS || 15 * 60 * 1000);
const LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 10);

const DEFAULT_USERS = [
  { username: 'admin', displayName: 'Admin', passwordHash: '4243810fb1ec73d1da79e60b954d34175cf64e9bdca6612029ef50e1cafe6f19', role: 'admin' },
  { username: 'sales', displayName: 'Sales', passwordHash: 'e47f598eeb1bfb2f6d49719c1cc67f620a60a46e8055187297c2be372efd241b', role: 'user' }
];

if (!process.env.SESSION_SECRET) {
  console.warn('SESSION_SECRET is not set. A temporary secret was generated; users will be logged out when the server restarts.');
}

function getFirebaseCredential() {
  if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    return admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    });
  }
  return admin.credential.applicationDefault();
}

admin.initializeApp({
  credential: getFirebaseCredential(),
  databaseURL: DATABASE_URL
});

const dbRef = admin.database().ref(DATA_PATH.replace(/^\/+/, ''));
const app = express();
app.set('trust proxy', 1);
const loginAttempts = new Map();

const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed'));
  },
  credentials: false
}));
app.use(express.json({ limit: '25mb' }));

function sha256(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function normalizeUser(user) {
  const normalized = { ...(user || {}) };
  normalized.username = String(normalized.username || '').trim().toLowerCase();
  normalized.displayName = String(normalized.displayName || normalized.username || 'User').trim();
  normalized.role = normalized.role === 'admin' ? 'admin' : 'user';
  normalized.canProjectAccess = normalized.role === 'admin' ? true : !!normalized.canProjectAccess;
  normalized.group = normalized.role === 'admin' ? '' : String(normalized.group || '').trim();
  normalized.contactPhone = String(normalized.contactPhone || normalized.mobile || '').trim();
  normalized.contactEmail = String(normalized.contactEmail || normalized.email || '').trim().toLowerCase();
  if (normalized.password && !normalized.passwordHash) {
    normalized.passwordHash = sha256(normalized.password);
  }
  delete normalized.password;
  return normalized;
}

function normalizeUsers(users, includeDefaults = true) {
  const source = Array.isArray(users) && users.length ? users : (includeDefaults ? DEFAULT_USERS : []);
  return source.map(normalizeUser).filter(user => user.username);
}

function normalizeState(state = {}) {
  return {
    quotations: Array.isArray(state.quotations) ? state.quotations : [],
    users: normalizeUsers(state.users, false),
    customers: Array.isArray(state.customers) ? state.customers : [],
    projects: Array.isArray(state.projects) ? state.projects : []
  };
}

function sanitizeUser(user) {
  const { password, passwordHash, ...safeUser } = normalizeUser(user);
  return safeUser;
}

function sanitizeState(state) {
  const normalized = normalizeState(state);
  return {
    ...normalized,
    users: normalized.users.map(sanitizeUser)
  };
}

function findUser(users, username) {
  const normalizedUsername = String(username || '').trim().toLowerCase();
  return normalizeUsers(users, false).find(user => user.username === normalizedUsername)
    || DEFAULT_USERS.find(user => user.username === normalizedUsername)
    || null;
}

function passwordMatches(user, password) {
  if (!user) return false;
  if (user.passwordHash) return sha256(password) === user.passwordHash;
  return false;
}

function loginAttemptKey(req, username) {
  return `${req.ip || 'unknown'}:${String(username || '').trim().toLowerCase()}`;
}

function isLoginRateLimited(req, username) {
  const key = loginAttemptKey(req, username);
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || entry.resetAt <= now) return false;
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}

function recordFailedLogin(req, username) {
  const key = loginAttemptKey(req, username);
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || entry.resetAt <= now) {
    loginAttempts.set(key, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return;
  }
  entry.count += 1;
}

function clearFailedLogin(req, username) {
  loginAttempts.delete(loginAttemptKey(req, username));
}

async function readState() {
  const snap = await dbRef.get();
  const raw = snap.exists() ? snap.val() : {};
  const state = normalizeState(raw);
  if (!state.users.length) state.users = DEFAULT_USERS.map(user => ({ ...user }));
  return state;
}

async function writeState(state) {
  await dbRef.set(normalizeState(state));
}

function issueToken(user) {
  return jwt.sign(
    { sub: user.username, username: user.username },
    SESSION_SECRET,
    { expiresIn: SESSION_TTL }
  );
}

function mergeUsersForWrite(currentUsers, submittedUsers, actingUser) {
  const current = normalizeUsers(currentUsers, true);
  const submitted = normalizeUsers(submittedUsers, false);
  if (actingUser.role === 'admin') {
    return submitted.map(user => {
      const existing = current.find(item => item.username === user.username);
      if (!user.passwordHash && existing?.passwordHash) user.passwordHash = existing.passwordHash;
      return normalizeUser(user);
    });
  }

  return current.map(user => {
    if (user.username !== actingUser.username) return user;
    const ownUpdate = submitted.find(item => item.username === actingUser.username);
    if (!ownUpdate) return user;
    return normalizeUser({
      ...user,
      contactPhone: ownUpdate.contactPhone,
      contactEmail: ownUpdate.contactEmail,
      passwordHash: ownUpdate.passwordHash || user.passwordHash
    });
  });
}

async function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Missing session token.' });
  try {
    const payload = jwt.verify(token, SESSION_SECRET);
    const state = await readState();
    const user = findUser(state.users, payload.username || payload.sub);
    if (!user) return res.status(401).json({ error: 'User no longer exists.' });
    req.user = normalizeUser(user);
    req.state = state;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

app.get('/api/health', (req, res) => {
  res.json({ mode: 'backend-server', ok: true });
});

app.post('/api/login', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (isLoginRateLimited(req, username)) {
      return res.status(429).json({ error: 'Too many login attempts. Please wait and try again.' });
    }
    const state = await readState();
    const user = findUser(state.users, username);
    if (!passwordMatches(user, password)) {
      recordFailedLogin(req, username);
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const normalizedUser = normalizeUser(user);
    const token = issueToken(normalizedUser);
    clearFailedLogin(req, username);
    res.json({
      token,
      user: sanitizeUser(normalizedUser),
      state: sanitizeState(state)
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/session', authRequired, (req, res) => {
  res.json({
    user: sanitizeUser(req.user),
    state: sanitizeState(req.state)
  });
});

app.get('/api/state', authRequired, (req, res) => {
  res.json({ state: sanitizeState(req.state) });
});

app.put('/api/state', authRequired, async (req, res, next) => {
  try {
    const submittedState = normalizeState(req.body || {});
    const nextState = {
      quotations: submittedState.quotations,
      customers: submittedState.customers,
      projects: submittedState.projects,
      users: mergeUsersForWrite(req.state.users, submittedState.users, req.user)
    };
    await writeState(nextState);
    res.json({ ok: true, state: sanitizeState(nextState) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/change-password', authRequired, async (req, res, next) => {
  try {
    const currentPassword = String(req.body?.currentPassword || '');
    const newPassword = String(req.body?.newPassword || '');
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters.' });
    }
    const user = findUser(req.state.users, req.user.username);
    if (!passwordMatches(user, currentPassword)) {
      return res.status(400).json({ error: 'Current password is incorrect.' });
    }
    const users = normalizeUsers(req.state.users, true).map(item => {
      if (item.username !== req.user.username) return item;
      return normalizeUser({ ...item, passwordHash: sha256(newPassword) });
    });
    const nextState = { ...req.state, users };
    await writeState(nextState);
    res.json({ ok: true, state: sanitizeState(nextState) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/logout', (req, res) => {
  res.json({ ok: true });
});

function sendApp(req, res) {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
}

app.get('/', sendApp);
app.get('/index.html', sendApp);
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found.' });
  return sendApp(req, res);
});

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

app.listen(PORT, () => {
  console.log(`Hexamech secure backend running on port ${PORT}`);
});
