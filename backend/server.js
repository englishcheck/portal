require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const { PORT: ENV_PORT, JWT_SECRET } = process.env;
const PORT = ENV_PORT || 3000;
const SALT_ROUNDS = 12;

if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET. Set it in backend/.env before starting the server.');
  process.exit(1);
}

app.use(cors());
app.use(express.json());

const dbPath = path.join(__dirname, 'data', 'english-check.db');
const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) {
        reject(error);
        return;
      }
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(rows);
    });
  });
}

async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      whatsapp TEXT NOT NULL,
      instagram TEXT NOT NULL,
      institution TEXT NOT NULL,
      major TEXT NOT NULL,
      academic_status TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      created_at INTEGER NOT NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS user_progress (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      module_key TEXT NOT NULL,
      score INTEGER DEFAULT 0,
      completed INTEGER DEFAULT 0,
      last_activity_at INTEGER NOT NULL,
      UNIQUE(user_id, module_key),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
}

function generateToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.post('/api/register', async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      whatsapp,
      instagram,
      institution,
      major,
      academicStatus,
    } = req.body;

    if (
      !name ||
      !email ||
      !password ||
      !whatsapp ||
      !instagram ||
      !institution ||
      !major ||
      !academicStatus
    ) {
      res.status(400).json({ message: 'All fields are required' });
      return;
    }

    if (password.length < 6) {
      res.status(400).json({ message: 'Password must be at least 6 characters' });
      return;
    }

    const existingUser = await get('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
      res.status(409).json({ message: 'Email is already registered' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const createdAt = Date.now();

    const result = await run(
      `
      INSERT INTO users (
        name,
        email,
        password_hash,
        whatsapp,
        instagram,
        institution,
        major,
        academic_status,
        role,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'student', ?)
      `,
      [name, email, passwordHash, whatsapp, instagram, institution, major, academicStatus, createdAt]
    );

    const user = await get(
      'SELECT id, name, email, role, academic_status FROM users WHERE id = ?',
      [result.id]
    );

    const token = generateToken(user);

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        academicStatus: user.academic_status,
      },
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to register user' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ message: 'Email and password are required' });
      return;
    }

    const user = await get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      res.status(401).json({ message: 'Invalid email or password' });
      return;
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      res.status(401).json({ message: 'Invalid email or password' });
      return;
    }

    const token = generateToken(user);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        academicStatus: user.academic_status,
      },
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to login' });
  }
});

app.get('/api/progress', authMiddleware, async (req, res) => {
  try {
    const progress = await all(
      `
      SELECT module_key, score, completed, last_activity_at
      FROM user_progress
      WHERE user_id = ?
      ORDER BY last_activity_at DESC
      `,
      [req.user.userId]
    );

    res.json({ progress });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch progress' });
  }
});

app.post('/api/progress', authMiddleware, async (req, res) => {
  try {
    const { moduleKey, score = 0, completed = false } = req.body;

    if (!moduleKey) {
      res.status(400).json({ message: 'moduleKey is required' });
      return;
    }

    const timestamp = Date.now();

    await run(
      `
      INSERT INTO user_progress (user_id, module_key, score, completed, last_activity_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id, module_key)
      DO UPDATE SET
        score = excluded.score,
        completed = excluded.completed,
        last_activity_at = excluded.last_activity_at
      `,
      [req.user.userId, moduleKey, Number(score) || 0, completed ? 1 : 0, timestamp]
    );

    res.json({ message: 'Progress saved' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to save progress' });
  }
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Backend running on http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Database init failed:', error);
    process.exit(1);
  });
