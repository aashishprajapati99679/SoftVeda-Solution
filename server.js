// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

/* -----------------------
   EXPRESS MIDDLEWARE SETUP
   ----------------------- */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'softveda_secret',
  resave: false,
  saveUninitialized: false,
}));

// static html files
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));


/* -----------------------
     DATABASE CONNECTION
   ----------------------- */
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'softveda_db'
});

db.connect(err => {
  if (err) {
    console.error('MySQL error:', err.message);
    process.exit(1);
  }
  console.log('Connected to MySQL');
});


/* -----------------------
   AUTH MIDDLEWARE
   ----------------------- */
function requireAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.redirect('/login.html');
}

function requireUser(req, res, next) {
  if (req.session?.userId) return next();
  return res.redirect('/login.html');
}


/* -----------------------
   CONTACT FORM
   ----------------------- */
app.post('/contact', (req, res) => {
  const { name, email, subject, message } = req.body;

  db.query(
    `INSERT INTO contacts (name,email,subject,message) VALUES (?,?,?,?)`,
    [name, email, subject, message],
    err => {
      if (err) return res.status(500).json({ success: false });
      res.json({ success: true });
    }
  );
});


/* -----------------------
   REGISTRATION
   ----------------------- */
app.post('/auth/register', (req, res) => {
  const { role } = req.body;

  /* USER REGISTRATION */
  if (role === 'user') {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).send('Missing fields');

    const hashed = bcrypt.hashSync(password, 10);

    db.query(
      `INSERT INTO users (name,email,password) VALUES (?,?,?)`,
      [name.trim(), email.trim().toLowerCase(), hashed],
      err => {
        if (err) return res.status(400).send('Email already exists');
        res.redirect('/login.html');
      }
    );
  }

  /* ADMIN REGISTRATION */
  else if (role === 'admin') {
    const { username, password, adminSecret } = req.body;

    const secretRequired = process.env.ADMIN_SECRET || 'SOFTVEDA2025';
    const isAllowed =
      (adminSecret && adminSecret === secretRequired) || req.session?.isAdmin;

    if (!isAllowed)
      return res.status(403).send('Admin request denied');

    const hashed = bcrypt.hashSync(password, 10);

    db.query(
      `INSERT INTO admin (username,password) VALUES (?,?)`,
      [username.trim(), hashed],
      err => {
        if (err) return res.status(400).send('Admin exists');
        return req.session.isAdmin
          ? res.redirect('/admin/dashboard.html')
          : res.redirect('/login.html');
      }
    );
  }

  else return res.status(400).send('Invalid role');
});


/* -----------------------
   FIXED LOGIN (MAIN FIX)
   ----------------------- */
app.post('/auth/login', (req, res) => {
  let { role, emailOrUsername, password } = req.body;

  emailOrUsername = emailOrUsername.trim().toLowerCase();
  password = password.trim();

  console.log("LOGIN REQUEST:", req.body);

  /* ---------------- USER LOGIN ---------------- */
  if (role === 'user') {
    const sql = `
      SELECT * FROM users 
      WHERE LOWER(email) = ? 
      LIMIT 1
    `;

    db.query(sql, [emailOrUsername], (err, rows) => {
      if (err || rows.length === 0)
        return res.status(400).send('Invalid email');

      const user = rows[0];

      const match = bcrypt.compareSync(password, user.password);
      if (!match) return res.status(400).send('Wrong password');

      req.session.userId = user.id;
      req.session.userName = user.name;

      return res.redirect('/user-dashboard.html');
    });
  }

  /* ---------------- ADMIN LOGIN ---------------- */
  else if (role === 'admin') {
    db.query(
      `SELECT * FROM admin WHERE username = ? LIMIT 1`,
      [emailOrUsername],
      (err, rows) => {
        if (err || rows.length === 0)
          return res.status(400).send('Invalid admin username');

        const admin = rows[0];

        const match = bcrypt.compareSync(password, admin.password);
        if (!match) return res.status(400).send('Wrong password');

        req.session.isAdmin = true;
        req.session.adminId = admin.id;

        return res.redirect('/admin/dashboard.html');
      }
    );
  }

  else return res.status(400).send('Invalid role');
});


/* -----------------------
   LOGOUT
   ----------------------- */
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});


/* -----------------------
   ADMIN PAGES
   ----------------------- */
app.get('/admin/dashboard.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin-dashboard.html'));
});


app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.query(`SELECT id,name,email,created_at FROM users`, (err, rows) => {
    res.json(rows || []);
  });
});

app.get('/api/admin/admins', requireAdmin, (req, res) => {
  db.query(`SELECT id,username,created_at FROM admin`, (err, rows) => {
    res.json(rows || []);
  });
});


/* -----------------------
   USER DASHBOARD
   ----------------------- */
app.get('/user-dashboard.html', requireUser, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
});


/* -----------------------
   HOME PAGE
   ----------------------- */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


/* -----------------------
   START SERVER
   ----------------------- */
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
