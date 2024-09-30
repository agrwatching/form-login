const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const session = require('express-session');
const cors = require('cors'); // Tambahkan ini
const app = express();
const port = 3002;

// Middleware
app.use(bodyParser.json());
app.use(session({
  secret: 'your_secret_key', // Kunci rahasia session
  resave: false, // Session tidak akan disimpan ulang jika tidak ada perubahan
  saveUninitialized: true // Session baru disimpan walaupun belum diubah
}));

// Middleware CORS (untuk mengatasi masalah CORS antara frontend dan backend)
app.use(cors({
  origin: 'http://127.0.0.1:3002', // Asal dari frontend
  methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE'], // Metode HTTP yang diizinkan
  allowedHeaders: ['Content-Type', 'Authorization'], // Header yang diizinkan
  credentials: true // Mengizinkan cookies atau session dikirimkan
}));

// Koneksi ke database MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'userdb' // Nama database
});

db.connect((err) => {
  if (err) throw err;
  console.log('Terhubung ke database');
});

// Route untuk registrasi
app.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  // Enkripsi password
  const hashedPassword = bcrypt.hashSync(password, 10);

  // Query untuk memasukkan data pengguna ke database
  const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  db.query(query, [username, email, hashedPassword], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Registrasi gagal');
    }
    res.send('Registrasi berhasil');
  });
});

// Route untuk login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Memeriksa apakah pengguna ada di database
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      return res.status(500).send('Login gagal');
    }
    if (results.length === 0) {
      return res.status(400).send('Pengguna tidak ditemukan');
    }

    const user = results[0];

    // Memeriksa kecocokan password
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(400).send('Password salah');
    }

    // Menyimpan session pengguna
    req.session.user = user;
    res.send('Login berhasil');
  });
});

// Route untuk memeriksa apakah pengguna sudah login
app.get('/check-auth', (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, username: req.session.user.username });
  } else {
    res.json({ authenticated: false });
  }
});

// Memulai server
app.listen(port, () => {
  console.log(`Server berjalan di port ${port}`);
});
