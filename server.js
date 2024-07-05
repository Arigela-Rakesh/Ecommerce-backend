const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
const port = 3001;
const secretKey = 'Rakesh@0802';


app.use(bodyParser.json());


app.use(cors());

// Setup MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Rakesh@0802',
  database: 'ecommerce'
});

db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
});

// Register endpoint
app.post('/register', (req, res) => {
  const { firstName, lastName, username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  const query = 'INSERT INTO register (firstName, lastName, username, password) VALUES (?, ?, ?, ?)';
  db.query(query, [firstName, lastName, username, hashedPassword], (err, results) => {
    if (err) {
      console.error('Error during registration:', err);
      return res.status(400).send({ message: 'User already exists' });
    }
    res.status(201).send({ message: 'User registered successfully' });
  });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM register WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error('Error during login:', err);
      return res.status(500).send({ message: 'Server error' });
    }
    if (results.length > 0) {
      const user = results[0];
      const passwordIsValid = bcrypt.compareSync(password, user.password);
      if (!passwordIsValid) {
        return res.status(401).send({ message: 'Invalid credentials' });
      }
      const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1h' });
      res.status(200).send({ message: 'Login successful', token, user: { firstName: user.firstName, lastName: user.lastName } });
    } else {
      res.status(401).send({ message: 'Invalid credentials' });
    }
  });
});

// Middleware to verify token
function verifyToken(req, res, next) {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(403).send({ message: 'No token provided' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(500).send({ message: 'Failed to authenticate token' });
    }

    req.userId = decoded.id;
    next();
  });
}

// Protected route example
app.get('/protected', verifyToken, (req, res) => {
  res.status(200).send({ message: 'This is a protected route' });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
