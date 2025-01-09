const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const secretKey = 'yourSecretKey'; 

app.use(bodyParser.json());

let users = [];

function generateToken(username) {
  return jwt.sign({ username }, secretKey, { expiresIn: '1h' }); 
}

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const userExists = users.some(user => user.username === username);
  if (userExists) {
    return res.status(400).send('User already exists');
  }

  users.push({ username, password: hashedPassword });
  res.status(201).send('User registered successfully');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(404).send('User not found');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).send('Invalid credentials');
  }

  const token = generateToken(username);
  res.json({ token });
});

function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).send('Access denied');
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid token');
    }

    req.user = user;
    next();
  });
}

app.get('/protected', authenticateToken, (req, res) => {
  res.send(`Hello ${req.user.username}, you have access to this protected route!`);
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
