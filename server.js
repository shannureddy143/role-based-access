const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 5000;
const SECRET_KEY = 'mysecretkey123';

app.use(cors());
app.use(express.json());

// Dummy users with roles
const users = [
  { email: 'admin@example.com', password: 'admin123', role: 'admin' },
  { email: 'moderator@example.com', password: 'mod123', role: 'moderator' },
  { email: 'user@example.com', password: 'user123', role: 'user' },
];

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);

  if(user){
    const token = jwt.sign({ email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Middleware to verify JWT and roles
const authorize = (roles) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if(!authHeader) return res.status(401).json({ message: 'No token provided' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if(err) return res.status(403).json({ message: 'Invalid token' });

    if(roles.includes(decoded.role)){
      req.user = decoded;
      next();
    } else {
      res.status(403).json({ message: 'Access denied' });
    }
  });
};

// Protected routes
app.get('/admin', authorize(['admin']), (req, res) => {
  res.json({ message: `Hello Admin: ${req.user.email}` });
});

app.get('/moderator', authorize(['admin', 'moderator']), (req, res) => {
  res.json({ message: `Hello Moderator: ${req.user.email}` });
});

app.get('/user', authorize(['admin', 'moderator', 'user']), (req, res) => {
  res.json({ message: `Hello User: ${req.user.email}` });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
