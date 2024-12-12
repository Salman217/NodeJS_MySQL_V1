const express = require('express');
const UserRoute = express.Router();
const db = require('../db');
const auth = require('../Auth');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');


UserRoute.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO Users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
      if (err) return res.status(500).send(err);
      res.status(201).send({ message: 'User registered successfully' });
    });
  });

  // Login user and generate JWT token
  UserRoute.post('/generateToken', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM Users WHERE username = ?', [username], async (err, results) => {
      if (err) return res.status(500).send(err);
      if (results.length === 0) return res.status(400).send('User not found');
      
      const user = results[0];
      console.log("users",user);
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(400).send('Invalid password');
      
      const token = jwt.sign({ userId: user.id, username: user.username }, auth.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    });
  });


  module.exports = UserRoute;
