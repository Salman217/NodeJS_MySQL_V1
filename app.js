const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const db = require('./db');
const PORT = 3000;


app.use(express.json());

const MovieRouter = require('./Routes/Movie');
const UserRouter = require('./Routes/User')


app.use('/Movie', MovieRouter);
app.use('/User', UserRouter);

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
  }
  console.log('Connected to MySQL');
});


app.use(function (req, res, next) {

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers,X-Access-Token,XKey,Authorization');
  next();
});

// Accept data formats as below
app.use(bodyParser.raw());
app.use(bodyParser.text());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });

