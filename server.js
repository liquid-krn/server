const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const pg = require('pg');
const app = express();
const saltRounds = 10;
require('dotenv').config();

const db = new pg.Client({
  user: 'postgres',
  host: 'localhost',
  database: 'moviedb',
  password: process.env.DBPASSWORD,
  port: 5432,
});
db.connect();

app.use(bodyParser.json());
app.use(cors());


app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  try {

    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        res.json('success');
        console.log('User logged in successfully');
      } else {
        res.status(400).json('Invalid credentials');
      }
    } else {
      res.status(400).json('User does not exist');
    }
  } catch (err) {
    console.error(err);
    res.status(500).json('Internal server error');
  }
});

app.post('/signup', async (req, res) => {
  const { email, password, repassword } = req.body;

  if (password !== repassword) {
    return res.status(400).json('Passwords do not match');
  }

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      return res.status(400).json('User already exists');
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error(err);
          return res.status(500).json('Error hashing password');
        }

        const result = await db.query(
          "INSERT INTO users(email, password) VALUES ($1, $2)",
          [email, hash]
        );

        console.log('User registered successfully:', result);
        return res.json('Signup success');
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json('Internal server error');
  }
});

app.listen(process.env.PORT || 3001, function () {
  console.log('Server working on port 3001');
});
