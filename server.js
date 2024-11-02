const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const knex = require('knex');
const path = require('path');
const app = express();
const saltRounds = 10;
require('dotenv').config();

const db = require('knex')({
  client: 'pg',
  connection: {
    host:process.env.DBHOST ,
    user:process.env.DBUSER ,
    password:process.env.DBPASSWORD ,
    database:process.env.DBDATABASE ,
    ssl: { rejectUnauthorized: false }
  }
});

app.use(bodyParser.json());
app.use(cors());

// app.get('/',(req,res)=>{
//   res.send('working')
// })
app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'build', 'index.html'));
});

app.post('/signup', async (req, res) => {
  const { email, password, repassword } = req.body;
  const date = new Date();

  if (password !== repassword) {
    return res.status(400).json('Passwords do not match');
  }
  try {
    const users = await db('users').where({ email }).select('*');
    if (users.length > 0) {
      return res.status(400).json('User already exists');
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error(err);
          return res.status(500).json('Error hashing password');
        }
        await db('users').insert({
          email,
          password: hash,
          created_at: date,
        });
        console.log('User registered successfully');
        return res.json('Signup success');
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json('Server error');
  }
});

app.post('/signin', async (req, res) => {
  const { email, password } = req.body;
  try {
    const users = await db('users').where({ email }).select('*');
    if (users.length > 0) {
      const user = users[0];
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

app.listen(process.env.PORT || 3001, function () {
  console.log('Server working on port 3001');
});
