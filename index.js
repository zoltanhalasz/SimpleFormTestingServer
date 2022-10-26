const express = require('express');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const zxcvbn = require('zxcvbn');

/**
 * Fake service for the form example. This service does nothing useful
 * and just simulates input validation and signup. Do not use it in production.
 */

const PORT = process.env.PORT || 3200;

/**
 * Regular expression for validating an email address.
 * Taken from Angular:
 * https://github.com/angular/angular/blob/43b4940c9d595c542a00795976bc3168dd0ca5af/packages/forms/src/validators.ts#L68-L99
 * Copyright Google LLC All Rights Reserved.
 * MIT-style license: https://angular.io/license
 */
const EMAIL_REGEXP = /^(?=.{1,254}$)(?=.{1,64}@)[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const USERNAME_REGEXP = /^[a-zA-Z0-9.]+$/;

/**
 * Allowed origins
 */

/**
 * Holds the users in memory.
 */
const users = [];

const isEmailSyntaxValid = (email) =>
  typeof email === 'string' &&
  email !== '' &&
  email.length <= 100 &&
  EMAIL_REGEXP.test(email);

const isPasswordSyntaxValid = (password) =>
  typeof password === 'string' && password !== '' && password.length <= 200;

const isUsernameTaken = (username) => users.some((user) => user.username == username);

const isEmailTaken = (email) => users.some((user) => user.email == email);

const app = express();
app.use(express.json());

// Enable CORS
app.use(cors());

// Enable API limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: false,
	legacyHeaders: false,
});
app.use(apiLimiter);

app.post('/password-strength', (req, res) => {
  const { password } = req.body;
  if (!isPasswordSyntaxValid(password)) {
    res.sendStatus(400);
    return;
  }
  const result = zxcvbn(password);
  res.send({
    score: result.score,
    warning: result.feedback.warning,
    suggestions: result.feedback.suggestions,
  });
});

app.post('/username-taken', (req, res) => {
  const { username } = req.body;
  if (!isUsernameSyntaxValid(username)) {
    res.sendStatus(400);
    return;
  }
  res.send({ usernameTaken: isUsernameTaken(username) });
});

app.post('/email-taken', (req, res) => {
  const { email } = req.body;
  if (!isEmailSyntaxValid(email)) {
    res.sendStatus(400);
    return;
  }
  res.send({ emailTaken: isEmailTaken(email) });
});

app.get('/', (req, res) => {  
  console.log(users);
  res.send(users);
});

const isNonEmptyString = (object, property) => {
  const value = object[property];
  return typeof value === 'string' && value !== '';
};

const validateSignup = (body) => {
  if (!body) {
    return { valid: false, error: 'Bad request' };
  }
  const { email, password } = body;
  const checks = {
    email: () => isEmailSyntaxValid(email) && !isEmailTaken(email),
    password: () => isPasswordSyntaxValid(password) && zxcvbn(password).score >= 3,
  };
  for (const [name, check] of Object.entries(checks)) {
    const valid = check();
    if (!valid) {
      return { valid: false, error: `${name} is invalid` };
    }
  }
  return { valid: true };
};

app.post('/signup', (req, res) => {
  const validationResult = validateSignup(req.body);
  if (!validationResult.valid) {
    res.status(400).send({ error: validationResult.error });
    return;
  }
  const { email, password } = req.body;
  users.push({    
    email,
    password,
  });
  console.log(`Successful signup: ${email}`);
  res.send({ success: true });
});

app.listen(PORT);
console.log('Server running on Port ' + PORT);
