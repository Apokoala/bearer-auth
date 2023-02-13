const { assert } = require('chai');
const request = require('supertest');
const express = require('express');
const base64 = require('js-base64');
const jwt = require('jsonwebtoken');
const { authRoutes } = require('../src/index');

const TOKEN_SECRET = process.env.TOKEN_SECRET || 'SET A TOKEN SECRET';

const app = express();
app.use(express.json());
app.use(authRoutes);

describe('Auth routes', () => {
  it('POST /signup should create a new user and return 201 status code', async () => {
    const res = await request(app)
      .post('/signup')
      .send({ username: 'testuser', password: 'testpassword' });

    assert.equal(res.statusCode, 201);
  });

  it('POST /signin should return a JWT if the credentials are valid', async () => {
    const signupRes = await request(app)
      .post('/signup')
      .send({ username: 'testuser2', password: 'testpassword2' });

    assert.equal(signupRes.statusCode, 201);

    const credentials = base64.encode('testuser2:testpassword2');
    const res = await request(app)
      .post('/signin')
      .set('Authorization', `Basic ${credentials}`);

    assert.equal(res.statusCode, 200);
    assert.isString(res.text);

    const decoded = jwt.verify(res.text, TOKEN_SECRET);
    assert.equal(decoded.username, 'testuser2');
  });

  it('checkToken middleware should return 404 if the Bearer header is missing', async () => {
    const res = await request(app).get('/');
    assert.equal(res.statusCode, 404);
  });

  it('checkToken middleware should return 404 if the JWT is invalid', async () => {
    const res = await request(app)
      .get('/')
      .set('Authorization', 'Bearer invalidtoken');

    assert.equal(res.statusCode, 404);
  });
});