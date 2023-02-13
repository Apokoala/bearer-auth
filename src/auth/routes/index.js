const express = require('express')
const base64 = require('js-base64')
const { User } = require('../models')
const jwt = require('jsonwebtoken')
const authRoutes = express()

const TOKEN_SECRET = process.env.TOKEN_SECRET ?? 'SET A TOKEN SECRET'

const signup = async (req, res, next) => {
    const { username, password } = req.body
    await User.createWithHashed(username, password)
    res.sendStatus(201)
}
const signin = async (req, res, next) => {
    let authorization = req.header('Authorization')
    if (!authorization.startsWith('Basic ')) {
      next(new Error('Invalid authorization scheme'))
      return
    }
  
    const decodedAuthorization = base64.decode(authorization.replace('Basic ', ''))
    const [username, password] = decodedAuthorization.split(':')
  
    try {
      let user = await User.findLoggedIn(username, password)
      if (user) {
        const data = { username: user.username }
        const token = jwt.sign(data, TOKEN_SECRET)
        res.send(token)
      } else {
        next(new Error('Invalid login'))
      }
    } catch (e) {
      console.error(e)
      next(e)
    }
  }

async function checkToken(req, _, next) {
    const authorization = req.header('Authorization') ?? ''
    if (!authorization.startsWith('Bearer ')) {
        next(new Error('Missing required Bearer header'))
        return
    }

    try {
        const token = authorization.replace('Bearer ', '')
        const decoded = jwt.verify(token, TOKEN_SECRET)
        req.username = decoded.username
        next()
    } catch (e) {
        next(new Error('Failed to decode authorization', { cause: e }))
    }
}
authRoutes.use(express.json())
authRoutes.post('/signup', signup)
authRoutes.post('/signin', signin)

module.exports = { authRoutes, signup, signin, checkToken }