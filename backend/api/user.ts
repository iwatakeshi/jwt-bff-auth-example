import * as bcrypt from 'bcrypt'
import * as jwt from 'jsonwebtoken'
import * as cookie from 'cookie'

import fp from 'fastify-plugin'
import { FastifyPluginCallback } from 'fastify'
import client from '../prisma/client'
import { User } from '@prisma/client'
import { omit } from 'lodash'

const saltRounds = 10
const SECRET_KEY = process.env.SECRET_KEY || 'mysecret'
const ERROR_RESPONSES = {
  MISSING_CREDENTIALS: {
    statusCode: 401,
    body: JSON.stringify({ message: 'Please include username and password' }),
  },
  INVALID_TOKEN: {
    statusCode: 401,
    body: JSON.stringify({ message: 'invalid token' }),
  },
  INVALID_CREDENTIALS: {
    statusCode: 401,
    body: JSON.stringify({ message: 'Please include username and password' }),
  },
  INVALID_SESSION: {
    statusCode: 401,
    body: JSON.stringify({ message: 'session no longer valid' }),
  },
}
const generateAccessToken = (user: User) =>
  jwt.sign({ id: user.id, access: true }, SECRET_KEY, { expiresIn: '15m' })
const generateRefreshToken = (user: User) =>
  jwt.sign({ id: user.id, refresh: true }, SECRET_KEY, { expiresIn: '7d' })

export default fp(async function users(fastify, _opts, next) {
  fastify.post('/signup', async function signup(req, reply) {
    if (!req.body) return ERROR_RESPONSES.MISSING_CREDENTIALS

    try {
      const { username, password } =
        typeof req.body === 'string' ? JSON.parse(req.body as string) : req.body

      const passwordHash = await bcrypt.hash(password, saltRounds)

      const user = await client.user.create({
        data: { username, password: passwordHash },
        select: {
          username: true,
          password: false,
          token: false,
        },
      })

      const accessToken = generateAccessToken(user as User)
      const refreshToken = generateRefreshToken(user as User)

      return reply
        .status(200)
        .headers({
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true,
          'Set-Cookie': cookie.serialize('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge: 60 * 60 * 24 * 7, // 7 days
          }),
        })
        .send(JSON.stringify({ user, accessToken }))
    } catch (error) {
      return {
        statusCode: 409,
        body: JSON.stringify({ message: error.message }),
      }
    }
  })

  fastify.post('/login', async function (req, reply) {
    if (!req.body) return ERROR_RESPONSES.MISSING_CREDENTIALS
    const { username, password } =
      typeof req.body === 'string' ? JSON.parse(req.body as string) : req.body

    try {
      const user = await client.user.findOne({ where: { username } })
      if (!user) return ERROR_RESPONSES.MISSING_CREDENTIALS
      const passwordMatch = await bcrypt.compare(password, user.password)

      const accessToken = generateAccessToken(user)
      const refreshToken = generateRefreshToken(user)

      if (!passwordMatch) throw 'Invalid username/password combination'

      return reply
        .status(200)
        .headers({
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true,
          'Set-Cookie': cookie.serialize('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge: 60 * 60 * 24 * 7, // 7 days
            sameSite: true,
            path: '/',
          }),
        })
        .send(
          JSON.stringify({
            accessToken,
            user: omit(user, ['password', 'token']),
          })
        )
    } catch (error) {
      return ERROR_RESPONSES.INVALID_CREDENTIALS
    }
  })

  fastify.get('/refresh', async function (req, reply) {
    if (!req.headers.cookie) return ERROR_RESPONSES.INVALID_SESSION

    const { refreshToken } = cookie.parse(req.headers.cookie)
    if (!refreshToken) return ERROR_RESPONSES.INVALID_SESSION

    try {
      const decoded = await new Promise((resolve, reject) => {
        jwt.verify(refreshToken, SECRET_KEY, async function (err, decoded) {
          if (err) reject(err)
          resolve(decoded)
        })
      })

      const { id, refresh } = decoded as { id?: number; refresh?: string }

      if (!refresh || !id) return ERROR_RESPONSES.INVALID_SESSION

      const user = await client.user.findOne({ where: { id } })
      if (!user) return ERROR_RESPONSES.INVALID_SESSION

      if (user.token !== refreshToken) {
        return ERROR_RESPONSES.INVALID_SESSION
      }

      const accessToken = generateAccessToken(user)
      const newRefreshToken = generateRefreshToken(user)
      await client.user.update({
        where: { id },
        data: { token: newRefreshToken },
      })
      return reply
        .status(200)
        .headers({
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true,
          'Set-Cookie': cookie.serialize('refreshToken', newRefreshToken, {
            httpOnly: true,
            maxAge: 60 * 60 * 24 * 7, // 7 days
            sameSite: true,
            path: '/',
          }),
        })
        .send(JSON.stringify({ accessToken }))
    } catch (error) {
      console.error(error)
      return ERROR_RESPONSES.INVALID_TOKEN
    }
  })

  fastify.get('/me', async function (req, reply) {
    const authToken = req.headers['Authorization'] as string
    if (!authToken || !authToken?.startsWith('Bearer'))
      return ERROR_RESPONSES.INVALID_TOKEN

    const accessToken = authToken.slice(7).trim()

    try {
      const decoded = await new Promise((resolve, reject) =>
        jwt.verify(accessToken, SECRET_KEY, async function (err, decoded) {
          if (err) reject(err)
          resolve(decoded)
        })
      )

      const { id, access } = decoded as { id: number; access?: boolean }

      if (!access || !id) return ERROR_RESPONSES.INVALID_TOKEN

      const user = await client.user.findOne({ where: { id } })
      if (!user) return ERROR_RESPONSES.INVALID_SESSION

      return reply
        .status(200)
        .headers({
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true,
        })
        .send(JSON.stringify({ user: omit(user, ['password', 'token']) }))
    } catch (e) {
      return ERROR_RESPONSES.INVALID_TOKEN
    }
  })

  fastify.post('/logout', async function (req, reply) {
    if (!req.headers.cookie) return ERROR_RESPONSES.INVALID_SESSION

    const cookies = cookie.parse(req.headers.cookie)

    const { refreshToken } = cookies

    if (!refreshToken) return ERROR_RESPONSES.INVALID_SESSION
    try {
      const decoded = await new Promise((resolve, reject) =>
        jwt.verify(refreshToken, SECRET_KEY, async function (err, decoded) {
          if (err) reject(err)
          resolve(decoded)
        })
      )

      const { id, refresh } = decoded as { id: number; refresh?: boolean }

      if (!refresh || !id) return ERROR_RESPONSES.INVALID_SESSION

      const user = await client.user.findOne({ where: { id } })

      if (!user) return ERROR_RESPONSES.INVALID_SESSION

      await client.user.update({ where: { id }, data: { token: '' } })

      return {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true,
          'Set-Cookie': cookie.serialize('refreshToken', '', {
            httpOnly: true,
            expires: new Date(), // expire immediately
            sameSite: true,
            path: '/',
          }),
        },
      }
    } catch (e) {
      return ERROR_RESPONSES.INVALID_TOKEN
    }
  })

  next()
} as FastifyPluginCallback)
