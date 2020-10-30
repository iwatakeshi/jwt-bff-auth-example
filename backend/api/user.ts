import { APIGatewayProxyEvent, Context } from 'aws-lambda'
import { Connection } from 'typeorm'
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as cookie from 'cookie';

import { Database } from '../db'

import fp from 'fastify-plugin';
import { FastifyPluginCallback } from 'fastify';
import client from '../prisma/client';
import { User } from '@prisma/client';

const saltRounds = 10;
const SECRET_KEY = process.env.SECRET_KEY || 'mysecret';
const ERROR_RESPONSES = {
  MISSING_CREDENTIALS: { statusCode: 401, body: JSON.stringify({ message: 'Please include username and password' }) },
  INVALID_TOKEN: { statusCode: 401, body: JSON.stringify({ message: 'invalid token' }) },
  INVALID_CREDENTIALS: { statusCode: 401, body: JSON.stringify({ message: 'Please include username and password' }) },
  INVALID_SESSION: { statusCode: 401, body: JSON.stringify({ message: 'session no longer valid' }) },
}
const generateAccessToken = (user: User) => jwt.sign({ id: user.id, access: true }, SECRET_KEY, { expiresIn: '15m' });
const generateRefreshToken = (user: User) => jwt.sign({ id: user.id, refresh: true }, SECRET_KEY, { expiresIn: '7d' });

module.exports = fp(async function users(fastify, _opts, next) {

  fastify.post('/signup', async function signup(req) {
    if (!req.body) return ERROR_RESPONSES.MISSING_CREDENTIALS

    try {
      const { username, password } = JSON.parse(req.body as string)

      const passwordHash = await bcrypt.hash(password, saltRounds);

      const user = await client.user.create({
        data: { username, password: passwordHash }, select: {
          username: true,
          password: false,
          token: false,
        }
      })

      const accessToken = generateAccessToken(user as User);
      const refreshToken = generateRefreshToken(user as User);

      return {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true,
          'Set-Cookie': cookie.serialize('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge: 60 * 60 * 24 * 7, // 7 days
          }),
        },
        body: JSON.stringify({ user, accessToken }),
      }
    } catch (error) {
      return { statusCode: 409, body: JSON.stringify({ message: e.message }) };
    }

  })

  fastify.post('/login',)

  next()
} as FastifyPluginCallback)

module.exports.login = async (event: APIGatewayProxyEvent, context: Context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  if (!event.body) return ERROR_RESPONSES.MISSING_CREDENTIALS;

  const { username, password } = JSON.parse(event.body);

  const database = new Database();
  let db: Connection = await database.getConnection();

  try {
    const userRepo = await db.getRepository(User);
    const user = await userRepo.findOneOrFail({ username: username });
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);


    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    userRepo.update(user.id, { refreshToken });

    delete user.passwordHash;
    delete user.refreshToken;

    if (!passwordMatch) throw 'Invalid username/password combination';

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
        'Set-Cookie': cookie.serialize('refreshToken', refreshToken, {
          httpOnly: true,
          maxAge: 60 * 60 * 24 * 7, // 7 days
          sameSite: true,
          path: '/',
        }),
      },
      body: JSON.stringify({ accessToken, user }),
    };
  } catch (e) {
    return ERROR_RESPONSES.INVALID_CREDENTIALS;
  }
}

module.exports.refresh = async (event: APIGatewayProxyEvent, context: Context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  if (!event.headers.cookie) return ERROR_RESPONSES.INVALID_SESSION;

  const { refreshToken } = cookie.parse(event.headers.cookie);
  if (!refreshToken) return ERROR_RESPONSES.INVALID_SESSION;


  const database = new Database();
  let db: Connection = await database.getConnection();

  try {
    const decoded = await new Promise((resolve, reject) =>
      jwt.verify(refreshToken, SECRET_KEY, async function (err, decoded) { if (err) reject(err); resolve(decoded) }));

    const { id, refresh } = decoded as { id: number, refresh?: boolean };

    if (!refresh || !id) return ERROR_RESPONSES.INVALID_SESSION;

    const userRepo = await db.getRepository(User);
    const user = await userRepo.findOneOrFail(id);
    if (user.refreshToken !== refreshToken) return ERROR_RESPONSES.INVALID_SESSION;

    const accessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    await userRepo.update(user.id, { refreshToken: newRefreshToken });

    delete user.passwordHash;
    delete user.refreshToken;

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
        'Set-Cookie': cookie.serialize('refreshToken', newRefreshToken, {
          httpOnly: true,
          maxAge: 60 * 60 * 24 * 7, // 7 days
          sameSite: true,
          path: '/',
        }),
      },
      body: JSON.stringify({ accessToken }),
    }
  } catch (e) {
    console.error(e);
    return ERROR_RESPONSES.INVALID_TOKEN;
  }
}

module.exports.me = async (event: APIGatewayProxyEvent, context: Context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  const authToken = event.headers['Authorization'];
  if (!authToken || !authToken.startsWith('Bearer')) return ERROR_RESPONSES.INVALID_TOKEN;

  const accessToken = authToken.slice(7).trim();

  const database = new Database();
  let db: Connection = await database.getConnection();

  try {
    const decoded = await new Promise((resolve, reject) =>
      jwt.verify(accessToken, SECRET_KEY, async function (err, decoded) { if (err) reject(err); resolve(decoded) }));

    const { id, access } = decoded as { id: number, access?: boolean };

    if (!access || !id) return ERROR_RESPONSES.INVALID_TOKEN;

    const userRepo = await db.getRepository(User);
    const user = await userRepo.findOneOrFail(id);
    delete user.passwordHash;
    delete user.refreshToken;

    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
      body: JSON.stringify({ user }),
    }
  } catch (e) {
    return ERROR_RESPONSES.INVALID_TOKEN;
  }
}

module.exports.logout = async (event: APIGatewayProxyEvent, context: Context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  if (!event.headers.cookie) return ERROR_RESPONSES.INVALID_SESSION;

  const cookies = cookie.parse(event.headers.cookie);

  const { refreshToken } = cookies;

  if (!refreshToken) return ERROR_RESPONSES.INVALID_SESSION;


  const database = new Database();
  let db: Connection = await database.getConnection();

  try {
    const decoded = await new Promise((resolve, reject) =>
      jwt.verify(refreshToken, SECRET_KEY, async function (err, decoded) { if (err) reject(err); resolve(decoded) }));

    const { id, refresh } = decoded as { id: number, refresh?: boolean };

    if (!refresh || !id) return ERROR_RESPONSES.INVALID_SESSION;

    const userRepo = await db.getRepository(User);

    await userRepo.update(id, { refreshToken: '' });

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
    return ERROR_RESPONSES.INVALID_TOKEN;
  }
}
