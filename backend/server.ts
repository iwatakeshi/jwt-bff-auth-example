import Fastify from 'fastify'
import users from './api/user'

const fastify = Fastify()

export default async function server() {
  try {
    await fastify.register(users)
    await fastify.listen(8080)
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
