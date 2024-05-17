import { createConnection } from 'node:net'
const socket = createConnection(process.env.PORT, process.env.HOST).setEncoding('utf8')
socket.pipe(process.stdout)
socket.on('error', error =>
  process.stderr.write(
    'errors' in error ?
      error.errors.map(e => e.toString()).join('\n')
    : error.toString()
  )
)
process.stdin.pipe(socket)
