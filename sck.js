import { createConnection } from 'node:net'
const prvPort = 6000
const socket = createConnection(prvPort, process.env.PRV_HOST).setEncoding('utf8')
socket.pipe(process.stdout)
socket.on('error', error =>
  process.stderr.write(
    'errors' in error ?
      error.errors.map(e => e.toString()).join('\n')
    : error.toString()
  )
)
process.stdin.pipe(socket)
