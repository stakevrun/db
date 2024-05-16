import { createConnection } from 'node:net'
const prvPort = 6000
const socket = createConnection(prvPort, process.env.PRV_HOST).setEncoding('utf8')
socket.pipe(process.stdout)
socket.on('error', error => process.stderr.write(error))
process.stdin.pipe(socket)
