import { BlindStoreSession } from '../store-session.js'
const session = new BlindStoreSession({ root: process.argv[2], validationOnly: true, allowPristineBootstrap: true })
await session.open()
process.send('locked')
setInterval(() => {}, 1000)
