export class BlindProtocolError extends Error {
  constructor (code, message) {
    super(message)
    this.name = 'BlindProtocolError'
    this.code = code
  }
}

export function protocolError (code, message) {
  throw new BlindProtocolError(code, message)
}
