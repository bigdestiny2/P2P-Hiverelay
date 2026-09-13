export class BlindClientError extends Error {
  constructor (code, message, options) {
    super(message, options)
    this.name = 'BlindClientError'
    this.code = code
  }
}

export function fail (code, message, options) {
  throw new BlindClientError(code, message, options)
}
