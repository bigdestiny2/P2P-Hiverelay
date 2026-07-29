import b4a from 'b4a'

export const sentinels = Object.freeze([
  'BINARY_TILE_STREAM_PRIVATE_SENTINEL_951e0d2c',
  'PRODUCER_MERIDIAN_PRIVATE_SENTINEL_11dfe9a7',
  'COORDINATE_INDEX_PRIVATE_SENTINEL_2c70a44e'
])

export function encodeFixtureRecord () {
  const header = b4a.from(JSON.stringify({
    fixture: sentinels[0],
    producer: sentinels[1],
    mediaType: 'application/x-private-sensor-tile',
    coordinateIndex: sentinels[2],
    tile: [24, 42, 17]
  }))
  const payload = b4a.alloc(128 * 1024)
  for (let index = 0; index < payload.byteLength; index++) payload[index] = (index * 131 + 17) & 0xff
  return b4a.concat([header, b4a.from([0]), payload])
}
