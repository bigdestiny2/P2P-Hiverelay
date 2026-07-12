import b4a from 'b4a'

export const sentinels = Object.freeze([
  'FIELD_NOTEBOOK_PRIVATE_SENTINEL_7b8a6b43',
  'AUTHOR_LARKSPUR_PRIVATE_SENTINEL_c5b9d120',
  'OBSERVATION_GRAPH_EDGE_PRIVATE_SENTINEL_3d927f4a'
])

export function encodeFixtureRecord () {
  return b4a.from(JSON.stringify({
    fixture: sentinels[0],
    author: sentinels[1],
    type: 'signed-text-observation',
    body: 'A client-owned field observation with a local graph link.',
    links: [{ relation: sentinels[2], logicalId: 'observation:2026-07-11:1' }]
  }))
}
