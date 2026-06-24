import test from 'brittle'
import {
  JSON_CONTENT_TYPE_ERROR,
  getPostJsonContentTypeProblem
} from 'p2p-hiverelay/core/relay-node/api-request.js'

function req (method, headers = {}) {
  return { method, headers }
}

test('api request: non-POST and empty POST requests do not require JSON content type', (t) => {
  t.absent(getPostJsonContentTypeProblem(req('GET', { 'content-type': 'text/plain' })))
  t.absent(getPostJsonContentTypeProblem(req('POST')))
  t.absent(getPostJsonContentTypeProblem(req('POST', { 'content-length': '0' })))
})

test('api request: application/json media type accepts optional parameters and case', (t) => {
  t.absent(getPostJsonContentTypeProblem(req('POST', {
    'content-type': 'application/json; charset=utf-8',
    'content-length': '2'
  })))
  t.absent(getPostJsonContentTypeProblem(req('POST', {
    'content-type': 'Application/JSON',
    'content-length': '2'
  })))
})

test('api request: JSON-looking media types are rejected without substring matching', (t) => {
  t.alike(getPostJsonContentTypeProblem(req('POST', {
    'content-type': 'text/plain; application/json',
    'content-length': '2'
  })), { error: JSON_CONTENT_TYPE_ERROR, close: true })

  t.alike(getPostJsonContentTypeProblem(req('POST', {
    'content-type': 'application/jsonp',
    'content-length': '2'
  })), { error: JSON_CONTENT_TYPE_ERROR, close: true })
})

test('api request: chunked body without Content-Type is rejected and should close', (t) => {
  t.alike(getPostJsonContentTypeProblem(req('POST', {
    'transfer-encoding': 'chunked'
  })), { error: JSON_CONTENT_TYPE_ERROR, close: true })
})

test('api request: wrong Content-Type with no body rejects without forcing close', (t) => {
  t.alike(getPostJsonContentTypeProblem(req('POST', {
    'content-type': 'text/plain'
  })), { error: JSON_CONTENT_TYPE_ERROR, close: false })
})
