// {signature}

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')

function check (script) {
  typeforce(types.Buffer, script)
  var chunks = bscript.decompile(script)

  return chunks.length === 1 &&
    bscript.isCanonicalSignature(chunks[0])
}
check.toJSON = function () { return 'pubKey input' }

function encodeRaw (signature) {
  typeforce(bscript.isCanonicalSignature, signature)
  return [signature]
}

function encodeStack (signature) {
  return bscript.toStack(encodeRaw(signature))
}

function encode (signature) {
  return bscript.compile(encodeRaw(signature))
}

function decode (buffer) {
  typeforce(check, buffer)
  return bscript.decompile(buffer)[0]
}

function decodeStack (stack) {
  typeforce(types.Stack, stack)
  var buffer = bscript.compile(stack)
  return decode(buffer)
}

module.exports = {
  check: check,
  decode: decode,
  decodeStack: decodeStack,
  encode: encode,
  encodeStack: encodeStack,
  encodeRaw: encodeRaw
}
