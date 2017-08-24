// {signature} {pubKey}

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')

function check (script) {
  typeforce(types.Buffer, script)
  var chunks = bscript.decompile(script)

  return chunks.length === 2 &&
    bscript.isCanonicalSignature(chunks[0]) &&
    bscript.isCanonicalPubKey(chunks[1])
}
check.toJSON = function () { return 'pubKeyHash input' }

function encodeRaw (signature, pubKey) {
  typeforce({
    signature: bscript.isCanonicalSignature,
    pubKey: bscript.isCanonicalPubKey
  }, {
    signature: signature,
    pubKey: pubKey
  })

  return [signature, pubKey]
}

function encodeStack (signature, pubKey) {
  console.warn('decodeStack/encodeStack is deprecated for non-Witness types')
  return bscript.toStack(encodeRaw(signature, pubKey))
}

function encode (signature, pubKey) {
  return bscript.compile(encodeRaw(signature, pubKey))
}

function decode (buffer) {
  typeforce(check, buffer)
  var chunks = bscript.decompile(buffer)
  return {
    signature: chunks[0],
    pubKey: chunks[1]
  }
}

function decodeStack (stack) {
  console.warn('decodeStack/encodeStack is deprecated for non-Witness types')
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
