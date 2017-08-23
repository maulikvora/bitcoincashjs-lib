// OP_0 [signatures ...]

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')

function partialSignature (value) {
  return value === OPS.OP_0 || bscript.isCanonicalSignature(value)
}

function check (script, allowIncomplete) {
  typeforce(types.Buffer, script)
  var chunks = bscript.decompile(script)
  if (chunks.length < 2) return false
  if (chunks[0] !== OPS.OP_0) return false

  if (allowIncomplete) {
    return chunks.slice(1).every(partialSignature)
  }

  return chunks.slice(1).every(bscript.isCanonicalSignature)
}
check.toJSON = function () { return 'multisig input' }

function encodeRaw (signatures, scriptPubKey) {
  typeforce([partialSignature], signatures)

  if (scriptPubKey) {
    var scriptData = bscript.multisig.output.decode(scriptPubKey)

    if (signatures.length < scriptData.m) {
      throw new TypeError('Not enough signatures provided')
    }

    if (signatures.length > scriptData.pubKeys.length) {
      throw new TypeError('Too many signatures provided')
    }
  }

  return [].concat(OPS.OP_0, signatures)
}

function encodeStack (signatures, scriptPubKey) {
  return bscript.toStack(encodeRaw(signatures, scriptPubKey))
}

function encode (signatures, scriptPubKey) {
  return bscript.compile(encodeRaw(signatures, scriptPubKey))
}

function decode (buffer, allowIncomplete) {
  typeforce(check, buffer, allowIncomplete)
  return bscript.decompile(buffer).slice(1)
}

function decodeStack (stack, allowIncomplete) {
  typeforce(types.Stack, stack)
  var buffer = bscript.compile(stack)
  return decode(buffer, allowIncomplete)
}

module.exports = {
  check: check,
  decode: decode,
  decodeStack: decodeStack,
  encode: encode,
  encodeStack: encodeStack,
  encodeRaw: encodeRaw
}
