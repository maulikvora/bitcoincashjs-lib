// <scriptSig> {serialized scriptPubKey script}

var Buffer = require('safe-buffer').Buffer
var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')

function check (script, allowIncomplete) {
  typeforce(types.Buffer, script)
  var chunks = bscript.decompile(script)
  if (chunks.length < 1) return false

  var lastChunk = chunks[chunks.length - 1]
  if (!Buffer.isBuffer(lastChunk)) return false

  var scriptSig = bscript.compile(chunks.slice(0, -1))
  var redeemScriptChunks = bscript.decompile(lastChunk)

  // is redeemScript a valid script?
  if (redeemScriptChunks.length === 0) return false

  // is redeemScriptSig push only?
  var scriptSigChunks = bscript.decompile(scriptSig)
  if (!bscript.isPushOnly(scriptSigChunks)) return false

  var inputType = bscript.classifyInput(scriptSig, allowIncomplete)
  var outputType = bscript.classifyOutput(lastChunk)
  if (chunks.length === 1) {
    return outputType === bscript.types.P2WSH || outputType === bscript.types.P2WPKH
  }
  return inputType === outputType
}
check.toJSON = function () { return 'scriptHash input' }

function encodeRaw (redeemScriptSig, redeemScript) {
  redeemScriptSig = bscript.decompile(redeemScriptSig)
  if (!bscript.isPushOnly(redeemScriptSig)) throw new TypeError('P2SH scriptSigs are PUSH only')

  var serializedRedeemScript = bscript.compile(redeemScript)

  return [].concat(redeemScriptSig, serializedRedeemScript)
}

function encodeStack (redeemScriptSig, redeemScript) {
  console.warn('decodeStack/encodeStack is deprecated for non-Witness types')
  return bscript.toStack(encodeRaw(redeemScriptSig, redeemScript))
}

function encode (redeemScriptSig, redeemScript) {
  return bscript.compile(encodeRaw(redeemScriptSig, redeemScript))
}

function decode (buffer) {
  typeforce(check, buffer)
  var chunks = bscript.decompile(buffer)
  return {
    redeemScriptSig: bscript.compile(chunks.slice(0, -1)),
    redeemScript: chunks[chunks.length - 1]
  }
}

function decodeStack (stack, allowIncomplete) {
  console.warn('decodeStack/encodeStack is deprecated for non-Witness types')
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
