// {scriptSig} {serialized scriptPubKey script}

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')

function checkStack (stack, allowIncomplete) {
  typeforce(types.Stack, stack)
  if (stack.length < 1) return false

  var witnessScript = stack[stack.length - 1]
  if (!Buffer.isBuffer(witnessScript)) return false

  var witnessScriptChunks = bscript.decompile(witnessScript)

  // is witnessScript a valid script?
  if (witnessScriptChunks.length === 0) return false

  var witnessStackScript = bscript.compile(stack.slice(0, -1))
  var inputType = bscript.classifyInput(witnessStackScript, allowIncomplete)
  var outputType = bscript.classifyOutput(witnessScript)
  return inputType === outputType
}
checkStack.toJSON = function () { return 'witnessScriptHash input' }

function encodeRaw (redeemScriptSig, redeemScript) {
  redeemScriptSig = bscript.decompile(redeemScriptSig)
  if (!bscript.isPushOnly(redeemScriptSig)) throw new TypeError('P2WSH scriptSigs are PUSH only')

  var serializedRedeemScript = bscript.compile(redeemScript)
  return [].concat(redeemScriptSig, serializedRedeemScript)
}

function encodeStack (witnessStack, witnessScript) {
  return bscript.toStack(encodeRaw(witnessStack, witnessScript))
}

function decodeStack (stack) {
  typeforce(checkStack, stack)
  return {
    witnessStack: stack[0],
    witnessScript: stack[1]
  }
}

module.exports = {
  checkStack: checkStack,
  decodeStack: decodeStack,
  encodeRaw: encodeRaw,
  encodeStack: encodeStack
}
