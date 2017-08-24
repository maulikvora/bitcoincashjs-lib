// {signature} {pubKey}

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')

function isCompressedCanonicalPubKey (pubKey) {
  return bscript.isCanonicalPubKey(pubKey) && pubKey.length === 33
}

function checkStack (stack) {
  typeforce(types.Stack, stack)

  return stack.length === 2 &&
    bscript.isCanonicalSignature(stack[0]) &&
    isCompressedCanonicalPubKey(stack[1])
}
checkStack.toJSON = function () { return 'witnessPubKeyHash input' }

function encodeRaw (signature, pubKey) {
  typeforce({
    signature: bscript.isCanonicalSignature,
    pubKey: isCompressedCanonicalPubKey
  }, {
    signature: signature,
    pubKey: pubKey
  })

  return [signature, pubKey]
}

function decodeStack (stack) {
  typeforce(checkStack, stack)
  return {
    signature: stack[0],
    pubKey: stack[1]
  }
}

module.exports = {
  checkStack: checkStack,
  decodeStack: decodeStack,
  encodeRaw: encodeRaw,
  encodeStack: encodeRaw
}
