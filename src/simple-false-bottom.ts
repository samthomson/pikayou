/**
 * Simple False Bottom Demo (XOR-based)
 * 
 * How it works:
 * - ciphertext = realMessage XOR realKey
 * - decoyKey = ciphertext XOR decoyMessage
 * - Same ciphertext, different keys → different messages
 */

import crypto from 'crypto'

function xorBuffers(a: Buffer, b: Buffer): Buffer {
  const result = Buffer.alloc(Math.max(a.length, b.length))
  for (let i = 0; i < result.length; i++) {
    result[i] = (a[i] || 0) ^ (b[i] || 0)
  }
  return result
}

function padToLength(msg: string, len: number): Buffer {
  const buf = Buffer.alloc(len)
  buf.write(msg)
  return buf
}

function createFalseBottom(hiddenMessage: string, decoyMessage: string) {
  const maxLen = Math.max(hiddenMessage.length, decoyMessage.length, 64)
  const hiddenBuf = padToLength(hiddenMessage, maxLen)
  const decoyBuf = padToLength(decoyMessage, maxLen)
  const hiddenKey = crypto.randomBytes(maxLen)
  const ciphertext = xorBuffers(hiddenBuf, hiddenKey)
  const decoyKey = xorBuffers(ciphertext, decoyBuf)
  return {
    ciphertext: ciphertext.toString('base64'),
    hiddenKey: hiddenKey.toString('base64'),
    decoyKey: decoyKey.toString('base64')
  }
}

function decrypt(ciphertext: string, key: string): string {
  const ctBuf = Buffer.from(ciphertext, 'base64')
  const keyBuf = Buffer.from(key, 'base64')
  return xorBuffers(ctBuf, keyBuf).toString().replace(/\0+$/, '')
}

const DECOY_MESSAGE = 'Meeting at 5pm for coffee'
const HIDDEN_MESSAGE = 'The treasure is buried under the oak tree'

console.log('╔════════════════════════════════════════════════════════════╗')
console.log('║              SIMPLE FALSE BOTTOM DEMO                      ║')
console.log('║  One ciphertext, two keys → different messages (XOR)       ║')
console.log('╚════════════════════════════════════════════════════════════╝\n')

// === 1. MESSAGES ===
console.log('┌─ 1. MESSAGES ─────────────────────────────────────────────┐')
console.log('│  Decoy:  "' + DECOY_MESSAGE + '"')
console.log('│  Hidden: "' + HIDDEN_MESSAGE + '"')
console.log('└───────────────────────────────────────────────────────────┘\n')

// === 2. ENCRYPT ===
const { ciphertext, hiddenKey, decoyKey } = createFalseBottom(HIDDEN_MESSAGE, DECOY_MESSAGE)

console.log('┌─ 2. PAYLOAD ──────────────────────────────────────────────┐')
console.log('│  Type: Single ciphertext + two keys')
console.log('│  Ciphertext: ' + ciphertext.slice(0, 50) + '...')
console.log('│  Decoy Key:  ' + decoyKey.slice(0, 50) + '...')
console.log('│  Hidden Key: ' + hiddenKey.slice(0, 50) + '...')
console.log('└───────────────────────────────────────────────────────────┘\n')

// === 3. DECRYPT NORMAL ===
const decoyResult = decrypt(ciphertext, decoyKey)

console.log('┌─ 3. DECRYPT (normal way - decoy key) ───────────────────────┐')
console.log('│  Key: decoyKey')
console.log('│  Result: "' + decoyResult + '"')
console.log('└───────────────────────────────────────────────────────────┘\n')

// === 4. DECRYPT HIDDEN ===
const hiddenResult = decrypt(ciphertext, hiddenKey)

console.log('┌─ 4. DECRYPT (secret way - hidden key) ──────────────────────┐')
console.log('│  Key: hiddenKey')
console.log('│  Result: "' + hiddenResult + '"')
console.log('└───────────────────────────────────────────────────────────┘\n')

console.log('✓ Same ciphertext, different keys → different messages')
console.log('✓ Mathematical property of XOR (educational demo)')
