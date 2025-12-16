/**
 * Simple False Bottom Implementation
 * 
 * Concept: XOR-based scheme where ONE ciphertext decrypts to different
 * messages with different keys.
 * 
 * ciphertext = realMessage XOR realKey
 * We choose: decoyKey = ciphertext XOR decoyMessage
 * 
 * So: ciphertext XOR realKey = realMessage
 *     ciphertext XOR decoyKey = decoyMessage
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

// === ENCRYPTION ===
function createFalseBottom(realMessage: string, decoyMessage: string) {
  const maxLen = Math.max(realMessage.length, decoyMessage.length, 64)
  
  const realBuf = padToLength(realMessage, maxLen)
  const decoyBuf = padToLength(decoyMessage, maxLen)
  
  // Generate random key for real message
  const realKey = crypto.randomBytes(maxLen)
  
  // Create ciphertext: realMessage XOR realKey
  const ciphertext = xorBuffers(realBuf, realKey)
  
  // Derive decoy key: ciphertext XOR decoyMessage
  // This ensures: ciphertext XOR decoyKey = decoyMessage
  const decoyKey = xorBuffers(ciphertext, decoyBuf)
  
  return {
    ciphertext: ciphertext.toString('base64'),
    realKey: realKey.toString('base64'),
    decoyKey: decoyKey.toString('base64')
  }
}

// === DECRYPTION ===
function decrypt(ciphertext: string, key: string): string {
  const ctBuf = Buffer.from(ciphertext, 'base64')
  const keyBuf = Buffer.from(key, 'base64')
  const result = xorBuffers(ctBuf, keyBuf)
  return result.toString().replace(/\0+$/, '') // trim null padding
}

// === DEMO ===
const REAL_MESSAGE = 'The treasure is buried under the oak tree'
const DECOY_MESSAGE = 'Meeting at 5pm for coffee'

console.log('=== SIMPLE FALSE BOTTOM DEMO ===\n')

console.log('Original messages:')
console.log('  Real:', REAL_MESSAGE)
console.log('  Decoy:', DECOY_MESSAGE)

const { ciphertext, realKey, decoyKey } = createFalseBottom(REAL_MESSAGE, DECOY_MESSAGE)

console.log('\n--- ONE Ciphertext, TWO Keys ---')
console.log('Ciphertext:', ciphertext)
console.log('Real Key:', realKey)
console.log('Decoy Key:', decoyKey)

console.log('\n--- Decryption ---')
console.log('With REAL key:', decrypt(ciphertext, realKey))
console.log('With DECOY key:', decrypt(ciphertext, decoyKey))

console.log('\n--- Scenario ---')
console.log('Store: ciphertext + both keys')
console.log('If coerced: give up ciphertext + decoyKey')
console.log('They decrypt:', decrypt(ciphertext, decoyKey))
console.log('Your real message stays hidden!')

