/**
 * Nostr + False Bottom Demo
 * 
 * Concept: Embed a false-bottom payload INSIDE a NIP-44 encrypted message.
 * 
 * Flow:
 * 1. Create false-bottom ciphertext (1 ciphertext, 2 keys: realKey + decoyKey)
 * 2. Package as JSON: { ct: ciphertext, dk: decoyKey }  (decoy key is "visible")
 * 3. Encrypt with NIP-44 to recipient
 * 4. Recipient decrypts NIP-44 → gets JSON with ciphertext + decoy key
 * 5. Using decoyKey → decoy message (plausible)
 * 6. Using realKey (shared secretly) → real message
 * 
 * The realKey could be:
 * - Pre-shared between sender/recipient
 * - Derived from a secondary shared secret
 * - Transmitted via a different channel
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import * as secp from '@noble/secp256k1'

// === FALSE BOTTOM ENCRYPTION (XOR-based) ===

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(Math.max(a.length, b.length))
  for (let i = 0; i < result.length; i++) {
    result[i] = (a[i] || 0) ^ (b[i] || 0)
  }
  return result
}

function padMessage(msg: string, len: number): Uint8Array {
  const buf = new Uint8Array(len)
  const encoded = new TextEncoder().encode(msg)
  buf.set(encoded)
  return buf
}

function createFalseBottom(realMessage: string, decoyMessage: string) {
  const maxLen = Math.max(realMessage.length, decoyMessage.length, 64)
  
  const realBuf = padMessage(realMessage, maxLen)
  const decoyBuf = padMessage(decoyMessage, maxLen)
  
  // Random key for real message
  const realKey = randomBytes(maxLen)
  
  // ciphertext = realMessage XOR realKey
  const ciphertext = xorBytes(realBuf, realKey)
  
  // decoyKey = ciphertext XOR decoyMessage
  const decoyKey = xorBytes(ciphertext, decoyBuf)
  
  return {
    ciphertext: Buffer.from(ciphertext).toString('base64'),
    realKey: Buffer.from(realKey).toString('base64'),
    decoyKey: Buffer.from(decoyKey).toString('base64')
  }
}

function decryptFalseBottom(ciphertext: string, key: string): string {
  const ct = new Uint8Array(Buffer.from(ciphertext, 'base64'))
  const k = new Uint8Array(Buffer.from(key, 'base64'))
  const result = xorBytes(ct, k)
  return new TextDecoder().decode(result).replace(/\0+$/, '')
}

// === SIMPLIFIED NIP-44 ENCRYPTION ===

function getConversationKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const sharedX = secp.getSharedSecret(privateKey, publicKey).slice(1, 33)
  return hkdf(sha256, sharedX, new TextEncoder().encode('nip44-v2'), undefined, 32)
}

function nip44Encrypt(plaintext: string, conversationKey: Uint8Array): string {
  const nonce = randomBytes(24)
  const messageKey = hkdf(sha256, conversationKey, nonce, new TextEncoder().encode('nip44-v2'), 32)
  const cipher = xchacha20poly1305(messageKey, nonce)
  const ciphertext = cipher.encrypt(new TextEncoder().encode(plaintext))
  
  // Format: version(1) + nonce(24) + ciphertext(variable)
  const result = new Uint8Array(1 + 24 + ciphertext.length)
  result[0] = 2 // version
  result.set(nonce, 1)
  result.set(ciphertext, 25)
  return Buffer.from(result).toString('base64')
}

function nip44Decrypt(payload: string, conversationKey: Uint8Array): string {
  const data = new Uint8Array(Buffer.from(payload, 'base64'))
  const version = data[0]
  if (version !== 2) throw new Error('Unsupported version')
  
  const nonce = data.slice(1, 25)
  const ciphertext = data.slice(25)
  
  const messageKey = hkdf(sha256, conversationKey, nonce, new TextEncoder().encode('nip44-v2'), 32)
  const cipher = xchacha20poly1305(messageKey, nonce)
  const plaintext = cipher.decrypt(ciphertext)
  return new TextDecoder().decode(plaintext)
}

// === DEMO ===

async function main() {
  console.log('=== NOSTR + FALSE BOTTOM DEMO ===\n')
  
  // Generate sender and recipient keys (like nsec/npub)
  const senderPrivKey = secp.utils.randomSecretKey()
  const senderPubKey = secp.getPublicKey(senderPrivKey, true)
  
  const recipientPrivKey = secp.utils.randomSecretKey()
  const recipientPubKey = secp.getPublicKey(recipientPrivKey, true)
  
  console.log('Sender pubkey:', Buffer.from(senderPubKey).toString('hex').slice(0, 16) + '...')
  console.log('Recipient pubkey:', Buffer.from(recipientPubKey).toString('hex').slice(0, 16) + '...')
  
  // Messages
  const REAL_MESSAGE = 'The treasure is buried under the oak tree'
  const DECOY_MESSAGE = 'Meeting at 5pm for coffee'
  
  console.log('\nOriginal messages:')
  console.log('  Real:', REAL_MESSAGE)
  console.log('  Decoy:', DECOY_MESSAGE)
  
  // Step 1: Create false-bottom payload
  const { ciphertext, realKey, decoyKey } = createFalseBottom(REAL_MESSAGE, DECOY_MESSAGE)
  
  // Step 2: Package with decoy key visible (real key transmitted separately)
  const innerPayload = JSON.stringify({ ct: ciphertext, dk: decoyKey })
  
  console.log('\n--- Step 1: False-bottom created ---')
  console.log('Inner payload (before NIP-44):', innerPayload.slice(0, 60) + '...')
  
  // Step 3: Encrypt with NIP-44 (sender → recipient)
  const conversationKey = getConversationKey(senderPrivKey, recipientPubKey)
  const nip44Payload = nip44Encrypt(innerPayload, conversationKey)
  
  console.log('\n--- Step 2: NIP-44 encrypted ---')
  console.log('NIP-44 payload:', nip44Payload.slice(0, 60) + '...')
  console.log('(This goes in the Nostr event content field)')
  
  // Step 4: Recipient decrypts NIP-44
  const recipientConvKey = getConversationKey(recipientPrivKey, senderPubKey)
  const decryptedInner = nip44Decrypt(nip44Payload, recipientConvKey)
  const { ct, dk } = JSON.parse(decryptedInner)
  
  console.log('\n--- Step 3: Recipient decrypts NIP-44 ---')
  console.log('Got ciphertext + decoy key')
  
  // Step 5: Decrypt with decoy key (what's "visible" in the payload)
  console.log('\n--- Decryption results ---')
  const decoyResult = decryptFalseBottom(ct, dk)
  console.log('With DECOY key (in payload):', decoyResult)
  
  // Step 6: Decrypt with real key (shared secretly)
  const realResult = decryptFalseBottom(ct, realKey)
  console.log('With REAL key (shared secretly):', realResult)
  
  console.log('\n--- Scenario ---')
  console.log('1. Send NIP-44 message to recipient (normal Nostr DM)')
  console.log('2. Recipient decrypts → sees ciphertext + decoyKey')
  console.log('3. Using decoyKey → "' + decoyResult + '"')
  console.log('4. But if they have realKey (pre-shared) → "' + realResult + '"')
  console.log('\nIf coerced to reveal nsec: they decrypt NIP-44, use decoyKey, see decoy.')
  console.log('Real message hidden unless realKey is also compromised!')
}

main().catch(console.error)

