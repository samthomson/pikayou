/**
 * Nostr + False Bottom Demo
 * 
 * How it works:
 * - Create false-bottom (1 ciphertext, 2 keys)
 * - Package with decoy key, encrypt with NIP-44
 * - Recipient decrypts NIP-44 → gets ciphertext + decoy key
 * - Hidden key shared separately
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import * as secp from '@noble/secp256k1'

// === FALSE BOTTOM (XOR) ===
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(Math.max(a.length, b.length))
  for (let i = 0; i < result.length; i++) result[i] = (a[i] || 0) ^ (b[i] || 0)
  return result
}

function padMessage(msg: string, len: number): Uint8Array {
  const buf = new Uint8Array(len)
  buf.set(new TextEncoder().encode(msg))
  return buf
}

function createFalseBottom(hiddenMessage: string, decoyMessage: string) {
  const maxLen = Math.max(hiddenMessage.length, decoyMessage.length, 64)
  const hiddenBuf = padMessage(hiddenMessage, maxLen)
  const decoyBuf = padMessage(decoyMessage, maxLen)
  const hiddenKey = randomBytes(maxLen)
  const ciphertext = xorBytes(hiddenBuf, hiddenKey)
  const decoyKey = xorBytes(ciphertext, decoyBuf)
  return {
    ciphertext: Buffer.from(ciphertext).toString('base64'),
    hiddenKey: Buffer.from(hiddenKey).toString('base64'),
    decoyKey: Buffer.from(decoyKey).toString('base64')
  }
}

function decryptFalseBottom(ciphertext: string, key: string): string {
  const ct = new Uint8Array(Buffer.from(ciphertext, 'base64'))
  const k = new Uint8Array(Buffer.from(key, 'base64'))
  return new TextDecoder().decode(xorBytes(ct, k)).replace(/\0+$/, '')
}

// === NIP-44 ===
function getConversationKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const sharedX = secp.getSharedSecret(privateKey, publicKey).slice(1, 33)
  return hkdf(sha256, sharedX, new TextEncoder().encode('nip44-v2'), undefined, 32)
}

function nip44Encrypt(plaintext: string, conversationKey: Uint8Array): string {
  const nonce = randomBytes(24)
  const messageKey = hkdf(sha256, conversationKey, nonce, new TextEncoder().encode('nip44-v2'), 32)
  const ciphertext = xchacha20poly1305(messageKey, nonce).encrypt(new TextEncoder().encode(plaintext))
  const result = new Uint8Array(1 + 24 + ciphertext.length)
  result[0] = 2
  result.set(nonce, 1)
  result.set(ciphertext, 25)
  return Buffer.from(result).toString('base64')
}

function nip44Decrypt(payload: string, conversationKey: Uint8Array): string {
  const data = new Uint8Array(Buffer.from(payload, 'base64'))
  const nonce = data.slice(1, 25)
  const ciphertext = data.slice(25)
  const messageKey = hkdf(sha256, conversationKey, nonce, new TextEncoder().encode('nip44-v2'), 32)
  return new TextDecoder().decode(xchacha20poly1305(messageKey, nonce).decrypt(ciphertext))
}

// === DEMO ===
const DECOY_MESSAGE = 'Meeting at 5pm for coffee'
const HIDDEN_MESSAGE = 'The treasure is buried under the oak tree'

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗')
  console.log('║              NOSTR + FALSE BOTTOM DEMO                     ║')
  console.log('║  NIP-44 encrypted, with false-bottom inside                ║')
  console.log('╚════════════════════════════════════════════════════════════╝\n')

  // Generate keys
  const senderPrivKey = secp.utils.randomSecretKey()
  const senderPubKey = secp.getPublicKey(senderPrivKey, true)
  const recipientPrivKey = secp.utils.randomSecretKey()
  const recipientPubKey = secp.getPublicKey(recipientPrivKey, true)

  // === 1. MESSAGES ===
  console.log('┌─ 1. MESSAGES ─────────────────────────────────────────────┐')
  console.log('│  Decoy:  "' + DECOY_MESSAGE + '"')
  console.log('│  Hidden: "' + HIDDEN_MESSAGE + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 2. ENCRYPT ===
  const { ciphertext, hiddenKey, decoyKey } = createFalseBottom(HIDDEN_MESSAGE, DECOY_MESSAGE)
  const innerPayload = JSON.stringify({ ct: ciphertext, dk: decoyKey })
  const conversationKey = getConversationKey(senderPrivKey, recipientPubKey)
  const nip44Payload = nip44Encrypt(innerPayload, conversationKey)

  console.log('┌─ 2. PAYLOAD ──────────────────────────────────────────────┐')
  console.log('│  Type: NIP-44 encrypted message (goes in Nostr event)')
  console.log('│  NIP-44 payload: ' + nip44Payload.slice(0, 40) + '...')
  console.log('│  Inner content: { ct: ciphertext, dk: decoyKey }')
  console.log('│  Hidden key: shared separately (not in payload)')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 3. DECRYPT NORMAL ===
  const recipientConvKey = getConversationKey(recipientPrivKey, senderPubKey)
  const decryptedInner = nip44Decrypt(nip44Payload, recipientConvKey)
  const { ct, dk } = JSON.parse(decryptedInner)
  const decoyResult = decryptFalseBottom(ct, dk)

  console.log('┌─ 3. DECRYPT (normal way - NIP-44 + decoy key) ────────────┐')
  console.log('│  Step 1: Decrypt NIP-44 with recipient nsec')
  console.log('│  Step 2: Use decoyKey from payload')
  console.log('│  Result: "' + decoyResult + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 4. DECRYPT HIDDEN ===
  const hiddenResult = decryptFalseBottom(ct, hiddenKey)

  console.log('┌─ 4. DECRYPT (secret way - NIP-44 + hidden key) ───────────┐')
  console.log('│  Step 1: Decrypt NIP-44 with recipient nsec')
  console.log('│  Step 2: Use hiddenKey (pre-shared secretly)')
  console.log('│  Result: "' + hiddenResult + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  console.log('✓ Looks like normal NIP-44 DM on Nostr')
  console.log('✓ If nsec compromised: attacker uses decoyKey, sees decoy')
  console.log('✓ Hidden message requires separately shared hiddenKey')
}

main().catch(console.error)
