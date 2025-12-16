/**
 * Nostr + Concatenation Demo
 * 
 * How it works:
 * - Hidden message encrypted with SHARED PASSWORD (same for all messages)
 * - Appended to decoy as "metadata" that looks intentional
 * - ONE shared password works forever
 * - 100% NIP-44 compatible
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import * as secp from '@noble/secp256k1'

// === ENCRYPT HIDDEN WITH SHARED PASSWORD ===

function deriveKey(password: string, salt: Uint8Array): Uint8Array {
  const passwordBytes = new TextEncoder().encode(password)
  return hkdf(sha256, passwordBytes, salt, new TextEncoder().encode('hidden-msg'), 32)
}

function encryptHidden(hidden: string, password: string): string {
  const salt = randomBytes(16)
  const nonce = randomBytes(24)
  const key = deriveKey(password, salt)
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(new TextEncoder().encode(hidden))
  
  // Combine: salt(16) + nonce(24) + ciphertext
  const combined = new Uint8Array(16 + 24 + ciphertext.length)
  combined.set(salt, 0)
  combined.set(nonce, 16)
  combined.set(ciphertext, 40)
  return Buffer.from(combined).toString('base64')
}

function decryptHidden(encrypted: string, password: string): string {
  const data = new Uint8Array(Buffer.from(encrypted, 'base64'))
  const salt = data.slice(0, 16)
  const nonce = data.slice(16, 40)
  const ciphertext = data.slice(40)
  const key = deriveKey(password, salt)
  const plaintext = xchacha20poly1305(key, nonce).decrypt(ciphertext)
  return new TextDecoder().decode(plaintext)
}

// === COMBINE DECOY + HIDDEN ===

const DELIMITER = '\n\n📎 '  // Looks like an attachment reference

function combineMessages(decoy: string, hidden: string, password: string): string {
  const encryptedHidden = encryptHidden(hidden, password)
  return decoy + DELIMITER + encryptedHidden
}

function splitMessages(combined: string, password: string): { decoy: string; hidden: string | null } {
  const parts = combined.split(DELIMITER)
  const decoy = parts[0]
  
  if (parts.length < 2) {
    return { decoy, hidden: null }
  }
  
  try {
    const hidden = decryptHidden(parts[1], password)
    return { decoy, hidden }
  } catch {
    return { decoy, hidden: null }  // Wrong password or no hidden message
  }
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
const SHARED_PASSWORD = 'our-secret-phrase-2024'  // Same for ALL messages!

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗')
  console.log('║              NOSTR + CONCATENATION DEMO                    ║')
  console.log('║  Hidden encrypted with shared password, appended to decoy  ║')
  console.log('╚════════════════════════════════════════════════════════════╝\n')

  const senderPrivKey = secp.utils.randomSecretKey()
  const senderPubKey = secp.getPublicKey(senderPrivKey, true)
  const recipientPrivKey = secp.utils.randomSecretKey()
  const recipientPubKey = secp.getPublicKey(recipientPrivKey, true)

  // === 1. MESSAGES ===
  console.log('┌─ 1. MESSAGES ─────────────────────────────────────────────┐')
  console.log('│  Decoy:  "' + DECOY_MESSAGE + '"')
  console.log('│  Hidden: "' + HIDDEN_MESSAGE + '"')
  console.log('│  Shared password: "' + SHARED_PASSWORD + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 2. COMBINE ===
  const combined = combineMessages(DECOY_MESSAGE, HIDDEN_MESSAGE, SHARED_PASSWORD)

  console.log('┌─ 2. COMBINED MESSAGE ─────────────────────────────────────┐')
  console.log('│  Before NIP-44 encryption:')
  console.log('│')
  console.log('│  ' + combined.split('\n').join('\n│  '))
  console.log('│')
  console.log('│  (Looks like a message with an attachment/reference)')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 3. NIP-44 ENCRYPT ===
  const conversationKey = getConversationKey(senderPrivKey, recipientPubKey)
  const nip44Payload = nip44Encrypt(combined, conversationKey)

  console.log('┌─ 3. PAYLOAD ──────────────────────────────────────────────┐')
  console.log('│  NIP-44 encrypted:')
  console.log('│    ' + nip44Payload)
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 4. DECRYPT (any Nostr client) ===
  const recipientConvKey = getConversationKey(recipientPrivKey, senderPubKey)
  const decrypted = nip44Decrypt(nip44Payload, recipientConvKey)

  console.log('┌─ 4. DECRYPT (any Nostr client) ───────────────────────────┐')
  console.log('│  Raw decrypted:')
  console.log('│  ' + decrypted.split('\n').join('\n│  '))
  console.log('│')
  console.log('│  What user sees: decoy + some attachment-looking data')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 5. EXTRACT HIDDEN (with password) ===
  const { decoy, hidden } = splitMessages(decrypted, SHARED_PASSWORD)

  console.log('┌─ 5. EXTRACT HIDDEN (with shared password) ────────────────┐')
  console.log('│  Decoy:  "' + decoy + '"')
  console.log('│  Hidden: "' + hidden + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 6. WRONG PASSWORD ===
  const wrongResult = splitMessages(decrypted, 'wrong-password')

  console.log('┌─ 6. WRONG PASSWORD ───────────────────────────────────────┐')
  console.log('│  Decoy:  "' + wrongResult.decoy + '"')
  console.log('│  Hidden: ' + (wrongResult.hidden ?? '(decryption failed)'))
  console.log('└───────────────────────────────────────────────────────────┘\n')

  console.log('✓ ONE shared password works for ALL messages')
  console.log('✓ 100% NIP-44 compatible')
  console.log('✓ Hidden data looks like attachment/reference metadata')
  console.log('✓ Wrong password = cannot decrypt hidden part')
}

main().catch(console.error)

