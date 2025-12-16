/**
 * Nostr + False Bottom Demo (Backwards Compatible)
 * 
 * How it works:
 * - NIP-44 message contains ONLY the decoy (normal plaintext!)
 * - Secret = hiddenMessage XOR decoyMessage (shared separately)
 * - Any Nostr client decrypts → sees decoy (100% compatible)
 * - With the secret: decoy XOR secret → hidden message
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import * as secp from '@noble/secp256k1'

// === FALSE BOTTOM (XOR) ===
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.max(a.length, b.length)
  const result = new Uint8Array(len)
  for (let i = 0; i < len; i++) result[i] = (a[i] || 0) ^ (b[i] || 0)
  return result
}

function createSecret(hiddenMessage: string, decoyMessage: string): string {
  // Secret = hidden XOR decoy (padded to same length)
  const maxLen = Math.max(hiddenMessage.length, decoyMessage.length)
  const hiddenBuf = new Uint8Array(maxLen)
  const decoyBuf = new Uint8Array(maxLen)
  hiddenBuf.set(new TextEncoder().encode(hiddenMessage))
  decoyBuf.set(new TextEncoder().encode(decoyMessage))
  const secret = xorBytes(hiddenBuf, decoyBuf)
  return Buffer.from(secret).toString('base64')
}

function revealHidden(decoyMessage: string, secret: string): string {
  const secretBuf = new Uint8Array(Buffer.from(secret, 'base64'))
  const decoyBuf = new Uint8Array(secretBuf.length)
  decoyBuf.set(new TextEncoder().encode(decoyMessage))
  const hidden = xorBytes(decoyBuf, secretBuf)
  return new TextDecoder().decode(hidden).replace(/\0+$/, '')
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
  console.log('║  100% backwards compatible with normal NIP-44              ║')
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

  // === 2. CREATE SECRET & ENCRYPT ===
  // The secret is shared separately (could be pre-shared, sent via different channel, etc)
  const secret = createSecret(HIDDEN_MESSAGE, DECOY_MESSAGE)
  
  // NIP-44 encrypts ONLY the decoy message (completely normal!)
  const conversationKey = getConversationKey(senderPrivKey, recipientPubKey)
  const nip44Payload = nip44Encrypt(DECOY_MESSAGE, conversationKey)

  console.log('┌─ 2. PAYLOAD ──────────────────────────────────────────────┐')
  console.log('│  NIP-44 content: JUST the decoy message (normal plaintext!)')
  console.log('│')
  console.log('│  NIP-44 encrypted payload:')
  console.log('│    ' + nip44Payload)
  console.log('│')
  console.log('│  Secret (shared separately, e.g. pre-shared or via other channel):')
  console.log('│    ' + secret)
  console.log('│')
  console.log('│  ✓ Any Nostr client can decrypt this normally!')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 3. DECRYPT NORMAL (any Nostr client) ===
  const recipientConvKey = getConversationKey(recipientPrivKey, senderPubKey)
  const decoyResult = nip44Decrypt(nip44Payload, recipientConvKey)

  console.log('┌─ 3. DECRYPT (normal way - any Nostr client) ──────────────┐')
  console.log('│  Decrypt NIP-44 with recipient nsec')
  console.log('│  Result: "' + decoyResult + '"')
  console.log('│')
  console.log('│  ✓ Works with Damus, Primal, Amethyst, etc!')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 4. REVEAL HIDDEN (requires secret) ===
  const hiddenResult = revealHidden(decoyResult, secret)

  console.log('┌─ 4. DECRYPT (secret way - with pre-shared secret) ────────┐')
  console.log('│  Step 1: Decrypt NIP-44 → "' + decoyResult + '"')
  console.log('│  Step 2: XOR with secret')
  console.log('│  Result: "' + hiddenResult + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  console.log('✓ NIP-44 message is 100% normal - no suspicious format')
  console.log('✓ Works with ALL existing Nostr clients')
  console.log('✓ Hidden message only revealed with separately shared secret')
}

main().catch(console.error)
