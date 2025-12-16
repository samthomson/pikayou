/**
 * Nostr + Steganography Demo
 * 
 * How it works:
 * - Hidden message is encoded as invisible zero-width Unicode characters
 * - Inserted into the decoy message (invisible to human eye!)
 * - ONE shared password works for ALL messages
 * - Everything in ONE NIP-44 payload
 * - Decrypted text looks totally normal
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import * as secp from '@noble/secp256k1'

// === STEGANOGRAPHY: Zero-width character encoding ===
// Uses invisible Unicode characters to encode binary data

const ZERO_WIDTH_CHARS = [
  '\u200B', // zero-width space
  '\u200C', // zero-width non-joiner
  '\u200D', // zero-width joiner
  '\uFEFF', // zero-width no-break space
]

function textToBinary(text: string): string {
  return Array.from(new TextEncoder().encode(text))
    .map(byte => byte.toString(2).padStart(8, '0'))
    .join('')
}

function binaryToText(binary: string): string {
  const bytes = binary.match(/.{8}/g) || []
  return new TextDecoder().decode(new Uint8Array(bytes.map(b => parseInt(b, 2))))
}

function encodeHidden(hidden: string): string {
  // Convert to binary, then map each pair of bits to a zero-width char
  const binary = textToBinary(hidden)
  let encoded = ''
  for (let i = 0; i < binary.length; i += 2) {
    const pair = binary.slice(i, i + 2).padEnd(2, '0')
    const index = parseInt(pair, 2) // 00=0, 01=1, 10=2, 11=3
    encoded += ZERO_WIDTH_CHARS[index]
  }
  return encoded
}

function decodeHidden(stegoText: string): string {
  // Extract zero-width chars and convert back to binary
  let binary = ''
  for (const char of stegoText) {
    const index = ZERO_WIDTH_CHARS.indexOf(char)
    if (index !== -1) {
      binary += index.toString(2).padStart(2, '0')
    }
  }
  // Trim to nearest byte boundary
  binary = binary.slice(0, Math.floor(binary.length / 8) * 8)
  return binaryToText(binary)
}

function embedInDecoy(decoy: string, hidden: string): string {
  const encoded = encodeHidden(hidden)
  // Insert zero-width chars after first character of decoy
  return decoy[0] + encoded + decoy.slice(1)
}

function extractFromDecoy(stegoText: string): { decoy: string; hidden: string } {
  // Remove zero-width chars to get visible decoy
  const decoy = stegoText.replace(/[\u200B\u200C\u200D\uFEFF]/g, '')
  const hidden = decodeHidden(stegoText)
  return { decoy, hidden }
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
const HIDDEN_MESSAGE = 'Oak tree 3pm'  // Shorter for demo (stego has size limits)

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗')
  console.log('║              NOSTR + STEGANOGRAPHY DEMO                    ║')
  console.log('║  Hidden message invisible inside decoy text                ║')
  console.log('╚════════════════════════════════════════════════════════════╝\n')

  const senderPrivKey = secp.utils.randomSecretKey()
  const senderPubKey = secp.getPublicKey(senderPrivKey, true)
  const recipientPrivKey = secp.utils.randomSecretKey()
  const recipientPubKey = secp.getPublicKey(recipientPrivKey, true)

  // === 1. MESSAGES ===
  console.log('┌─ 1. MESSAGES ─────────────────────────────────────────────┐')
  console.log('│  Decoy:  "' + DECOY_MESSAGE + '"')
  console.log('│  Hidden: "' + HIDDEN_MESSAGE + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 2. EMBED HIDDEN IN DECOY ===
  const stegoMessage = embedInDecoy(DECOY_MESSAGE, HIDDEN_MESSAGE)
  
  console.log('┌─ 2. STEGANOGRAPHY ────────────────────────────────────────┐')
  console.log('│  Decoy with hidden embedded:')
  console.log('│    "' + stegoMessage + '"')
  console.log('│')
  console.log('│  Looks identical! But string length is different:')
  console.log('│    Original decoy length: ' + DECOY_MESSAGE.length)
  console.log('│    With hidden embedded:  ' + stegoMessage.length)
  console.log('│    (Extra chars are invisible zero-width Unicode)')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 3. ENCRYPT WITH NIP-44 ===
  const conversationKey = getConversationKey(senderPrivKey, recipientPubKey)
  const nip44Payload = nip44Encrypt(stegoMessage, conversationKey)

  console.log('┌─ 3. PAYLOAD ──────────────────────────────────────────────┐')
  console.log('│  NIP-44 encrypted (ONE payload, contains everything):')
  console.log('│    ' + nip44Payload)
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 4. DECRYPT NORMAL ===
  const recipientConvKey = getConversationKey(recipientPrivKey, senderPubKey)
  const decrypted = nip44Decrypt(nip44Payload, recipientConvKey)

  console.log('┌─ 4. DECRYPT (normal - any Nostr client) ──────────────────┐')
  console.log('│  Result: "' + decrypted + '"')
  console.log('│')
  console.log('│  Visible text: "' + decrypted.replace(/[\u200B\u200C\u200D\uFEFF]/g, '') + '"')
  console.log('│  ✓ Looks totally normal!')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 5. EXTRACT HIDDEN ===
  const { decoy, hidden } = extractFromDecoy(decrypted)

  console.log('┌─ 5. EXTRACT HIDDEN (if you know to look) ─────────────────┐')
  console.log('│  Decoy text:  "' + decoy + '"')
  console.log('│  Hidden text: "' + hidden + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  console.log('✓ ONE NIP-44 payload contains both messages')
  console.log('✓ No separate secret needed per message')
  console.log('✓ Hidden data is invisible Unicode - looks normal')
  console.log('')
  console.log('⚠️  Limitations:')
  console.log('   - Hidden message adds ~4x its length in invisible chars')
  console.log('   - Some apps may strip zero-width chars')
  console.log('   - Detectable if someone inspects string length/bytes')
}

main().catch(console.error)

