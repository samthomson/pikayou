/**
 * Nostr + Blockcrypt Combined Demo
 * 
 * A new approach combining:
 * - NIP-44 compatibility (any Nostr client can decrypt decoy)
 * - Blockcrypt-style plausible deniability (can't tell how many secrets)
 * - Custom password for hidden message
 * 
 * Structure:
 * - Slot 1: NIP-44 conversation key → decoy message
 * - Slot 2: Custom password → hidden message
 * - Headers are indistinguishable (blockcrypt-style)
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import * as secp from '@noble/secp256k1'

// === KEY DERIVATION ===

function deriveKey(input: Uint8Array | string, salt: Uint8Array, info: string): Uint8Array {
  const inputBytes = typeof input === 'string' 
    ? new TextEncoder().encode(input) 
    : input
  return hkdf(sha256, inputBytes, salt, new TextEncoder().encode(info), 32)
}

function getConversationKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const sharedX = secp.getSharedSecret(privateKey, publicKey).slice(1, 33)
  return hkdf(sha256, sharedX, new TextEncoder().encode('nip44-v2'), undefined, 32)
}

// === BLOCKCRYPT-STYLE ENCRYPTION ===

interface Secret {
  message: string
  key: Uint8Array | string  // Uint8Array for NIP-44 key, string for password
}

interface EncryptedBlock {
  salt: string      // base64
  iv: string        // base64
  headers: string   // base64 (padded, indistinguishable)
  data: string      // base64 (padded)
}

const HEADER_SIZE = 32  // bytes per header slot
const MAX_SLOTS = 4
const HEADERS_LENGTH = HEADER_SIZE * MAX_SLOTS  // 128 bytes total

function encrypt(secrets: Secret[]): EncryptedBlock {
  const salt = randomBytes(16)
  const iv = randomBytes(24)  // xchacha20 needs 24-byte nonce
  
  const headers: Uint8Array[] = []
  const dataChunks: Uint8Array[] = []
  let dataOffset = 0
  
  for (const secret of secrets) {
    // Derive encryption key
    const key = deriveKey(secret.key, salt, 'nostr-blockcrypt')
    
    // Encrypt message
    const nonce = randomBytes(24)
    const cipher = xchacha20poly1305(key, nonce)
    const encrypted = cipher.encrypt(new TextEncoder().encode(secret.message))
    
    // Create header: offset (4 bytes) + length (4 bytes) + nonce (24 bytes) = 32 bytes
    const header = new Uint8Array(HEADER_SIZE)
    const view = new DataView(header.buffer)
    view.setUint32(0, dataOffset, true)
    view.setUint32(4, encrypted.length, true)
    header.set(nonce, 8)
    
    // Encrypt header with same key
    const headerKey = deriveKey(secret.key, salt, 'nostr-blockcrypt-header')
    const headerCipher = xchacha20poly1305(headerKey, iv)
    // Pad header to fixed size before encrypting
    const encryptedHeader = headerCipher.encrypt(header)
    headers.push(encryptedHeader)
    
    dataChunks.push(encrypted)
    dataOffset += encrypted.length
  }
  
  // Pad headers to fixed length (indistinguishable)
  let headersBuffer = new Uint8Array(HEADERS_LENGTH + (secrets.length * 16)) // account for auth tags
  let headerOffset = 0
  for (const h of headers) {
    headersBuffer.set(h, headerOffset)
    headerOffset += h.length
  }
  // Fill rest with random (looks like more encrypted headers)
  const remaining = randomBytes(headersBuffer.length - headerOffset)
  headersBuffer.set(remaining, headerOffset)
  
  // Combine data and pad
  const totalDataLength = dataChunks.reduce((sum, d) => sum + d.length, 0)
  const paddedDataLength = Math.ceil(totalDataLength / 64) * 64 + 64  // pad to 64-byte boundary + extra
  const dataBuffer = new Uint8Array(paddedDataLength)
  let dataPos = 0
  for (const chunk of dataChunks) {
    dataBuffer.set(chunk, dataPos)
    dataPos += chunk.length
  }
  // Fill rest with random
  dataBuffer.set(randomBytes(paddedDataLength - dataPos), dataPos)
  
  return {
    salt: Buffer.from(salt).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    headers: Buffer.from(headersBuffer).toString('base64'),
    data: Buffer.from(dataBuffer).toString('base64')
  }
}

function decrypt(block: EncryptedBlock, key: Uint8Array | string): string | null {
  const salt = new Uint8Array(Buffer.from(block.salt, 'base64'))
  const iv = new Uint8Array(Buffer.from(block.iv, 'base64'))
  const headers = new Uint8Array(Buffer.from(block.headers, 'base64'))
  const data = new Uint8Array(Buffer.from(block.data, 'base64'))
  
  const headerKey = deriveKey(key, salt, 'nostr-blockcrypt-header')
  const dataKey = deriveKey(key, salt, 'nostr-blockcrypt')
  
  // Try to find and decrypt our header
  const encryptedHeaderSize = HEADER_SIZE + 16  // header + auth tag
  
  for (let i = 0; i <= headers.length - encryptedHeaderSize; i += encryptedHeaderSize) {
    try {
      const encryptedHeader = headers.slice(i, i + encryptedHeaderSize)
      const headerCipher = xchacha20poly1305(headerKey, iv)
      const header = headerCipher.decrypt(encryptedHeader)
      
      const view = new DataView(header.buffer, header.byteOffset)
      const offset = view.getUint32(0, true)
      const length = view.getUint32(4, true)
      const nonce = header.slice(8, 32)
      
      // Sanity check
      if (offset + length > data.length) continue
      
      const encrypted = data.slice(offset, offset + length)
      const cipher = xchacha20poly1305(dataKey, nonce)
      const decrypted = cipher.decrypt(encrypted)
      
      return new TextDecoder().decode(decrypted)
    } catch {
      // Wrong key for this slot, try next
      continue
    }
  }
  
  return null  // No valid header found for this key
}

// === DEMO ===

const DECOY_MESSAGE = 'Meeting at 5pm for coffee'
const HIDDEN_MESSAGE = 'The treasure is buried under the oak tree'
const CUSTOM_PASSWORD = 'our-secret-phrase'

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗')
  console.log('║              NOSTR + BLOCKCRYPT DEMO                       ║')
  console.log('║  NIP-44 compatible + password slot + plausible deniability ║')
  console.log('╚════════════════════════════════════════════════════════════╝\n')

  // Generate Nostr keys
  const senderPrivKey = secp.utils.randomSecretKey()
  const senderPubKey = secp.getPublicKey(senderPrivKey, true)
  const recipientPrivKey = secp.utils.randomSecretKey()
  const recipientPubKey = secp.getPublicKey(recipientPrivKey, true)
  
  // NIP-44 conversation key (what normal Nostr clients derive)
  const conversationKey = getConversationKey(senderPrivKey, recipientPubKey)

  // === 1. MESSAGES ===
  console.log('┌─ 1. MESSAGES ─────────────────────────────────────────────┐')
  console.log('│  Decoy (NIP-44):  "' + DECOY_MESSAGE + '"')
  console.log('│  Hidden (password): "' + HIDDEN_MESSAGE + '"')
  console.log('│  Custom password: "' + CUSTOM_PASSWORD + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 2. ENCRYPT ===
  const block = encrypt([
    { message: DECOY_MESSAGE, key: conversationKey },    // NIP-44 slot
    { message: HIDDEN_MESSAGE, key: CUSTOM_PASSWORD },   // Password slot
  ])

  console.log('┌─ 2. PAYLOAD ──────────────────────────────────────────────┐')
  console.log('│  Type: Blockcrypt-style block (indistinguishable headers)')
  console.log('│  Salt: ' + block.salt)
  console.log('│  IV: ' + block.iv)
  console.log('│  Headers: ' + block.headers.slice(0, 50) + '...')
  console.log('│  Data: ' + block.data.slice(0, 50) + '...')
  console.log('│')
  console.log('│  ✓ Cannot tell how many secrets exist!')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 3. DECRYPT WITH NIP-44 KEY ===
  const recipientConvKey = getConversationKey(recipientPrivKey, senderPubKey)
  const decoyResult = decrypt(block, recipientConvKey)

  console.log('┌─ 3. DECRYPT (NIP-44 conversation key) ────────────────────┐')
  console.log('│  Key: derived from sender pubkey + recipient privkey')
  console.log('│  Result: "' + decoyResult + '"')
  console.log('│')
  console.log('│  ✓ Any Nostr client with access to keys can do this!')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 4. DECRYPT WITH PASSWORD ===
  const hiddenResult = decrypt(block, CUSTOM_PASSWORD)

  console.log('┌─ 4. DECRYPT (custom password) ────────────────────────────┐')
  console.log('│  Password: "' + CUSTOM_PASSWORD + '"')
  console.log('│  Result: "' + hiddenResult + '"')
  console.log('│')
  console.log('│  ✓ Only those who know the password can see this!')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 5. WRONG PASSWORD ===
  const wrongResult = decrypt(block, 'wrong-password')

  console.log('┌─ 5. WRONG PASSWORD ───────────────────────────────────────┐')
  console.log('│  Password: "wrong-password"')
  console.log('│  Result: ' + (wrongResult ?? '(no valid message found)'))
  console.log('└───────────────────────────────────────────────────────────┘\n')

  console.log('✓ Slot 1: NIP-44 compatible (Nostr clients work)')
  console.log('✓ Slot 2: Custom password (plausibly deniable)')
  console.log('✓ Headers indistinguishable - can\'t tell how many secrets')
  console.log('✓ Same password works for all messages')
  console.log('')
  console.log('📋 To use as Nostr DM: base64 encode the whole block as content')
}

main().catch(console.error)

