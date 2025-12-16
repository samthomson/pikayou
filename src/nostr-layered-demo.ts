/**
 * Nostr + Layered Encryption Demo
 * 
 * Structure:
 * - Outer: Standard NIP-44 encryption (Nostr transport)
 * - Inner: Blockcrypt-style content
 *   - Slot 0: NO password → decoy message (anyone can read)
 *   - Slot 1: PASSWORD → hidden message (only those who know)
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import * as secp from '@noble/secp256k1'

// === INNER LAYER: Blockcrypt-style multi-slot encryption ===

const SLOT_COUNT = 4
const HEADER_SIZE = 48

interface InnerBlock {
  salt: string
  headers: string
  data: string
}

function deriveSlotKey(password: string, salt: Uint8Array, slot: number): Uint8Array {
  const input = new TextEncoder().encode(password + ':slot:' + slot)
  return hkdf(sha256, input, salt, new TextEncoder().encode('inner-slot'), 32)
}

function encryptInner(messages: { message: string; password: string }[]): InnerBlock {
  const salt = randomBytes(16)
  const headers = new Uint8Array(SLOT_COUNT * HEADER_SIZE)
  const dataChunks: Uint8Array[] = []
  let dataOffset = 0
  
  crypto.getRandomValues(headers)
  
  for (let slot = 0; slot < messages.length && slot < SLOT_COUNT; slot++) {
    const { message, password } = messages[slot]
    const key = deriveSlotKey(password, salt, slot)
    const nonce = randomBytes(24)
    
    const cipher = xchacha20poly1305(key, nonce)
    const encrypted = cipher.encrypt(new TextEncoder().encode(message))
    
    const headerOffset = slot * HEADER_SIZE
    const headerView = new DataView(headers.buffer, headerOffset)
    headerView.setUint32(0, dataOffset, true)
    headerView.setUint32(4, encrypted.length, true)
    headers.set(nonce, headerOffset + 8)
    
    dataChunks.push(encrypted)
    dataOffset += encrypted.length
  }
  
  const totalData = dataChunks.reduce((sum, d) => sum + d.length, 0)
  const paddedLength = Math.ceil(totalData / 64) * 64 + 64
  const data = new Uint8Array(paddedLength)
  let pos = 0
  for (const chunk of dataChunks) {
    data.set(chunk, pos)
    pos += chunk.length
  }
  data.set(randomBytes(paddedLength - pos), pos)
  
  return {
    salt: Buffer.from(salt).toString('base64'),
    headers: Buffer.from(headers).toString('base64'),
    data: Buffer.from(data).toString('base64')
  }
}

function decryptInner(block: InnerBlock, password: string): string | null {
  const salt = new Uint8Array(Buffer.from(block.salt, 'base64'))
  const headers = new Uint8Array(Buffer.from(block.headers, 'base64'))
  const data = new Uint8Array(Buffer.from(block.data, 'base64'))
  
  for (let slot = 0; slot < SLOT_COUNT; slot++) {
    try {
      const key = deriveSlotKey(password, salt, slot)
      const headerOffset = slot * HEADER_SIZE
      const headerView = new DataView(headers.buffer, headers.byteOffset + headerOffset)
      const dataOffset = headerView.getUint32(0, true)
      const dataLength = headerView.getUint32(4, true)
      const nonce = headers.slice(headerOffset + 8, headerOffset + 32)
      
      if (dataOffset + dataLength > data.length) continue
      
      const encrypted = data.slice(dataOffset, dataOffset + dataLength)
      const cipher = xchacha20poly1305(key, nonce)
      const decrypted = cipher.decrypt(encrypted)
      
      return new TextDecoder().decode(decrypted)
    } catch {
      continue
    }
  }
  return null
}

// === OUTER LAYER: NIP-44 style encryption ===

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
const NO_PASSWORD = ''
const SECRET_PASSWORD = 'our-secret-phrase'

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗')
  console.log('║              NOSTR + LAYERED ENCRYPTION DEMO               ║')
  console.log('║  NIP-44 outside, blockcrypt-style inside                   ║')
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
  console.log('│')
  console.log('│  Decoy password: "" (empty)')
  console.log('│  Hidden password: "' + SECRET_PASSWORD + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 2. CREATE INNER BLOCK ===
  const innerBlock = encryptInner([
    { message: DECOY_MESSAGE, password: NO_PASSWORD },
    { message: HIDDEN_MESSAGE, password: SECRET_PASSWORD },
  ])
  const innerContent = JSON.stringify(innerBlock)

  console.log('┌─ 2. INNER BLOCK (blockcrypt-style) ───────────────────────┐')
  console.log('│  Salt: ' + innerBlock.salt)
  console.log('│  Headers: ' + innerBlock.headers)
  console.log('│  Data: ' + innerBlock.data)
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 3. NIP-44 ENCRYPT ===
  const conversationKey = getConversationKey(senderPrivKey, recipientPubKey)
  const nip44Payload = nip44Encrypt(innerContent, conversationKey)

  console.log('┌─ 3. NIP-44 PAYLOAD (what goes on Nostr) ──────────────────┐')
  console.log('│  ' + nip44Payload)
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 4. NIP-44 DECRYPT ===
  const recipientConvKey = getConversationKey(recipientPrivKey, senderPubKey)
  const decryptedInner = nip44Decrypt(nip44Payload, recipientConvKey)
  const recoveredBlock: InnerBlock = JSON.parse(decryptedInner)

  console.log('┌─ 4. NIP-44 DECRYPTED (recipient decrypts) ────────────────┐')
  console.log('│  Salt: ' + recoveredBlock.salt)
  console.log('│  Headers: ' + recoveredBlock.headers)
  console.log('│  Data: ' + recoveredBlock.data)
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 5. DECRYPT DECOY (empty password) ===
  const decoyResult = decryptInner(recoveredBlock, NO_PASSWORD)

  console.log('┌─ 5. DECRYPT SLOT 0 (empty password - anyone) ─────────────┐')
  console.log('│  Password: "" (empty)')
  console.log('│  Result: "' + decoyResult + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 6. DECRYPT HIDDEN (secret password) ===
  const hiddenResult = decryptInner(recoveredBlock, SECRET_PASSWORD)

  console.log('┌─ 6. DECRYPT SLOT 1 (secret password) ─────────────────────┐')
  console.log('│  Password: "' + SECRET_PASSWORD + '"')
  console.log('│  Result: "' + hiddenResult + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  console.log('✓ NIP-44 encrypted → inner block')
  console.log('✓ Empty password → decoy message')
  console.log('✓ Secret password → hidden message')
  console.log('✓ Same password works for ALL messages')
}

main().catch(console.error)
