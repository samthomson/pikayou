/**
 * Deniable Encryption Demo
 * 
 * How it works:
 * - Uses RSA asymmetric encryption
 * - Creates TWO separate ciphertexts with TWO key pairs
 * - Give up plausible keypair + ciphertext if coerced
 */

import { DeniableEncryption } from 'deniable-encryption'

const DECOY_MESSAGE = 'Meeting at 5pm for coffee'
const HIDDEN_MESSAGE = 'The treasure is buried under the oak tree'

console.log('╔════════════════════════════════════════════════════════════╗')
console.log('║              DENIABLE ENCRYPTION DEMO                      ║')
console.log('║  Two ciphertexts, two keypairs (RSA-based)                 ║')
console.log('╚════════════════════════════════════════════════════════════╝\n')

// === 1. MESSAGES ===
console.log('┌─ 1. MESSAGES ─────────────────────────────────────────────┐')
console.log('│  Decoy:  "' + DECOY_MESSAGE + '"')
console.log('│  Hidden: "' + HIDDEN_MESSAGE + '"')
console.log('└───────────────────────────────────────────────────────────┘\n')

// === 2. ENCRYPT ===
const { publicKey, privateKey } = DeniableEncryption.generateKeyPair()
const {
  encryptedOriginalMessage,
  plausibleKeyPair,
  encryptedPlausibleMessage
} = DeniableEncryption.createDeniableEncryption({
  originalMessage: HIDDEN_MESSAGE,
  plausibleMessage: DECOY_MESSAGE,
  publicKey
})

console.log('┌─ 2. PAYLOAD ──────────────────────────────────────────────┐')
console.log('│  Type: TWO separate RSA-encrypted ciphertexts')
console.log('│  Ciphertext (hidden):')
console.log('│    ' + encryptedOriginalMessage)
console.log('│  Ciphertext (decoy):')
console.log('│    ' + encryptedPlausibleMessage)
console.log('│  Note: Each has its own keypair')
console.log('└───────────────────────────────────────────────────────────┘\n')

// === 3. DECRYPT NORMAL ===
const decoyResult = DeniableEncryption.decryptWithPrivateKey(
  plausibleKeyPair.privateKey,
  encryptedPlausibleMessage
)

console.log('┌─ 3. DECRYPT (normal way - plausible private key) ─────────┐')
console.log('│  Key: plausibleKeyPair.privateKey')
console.log('│  Result: "' + decoyResult + '"')
console.log('└───────────────────────────────────────────────────────────┘\n')

// === 4. DECRYPT HIDDEN ===
const hiddenResult = DeniableEncryption.decryptWithPrivateKey(
  privateKey,
  encryptedOriginalMessage
)

console.log('┌─ 4. DECRYPT (secret way - real private key) ────────────────┐')
console.log('│  Key: privateKey (your real key)')
console.log('│  Result: "' + hiddenResult + '"')
console.log('└───────────────────────────────────────────────────────────┘\n')

console.log('✓ Two separate ciphertexts, two separate keypairs')
console.log('✓ If coerced: give up plausible keypair + its ciphertext')
