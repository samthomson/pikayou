/**
 * Deniable Encryption Demo
 * 
 * How it works:
 * - Uses RSA asymmetric encryption
 * - You encrypt original message with YOUR public key
 * - Library generates a SECOND key pair for the plausible message
 * - If coerced, you give up the plausible private key → reveals decoy
 * - Your real private key → reveals real message
 * - Both ciphertexts look legitimate
 */

import { DeniableEncryption } from 'deniable-encryption'

const REAL_MESSAGE = 'The treasure is buried under the oak tree'
const DECOY_MESSAGE = 'Meeting at 5pm for coffee'

console.log('=== DENIABLE ENCRYPTION DEMO ===\n')

// Generate your main key pair
const { publicKey, privateKey } = DeniableEncryption.generateKeyPair()

console.log('Original messages:')
console.log('  Decoy:', DECOY_MESSAGE)
console.log('  Real:', REAL_MESSAGE)

// Create deniable encryption
const {
  encryptedOriginalMessage,
  plausibleKeyPair,
  encryptedPlausibleMessage
} = DeniableEncryption.createDeniableEncryption({
  originalMessage: REAL_MESSAGE,
  plausibleMessage: DECOY_MESSAGE,
  publicKey
})

console.log('\nEncrypted original:', encryptedOriginalMessage.substring(0, 60) + '...')
console.log('Encrypted plausible:', encryptedPlausibleMessage.substring(0, 60) + '...')

// Decrypt with real private key
console.log('\n--- Decryption ---')

const decryptedReal = DeniableEncryption.decryptWithPrivateKey(
  privateKey,
  encryptedOriginalMessage
)

const decryptedDecoy = DeniableEncryption.decryptWithPrivateKey(
  plausibleKeyPair.privateKey,
  encryptedPlausibleMessage
)

console.log('With YOUR private key:', decryptedReal)
console.log('With PLAUSIBLE private key:', decryptedDecoy)

console.log('\n--- Scenario ---')
console.log('If coerced: give up plausibleKeyPair.privateKey + encryptedPlausibleMessage')
console.log('They decrypt and see:', decryptedDecoy)
console.log('Your real message stays hidden!')

