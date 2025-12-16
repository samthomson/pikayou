/**
 * False Bottom Demo (npm: false-bottom)
 * 
 * NOTE: This library appears buggy - decryption returns garbled output.
 * Kept for experimentation purposes.
 * 
 * How it's supposed to work:
 * - Start with empty ciphertext, add messages one by one
 * - Each message addition returns a unique secret key for THAT message
 * - Same ciphertext, different keys → different messages
 */

import { encrypt, decrypt } from 'false-bottom'

const REAL_MESSAGE = 'The treasure is buried under the oak tree'
const DECOY_MESSAGE = 'Meeting at 5pm for coffee'

console.log('=== FALSE BOTTOM DEMO ===\n')

console.log('Original messages:')
console.log('  Decoy:', DECOY_MESSAGE)
console.log('  Real:', REAL_MESSAGE)

// Start with empty ciphertext, add decoy message
const { updatedCiphertext: ct1, newSecretKey: decoyKey } = encrypt([], DECOY_MESSAGE)

// Add real message to same ciphertext
const { updatedCiphertext: finalCiphertext, newSecretKey: realKey } = encrypt(ct1, REAL_MESSAGE)

console.log('\nCiphertext (array of', finalCiphertext.length, 'bigints)')
console.log('First few values:', finalCiphertext.slice(0, 3).map(n => n.toString().slice(0, 20) + '...'))

// Decrypt with different keys
console.log('\n--- Decryption ---')

const decryptedDecoy = decrypt(finalCiphertext, decoyKey)
const decryptedReal = decrypt(finalCiphertext, realKey)

console.log('With DECOY key:', decryptedDecoy)
console.log('With REAL key:', decryptedReal)

console.log('\n--- Scenario ---')
console.log('If coerced: give up decoyKey')
console.log('They decrypt and see:', decryptedDecoy)
console.log('Your real message (needs realKey) stays hidden!')

console.log('\n⚠️  NOTE: If output is garbled, this library has bugs.')

