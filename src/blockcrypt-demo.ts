/**
 * Blockcrypt Demo
 * 
 * How it works:
 * - Encrypt multiple secrets with different passphrases into ONE block
 * - Each passphrase decrypts ONLY its own message
 * - Headers are indistinguishable - can't tell how many secrets exist
 * - Padding makes it impossible to know actual data sizes
 */

import { encrypt, decrypt } from 'blockcrypt'
import { scrypt } from 'crypto'

// Key derivation function (required by blockcrypt)
const kdf = async (passphrase: string, salt: string): Promise<Buffer> => {
  return new Promise((resolve, reject) => {
    scrypt(passphrase, salt, 32, (err, key) => {
      if (err) reject(err)
      else resolve(key)
    })
  })
}

const REAL_MESSAGE = 'The treasure is buried under the oak tree'
const DECOY_MESSAGE = 'Meeting at 5pm for coffee'
const REAL_PASSPHRASE = 'correct-horse-battery-staple'
const DECOY_PASSPHRASE = 'password123'

async function main() {
  console.log('=== BLOCKCRYPT DEMO ===\n')
  
  console.log('Original messages:')
  console.log('  Real:', REAL_MESSAGE)
  console.log('  Decoy:', DECOY_MESSAGE)
  
  // Encrypt both secrets into ONE block
  const secrets = [
    { message: DECOY_MESSAGE, passphrase: DECOY_PASSPHRASE },
    { message: REAL_MESSAGE, passphrase: REAL_PASSPHRASE },
  ]
  
  const block = await encrypt(secrets, kdf)
  
  console.log('\n--- ONE Block (contains both secrets) ---')
  console.log('Salt:', block.salt.toString('base64'))
  console.log('IV:', block.iv.toString('base64'))
  console.log('Headers:', block.headers.toString('base64').slice(0, 40) + '...')
  console.log('Data:', block.data.toString('base64').slice(0, 40) + '...')
  
  // Decrypt with different passphrases
  console.log('\n--- Decryption ---')
  
  const decryptedDecoy = await decrypt(
    DECOY_PASSPHRASE,
    block.salt,
    block.iv,
    block.headers,
    block.data,
    kdf
  )
  
  const decryptedReal = await decrypt(
    REAL_PASSPHRASE,
    block.salt,
    block.iv,
    block.headers,
    block.data,
    kdf
  )
  
  console.log('With DECOY passphrase:', decryptedDecoy.toString())
  console.log('With REAL passphrase:', decryptedReal.toString())
  
  // Wrong passphrase
  console.log('\n--- Wrong passphrase ---')
  try {
    await decrypt('wrong-password', block.salt, block.iv, block.headers, block.data, kdf)
    console.log('Decrypted something (should not happen)')
  } catch (e) {
    console.log('Error: Header not found (expected - wrong passphrase)')
  }
  
  console.log('\n--- Scenario ---')
  console.log('Store: salt, iv, headers, data (the block)')
  console.log('If coerced: give up DECOY_PASSPHRASE')
  console.log('They decrypt:', decryptedDecoy.toString())
  console.log('They cannot know another secret exists!')
  console.log('Your real message stays hidden!')
}

main()

