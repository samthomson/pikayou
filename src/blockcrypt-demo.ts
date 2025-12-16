/**
 * Blockcrypt Demo
 * 
 * How it works:
 * - Encrypt multiple secrets with different passphrases into ONE block
 * - Each passphrase decrypts ONLY its own message
 * - Headers are indistinguishable - can't tell how many secrets exist
 */

import { encrypt, decrypt } from 'blockcrypt'
import { scrypt } from 'crypto'

const kdf = async (passphrase: string, salt: string): Promise<Buffer> => {
  return new Promise((resolve, reject) => {
    scrypt(passphrase, salt, 32, (err, key) => {
      if (err) reject(err)
      else resolve(key)
    })
  })
}

const DECOY_MESSAGE = 'Meeting at 5pm for coffee'
const HIDDEN_MESSAGE = 'The treasure is buried under the oak tree'
const DECOY_PASS = 'password123'
const HIDDEN_PASS = 'correct-horse-battery-staple'

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗')
  console.log('║              BLOCKCRYPT DEMO                               ║')
  console.log('║  One block, multiple passphrases → different messages      ║')
  console.log('╚════════════════════════════════════════════════════════════╝\n')

  // === 1. MESSAGES ===
  console.log('┌─ 1. MESSAGES ─────────────────────────────────────────────┐')
  console.log('│  Decoy:  "' + DECOY_MESSAGE + '"')
  console.log('│  Hidden: "' + HIDDEN_MESSAGE + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 2. ENCRYPT ===
  const secrets = [
    { message: DECOY_MESSAGE, passphrase: DECOY_PASS },
    { message: HIDDEN_MESSAGE, passphrase: HIDDEN_PASS },
  ]
  const block = await encrypt(secrets, kdf)

  console.log('┌─ 2. PAYLOAD ──────────────────────────────────────────────┐')
  console.log('│  Type: Single encrypted block (salt + iv + headers + data)')
  console.log('│  Salt: ' + block.salt.toString('base64'))
  console.log('│  IV:   ' + block.iv.toString('base64'))
  console.log('│  Headers: ' + block.headers.toString('base64'))
  console.log('│  Data: ' + block.data.toString('base64'))
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 3. DECRYPT NORMAL ===
  const decoyResult = await decrypt(DECOY_PASS, block.salt, block.iv, block.headers, block.data, kdf)

  console.log('┌─ 3. DECRYPT (normal way - decoy passphrase) ──────────────┐')
  console.log('│  Passphrase: "' + DECOY_PASS + '"')
  console.log('│  Result: "' + decoyResult.toString() + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  // === 4. DECRYPT HIDDEN ===
  const hiddenResult = await decrypt(HIDDEN_PASS, block.salt, block.iv, block.headers, block.data, kdf)

  console.log('┌─ 4. DECRYPT (secret way - hidden passphrase) ─────────────┐')
  console.log('│  Passphrase: "' + HIDDEN_PASS + '"')
  console.log('│  Result: "' + hiddenResult.toString() + '"')
  console.log('└───────────────────────────────────────────────────────────┘\n')

  console.log('✓ Same payload, different passphrases → different messages')
  console.log('✓ Cannot tell how many secrets exist in the block')
}

main()
