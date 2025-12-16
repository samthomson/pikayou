# Plausible Deniability / False Bottom Encryption Demos

Exploring different approaches to deniable encryption in Node.js/TypeScript.

## Quick Start

```bash
npm install
npm run demo:blockcrypt   # recommended
```

## Approaches

| Demo | Command | How it works | One password forever? | Status |
|------|---------|--------------|----------------------|--------|
| **nostr-bc** | `npm run demo:nostr-bc` | **Best for Nostr!** Blockcrypt-style + NIP-44. Slot 1 = NIP-44 key, Slot 2 = password. | ✅ Yes | ✅ Works |
| **blockcrypt** | `npm run demo:blockcrypt` | One block, multiple passphrases → different messages. Can't tell how many secrets exist. | ✅ Yes | ✅ Works |
| **concat** | `npm run demo:concat` | Hidden msg encrypted with shared password, appended to decoy. NIP-44 compatible. | ✅ Yes | ✅ Works |
| **stego** | `npm run demo:stego` | Hidden msg encoded as invisible zero-width Unicode chars inside decoy. NIP-44 compatible. | ✅ (no password needed) | ✅ Works |
| **deniable** | `npm run demo:deniable` | RSA-based. Two separate ciphertexts, two keypairs. Give up plausible keypair if coerced. | ➖ Keypairs | ✅ Works |
| **simple** | `npm run demo:simple` | XOR-based. One ciphertext, two keys → different messages. Educational. | ❌ Key per message | ✅ Works |
| **nostr** | `npm run demo:nostr` | XOR-based with NIP-44. Secret = hidden XOR decoy, shared separately. | ❌ Secret per message | ✅ Works |
| **false-bottom** | `npm run demo:false-bottom` | npm `false-bottom` library | - | ❌ Broken |

## Recommendation

**For Nostr:** `nostr-bc` (blockcrypt-style with NIP-44 compatibility)

**For general use:** `blockcrypt`

**For understanding the concept:** `simple`

## How Plausible Deniability Works

1. You have two messages: **decoy** (safe to reveal) and **hidden** (secret)
2. You encrypt them together
3. If coerced: give up decoy password → they see decoy
4. Claim "that's all I have" - they can't prove otherwise

## Libraries Used

- [blockcrypt](https://www.npmjs.com/package/blockcrypt) - Best for true plausible deniability
- [deniable-encryption](https://www.npmjs.com/package/deniable-encryption) - RSA-based approach
- [@noble/secp256k1](https://www.npmjs.com/package/@noble/secp256k1) - For Nostr key operations
- [@noble/ciphers](https://www.npmjs.com/package/@noble/ciphers) - XChaCha20-Poly1305 for NIP-44

