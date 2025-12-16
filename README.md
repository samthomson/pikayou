# Plausible Deniability / False Bottom Encryption Demos

Exploring different approaches to deniable encryption in Node.js/TypeScript.

## Live Demo

🌐 **[pikayou.shakespeare.wtf](https://pikayou.shakespeare.wtf/)** - Web implementation (experimental)

## Quick Start

```bash
npm install
npm run demo:layered   # recommended for Nostr
```

## Approaches

| Demo | Command | How it works | One password forever? | Status |
|------|---------|--------------|----------------------|--------|
| **layered** ⭐ | `npm run demo:layered` | **🏆 WINNER!** NIP-44 outside, blockcrypt-style inside. Slot 0 = empty password (decoy), Slot 1 = secret password (hidden). | ✅ Yes | ✅ Works |
| **nostr-bc** | `npm run demo:nostr-bc` | Blockcrypt-style + NIP-44 conversation key. Slot 1 = NIP-44 key, Slot 2 = password. | ✅ Yes | ✅ Works |
| **blockcrypt** | `npm run demo:blockcrypt` | One block, multiple passphrases → different messages. Can't tell how many secrets exist. | ✅ Yes | ✅ Works |
| **concat** | `npm run demo:concat` | Hidden msg encrypted with shared password, appended to decoy as metadata. | ✅ Yes | ✅ Works |
| **stego** | `npm run demo:stego` | Hidden msg encoded as invisible zero-width Unicode chars inside decoy. | ✅ (no password) | ✅ Works |
| **deniable** | `npm run demo:deniable` | RSA-based. Two separate ciphertexts, two keypairs. | ➖ Keypairs | ✅ Works |
| **simple** | `npm run demo:simple` | XOR-based. One ciphertext, two keys → different messages. Educational. | ❌ Key per msg | ✅ Works |
| **nostr** | `npm run demo:nostr` | XOR-based with NIP-44. Secret = hidden XOR decoy, shared separately. | ❌ Secret per msg | ✅ Works |
| **false-bottom** | `npm run demo:false-bottom` | npm `false-bottom` library | - | ❌ Broken |

## Recommendation

### 🏆 Winner: `layered`

The **layered** approach is the best solution for Nostr:
- Clean separation: NIP-44 handles transport, blockcrypt-style handles deniability
- Empty password for decoy = no friction for normal use
- Secret password for hidden = plausible deniability
- Same password works for ALL messages
- Cannot tell how many slots are used

**For general (non-Nostr) use:** `blockcrypt`

**For understanding the concept:** `simple`

## How `layered` Works

```
┌─ NIP-44 (Nostr transport) ────────────────────────────────┐
│                                                           │
│  ┌─ Inner Block (blockcrypt-style) ────────────────────┐  │
│  │                                                     │  │
│  │  Slot 0: "" (empty pass) → "Meeting at 5pm"         │  │
│  │  Slot 1: "secret"        → "The treasure..."        │  │
│  │  Slot 2: [random padding]                           │  │
│  │  Slot 3: [random padding]                           │  │
│  │                                                     │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

1. NIP-44 encrypts the inner block (standard Nostr DM)
2. Anyone decrypting NIP-44 can use empty password → sees decoy
3. Only those with secret password → see hidden message
4. Can't tell how many slots are used (padding looks like real slots)

## How Plausible Deniability Works

1. You have two messages: **decoy** (safe to reveal) and **hidden** (secret)
2. You encrypt them together
3. If coerced: give up decoy password → they see decoy
4. Claim "that's all I have" - they can't prove otherwise

## Libraries Used

- [blockcrypt](https://www.npmjs.com/package/blockcrypt) - Best for true plausible deniability
- [deniable-encryption](https://www.npmjs.com/package/deniable-encryption) - RSA-based approach
- [@noble/secp256k1](https://www.npmjs.com/package/@noble/secp256k1) - For Nostr key operations
- [@noble/ciphers](https://www.npmjs.com/package/@noble/ciphers) - XChaCha20-Poly1305
- [@noble/hashes](https://www.npmjs.com/package/@noble/hashes) - HKDF, SHA256
