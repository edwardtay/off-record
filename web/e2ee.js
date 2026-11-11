/* NEAR AI Cloud end-to-end encryption, version 2 (docs.near.ai/cloud/guides/e2ee-chat-completions).
   Each message is encrypted in the browser to the model's Ed25519 key, the key the TDX quote binds
   in report_data, so NEAR AI's gateway only ever relays ciphertext. Replies come back encrypted to a
   one-time client key that never leaves this page.

   Wire format of an encrypted field, hex: ephemeral X25519 public key (32) | nonce (24) | ciphertext + tag.
   Key: HKDF-SHA256(X25519(ephemeral, model key as X25519), no salt, info "ed25519_encryption", 32 bytes).
   Cipher: XChaCha20-Poly1305. */
import { ed25519, x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv, hkdf, sha256, xchacha20poly1305, randomBytes } from './vendor/noble.js?v=11';

const INFO = new TextEncoder().encode('ed25519_encryption');
const toHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(String(h).replace(/^0x/, '').match(/../g) || [], (x) => parseInt(x, 16));
const derive = (shared) => hkdf(sha256, shared, undefined, INFO, 32);

/** A one-time client key pair for this run. Only the public half is sent. */
export function newClientKeys() {
  const seed = randomBytes(32);
  return { publicHex: toHex(ed25519.getPublicKey(seed)), x25519Secret: toHex(edwardsToMontgomeryPriv(seed)) };
}

/** Encrypt one string to the model's Ed25519 public key (hex). Returns the field and its one-time secret. */
export function encryptTo(modelPubHex, text) {
  const eph = randomBytes(32);
  const key = derive(x25519.getSharedSecret(eph, edwardsToMontgomeryPub(fromHex(modelPubHex))));
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(new TextEncoder().encode(text));
  return { hex: toHex(new Uint8Array([...x25519.getPublicKey(eph), ...nonce, ...ct])), opening: toHex(eph) };
}

/**
 * Open a request field with its one-time secret (kept in the receipt). Succeeds only if the field
 * was encrypted to `modelPubHex`: the AEAD tag fails for any other key, and the ephemeral public
 * key in the field must belong to the opening.
 */
export function openRequestField(modelPubHex, openingHex, hex) {
  const b = fromHex(hex);
  const eph = fromHex(openingHex);
  if (toHex(x25519.getPublicKey(eph)) !== toHex(b.slice(0, 32))) throw new Error('opening does not match the field');
  const key = derive(x25519.getSharedSecret(eph, edwardsToMontgomeryPub(fromHex(modelPubHex))));
  return new TextDecoder().decode(xchacha20poly1305(key, b.slice(32, 56)).decrypt(b.slice(56)));
}

/** Decrypt one field the model encrypted to our client key. */
export function decryptWith(x25519SecretHex, hex) {
  const b = fromHex(hex);
  if (b.length < 32 + 24 + 16) throw new Error('encrypted field too short');
  const key = derive(x25519.getSharedSecret(fromHex(x25519SecretHex), b.slice(0, 32)));
  return new TextDecoder().decode(xchacha20poly1305(key, b.slice(32, 56)).decrypt(b.slice(56)));
}

/** Ed25519 signature check over the signed text, with the signer's public key as the address. */
export function verifyEd25519(text, sigHex, pubHex) {
  try { return ed25519.verify(fromHex(sigHex), new TextEncoder().encode(text), fromHex(pubHex)); } catch { return false; }
}

export const isHexCipher = (s) => typeof s === 'string' && s.length >= 2 * (32 + 24 + 16) && /^[0-9a-f]+$/i.test(s);
