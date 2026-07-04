'use strict';
/**
 * HMAC-SHA256/384/512 ve HKDF (RFC 5869)
 */
const { sha256, sha384, sha512, hashByName } = require('./hash');

// Hash blok boyutları
const BLOCK_SIZE = { sha256: 64, sha384: 128, sha512: 128 };
const HASH_LEN   = { sha256: 32, sha384: 48,  sha512: 64  };

/**
 * HMAC hesaplar.
 * @param {'sha256'|'sha384'|'sha512'} alg
 * @param {Buffer} key
 * @param {Buffer} data
 */
function hmac(alg, key, data) {
  const blockSize = BLOCK_SIZE[alg];
  if (!blockSize) throw new Error(`Bilinmeyen HMAC algoritması: ${alg}`);

  if (key.length > blockSize) key = hashByName(alg, key);
  const padKey = Buffer.alloc(blockSize);
  key.copy(padKey);

  const ipad = Buffer.alloc(blockSize, 0x36);
  const opad = Buffer.alloc(blockSize, 0x5c);
  const innerKey = Buffer.allocUnsafe(blockSize);
  const outerKey = Buffer.allocUnsafe(blockSize);
  for (let i = 0; i < blockSize; i++) {
    innerKey[i] = padKey[i] ^ ipad[i];
    outerKey[i] = padKey[i] ^ opad[i];
  }
  const inner = hashByName(alg, Buffer.concat([innerKey, data]));
  return hashByName(alg, Buffer.concat([outerKey, inner]));
}

/** Kısa yol: hmac('sha256', ...) */
function hmac256(key, data) { return hmac('sha256', key, data); }
function hmac384(key, data) { return hmac('sha384', key, data); }
function hmac512(key, data) { return hmac('sha512', key, data); }

/**
 * HKDF-Extract (RFC 5869 §2.2)
 */
function hkdfExtract(alg, salt, ikm) {
  if (!salt || salt.length === 0) salt = Buffer.alloc(HASH_LEN[alg]);
  return hmac(alg, salt, ikm);
}

/**
 * HKDF-Expand (RFC 5869 §2.3)
 */
function hkdfExpand(alg, prk, info, len) {
  const hashLen = HASH_LEN[alg];
  if (len > 255 * hashLen) throw new Error('HKDF: çok uzun çıktı talep edildi');
  const out = Buffer.alloc(len);
  let prev = Buffer.alloc(0);
  let written = 0;
  for (let ctr = 1; written < len; ctr++) {
    prev = hmac(alg, prk, Buffer.concat([prev, info, Buffer.from([ctr])]));
    const take = Math.min(hashLen, len - written);
    prev.copy(out, written, 0, take);
    written += take;
  }
  return out;
}

/**
 * Tek adım HKDF.
 * @param {'sha256'|'sha384'|'sha512'} alg
 * @param {Buffer} ikm   Giriş anahtar materyali
 * @param {Buffer} salt  (isteğe bağlı)
 * @param {Buffer} info  Bağlam bilgisi
 * @param {number} len   Çıktı bayt sayısı
 */
function hkdf(alg, ikm, salt, info, len) {
  const prk = hkdfExtract(alg, salt || Buffer.alloc(0), ikm);
  return hkdfExpand(alg, prk, info || Buffer.alloc(0), len);
}

module.exports = { hmac, hmac256, hmac384, hmac512, hkdfExtract, hkdfExpand, hkdf };
