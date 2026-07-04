'use strict';
/**
 * RSA-2048 / RSA-3072 / RSA-4096
 * PKCS#1 v1.5 imza (sha256WithRSAEncryption / sha384 / sha512)
 * ve RSA-OAEP şifreleme (SHA-256 maskesi).
 */
const { modPow, modInverse, generatePrime } = require('./bigint');
const { sha256, sha384, sha512, hashByName } = require('./hash');

// DigestInfo DER önekleri — PKCS#1 v1.5 için (hash dahil değil, sadece prefix)
const PKCS1_DIGEST_INFO = {
  sha256: Buffer.from('3031300d060960864801650304020105000420', 'hex'),
  sha384: Buffer.from('3041300d060960864801650304020205000430', 'hex'),
  sha512: Buffer.from('3051300d060960864801650304020305000440', 'hex'),
};

// ─────────────────────────────────────────────────────────────────────────────
// Anahtar üretimi
// ─────────────────────────────────────────────────────────────────────────────
/**
 * RSA anahtar çifti üretir.
 * @param {2048|3072|4096} bits
 * @param {boolean} [verbose]
 * @returns {{ n, e, d, p, q, dp, dq, qInv, bits }}
 */
function generateRsaKeyPair(bits = 2048, verbose = false) {
  if (![2048, 3072, 4096].includes(bits))
    throw new Error('RSA: desteklenen bit uzunlukları 2048, 3072, 4096');
  const halfBits = bits >> 1;
  if (verbose) process.stdout.write(`[RSA] ${bits}-bit anahtar üretiliyor`);
  let p, q;
  while (true) {
    p = generatePrime(halfBits, verbose);
    q = generatePrime(halfBits, verbose);
    if (p !== q && (p > q ? p - q : q - p) > (1n << BigInt(halfBits - 100))) break;
  }
  if (p < q) [p, q] = [q, p]; // p > q
  const n = p * q;
  const e = 65537n;
  const phi = (p - 1n) * (q - 1n);
  const d = modInverse(e, phi);
  // CRT parametreleri
  const dp = d % (p - 1n);
  const dq = d % (q - 1n);
  const qInv = modInverse(q, p);
  if (verbose) console.log(' tamam');
  return { n, e, d, p, q, dp, dq, qInv, bits };
}

// ─────────────────────────────────────────────────────────────────────────────
// PKCS#1 v1.5 dolgusu
// ─────────────────────────────────────────────────────────────────────────────
function _pkcs1v15Pad(hashAlg, msgHash, emLen) {
  const prefix = PKCS1_DIGEST_INFO[hashAlg];
  if (!prefix) throw new Error(`PKCS#1: bilinmeyen hash: ${hashAlg}`);
  const T = Buffer.concat([prefix, msgHash]);
  const psLen = emLen - T.length - 3;
  if (psLen < 8) throw new Error('PKCS#1: modulus çok kısa');
  const PS = Buffer.alloc(psLen, 0xff);
  return Buffer.concat([Buffer.from([0x00, 0x01]), PS, Buffer.from([0x00]), T]);
}

function _bufToBigInt(buf) {
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  return v;
}

function _bigIntToBuf(v, len) {
  let hex = v.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex.padStart(len * 2, '0'), 'hex');
}

// ─────────────────────────────────────────────────────────────────────────────
// İmzalama ve doğrulama
// ─────────────────────────────────────────────────────────────────────────────
/**
 * RSA PKCS#1 v1.5 imzası.
 * @param {{ n, d }} key
 * @param {Buffer} data       İmzalanacak veri
 * @param {'sha256'|'sha384'|'sha512'} [hashAlg]
 */
function rsaSign(key, data, hashAlg = 'sha256') {
  const mHash = hashByName(hashAlg, data);
  const emLen = Math.ceil((key.n.toString(2).length) / 8);
  const em = _pkcs1v15Pad(hashAlg, mHash, emLen);
  const m = _bufToBigInt(em);
  const sig = modPow(m, key.d, key.n);
  return _bigIntToBuf(sig, emLen);
}

/**
 * RSA PKCS#1 v1.5 doğrulama.
 * @param {{ n, e }} key
 * @param {Buffer} data
 * @param {Buffer} signature
 * @param {'sha256'|'sha384'|'sha512'} [hashAlg]
 */
function rsaVerify(key, data, signature, hashAlg = 'sha256') {
  const mHash = hashByName(hashAlg, data);
  const emLen = Math.ceil((key.n.toString(2).length) / 8);
  const sigInt = _bufToBigInt(signature);
  const emInt = modPow(sigInt, key.e, key.n);
  const em = _bigIntToBuf(emInt, emLen);
  const expected = _pkcs1v15Pad(hashAlg, mHash, emLen);
  if (em.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < em.length; i++) diff |= em[i] ^ expected[i];
  return diff === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// RSA-OAEP şifreleme (SHA-256 MGF)
// ─────────────────────────────────────────────────────────────────────────────
const { randomBytes } = require('./random');

function _mgf1(seed, len) {
  const out = Buffer.alloc(len);
  let written = 0;
  for (let ctr = 0; written < len; ctr++) {
    const ctrBuf = Buffer.alloc(4);
    ctrBuf.writeUInt32BE(ctr, 0);
    const hash = sha256(Buffer.concat([seed, ctrBuf]));
    const take = Math.min(32, len - written);
    hash.copy(out, written, 0, take);
    written += take;
  }
  return out;
}

/**
 * RSA-OAEP şifreleyici (SHA-256).
 * @param {{ n, e }} pubKey
 * @param {Buffer} data
 * @param {Buffer} [label]
 */
function rsaOaepEncrypt(pubKey, data, label = Buffer.alloc(0)) {
  const mLen = data.length;
  const hLen = 32; // SHA-256
  const emLen = Math.ceil((pubKey.n.toString(2).length) / 8);
  if (mLen > emLen - 2 * hLen - 2) throw new Error('OAEP: mesaj çok uzun');
  const lHash = sha256(label);
  const DB = Buffer.alloc(emLen - hLen - 1);
  lHash.copy(DB, 0);
  DB[emLen - hLen - mLen - 2] = 0x01;
  data.copy(DB, emLen - hLen - mLen - 1);
  const seed = randomBytes(hLen);
  const dbMask = _mgf1(seed, DB.length);
  const maskedDB = Buffer.allocUnsafe(DB.length);
  for (let i = 0; i < DB.length; i++) maskedDB[i] = DB[i] ^ dbMask[i];
  const seedMask = _mgf1(maskedDB, hLen);
  const maskedSeed = Buffer.allocUnsafe(hLen);
  for (let i = 0; i < hLen; i++) maskedSeed[i] = seed[i] ^ seedMask[i];
  const EM = Buffer.concat([Buffer.from([0x00]), maskedSeed, maskedDB]);
  const m = _bufToBigInt(EM);
  const c = modPow(m, pubKey.e, pubKey.n);
  return _bigIntToBuf(c, emLen);
}

/**
 * RSA-OAEP çözücü (SHA-256).
 * @param {{ n, d }} privKey
 * @param {Buffer} ciphertext
 * @param {Buffer} [label]
 */
function rsaOaepDecrypt(privKey, ciphertext, label = Buffer.alloc(0)) {
  const hLen = 32;
  const emLen = Math.ceil((privKey.n.toString(2).length) / 8);
  const c = _bufToBigInt(ciphertext);
  const m = modPow(c, privKey.d, privKey.n);
  const EM = _bigIntToBuf(m, emLen);
  if (EM[0] !== 0x00) throw new Error('OAEP: çözme başarısız');
  const lHash = sha256(label);
  const maskedSeed = EM.subarray(1, 1 + hLen);
  const maskedDB = EM.subarray(1 + hLen);
  const seedMask = _mgf1(maskedDB, hLen);
  const seed = Buffer.allocUnsafe(hLen);
  for (let i = 0; i < hLen; i++) seed[i] = maskedSeed[i] ^ seedMask[i];
  const dbMask = _mgf1(seed, maskedDB.length);
  const DB = Buffer.allocUnsafe(maskedDB.length);
  for (let i = 0; i < maskedDB.length; i++) DB[i] = maskedDB[i] ^ dbMask[i];
  // lHash kontrolü
  let diff = 0;
  for (let i = 0; i < hLen; i++) diff |= DB[i] ^ lHash[i];
  // 0x01 ayırıcı bul
  let sepIdx = hLen;
  while (sepIdx < DB.length && DB[sepIdx] === 0x00) sepIdx++;
  if (sepIdx >= DB.length || DB[sepIdx] !== 0x01 || diff !== 0)
    throw new Error('OAEP: çözme başarısız');
  return DB.subarray(sepIdx + 1);
}

module.exports = {
  generateRsaKeyPair, rsaSign, rsaVerify,
  rsaOaepEncrypt, rsaOaepDecrypt,
  _bufToBigInt, _bigIntToBuf,
};
