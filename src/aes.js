'use strict';
/**
 * AES-128 / AES-192 / AES-256 çekirdek + GCM (AEAD) modu.
 * Anahtar uzunluğu: 16 / 24 / 32 bayt.
 * NIST FIPS 197 ve SP 800-38D standardına uygundur.
 */

// ─────────────────────────────────────────────────────────────────────────────
// AES S-Box ve ters S-Box
// ─────────────────────────────────────────────────────────────────────────────
const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);

function subWord(w) {
  return ((SBOX[w >>> 24] << 24) | (SBOX[(w >> 16) & 0xff] << 16) |
          (SBOX[(w >> 8) & 0xff] << 8) | SBOX[w & 0xff]) >>> 0;
}
function rotWord(w) { return ((w << 8) | (w >>> 24)) >>> 0; }

// ─────────────────────────────────────────────────────────────────────────────
// AES anahtar genişletme (128 / 192 / 256 bit)
// ─────────────────────────────────────────────────────────────────────────────
const RCON = new Uint32Array([
  0x01000000, 0x02000000, 0x04000000, 0x08000000,
  0x10000000, 0x20000000, 0x40000000, 0x80000000,
  0x1b000000, 0x36000000,
]);

function aesExpandKey(keyBuf) {
  const Nk = keyBuf.length >>> 2;   // 4 / 6 / 8
  const Nr = Nk + 6;                // 10 / 12 / 14
  const rk = new Uint32Array(4 * (Nr + 1));

  for (let i = 0; i < Nk; i++) rk[i] = keyBuf.readUInt32BE(i * 4);

  for (let i = Nk; i < rk.length; i++) {
    let t = rk[i - 1];
    if (i % Nk === 0) {
      t = subWord(rotWord(t)) ^ RCON[i / Nk - 1];
    } else if (Nk > 6 && i % Nk === 4) {
      t = subWord(t);
    }
    rk[i] = (rk[i - Nk] ^ t) >>> 0;
  }
  return { rk, Nr };
}

// ─────────────────────────────────────────────────────────────────────────────
// GF(2^8) çarpma — MixColumns için
// ─────────────────────────────────────────────────────────────────────────────
function xt(x) { return ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff; }

function mc(a, b, c, d) {
  const x = xt(a) ^ xt(b) ^ b ^ c ^ d;
  const y = a ^ xt(b) ^ xt(c) ^ c ^ d;
  const z = a ^ b ^ xt(c) ^ xt(d) ^ d;
  const w = xt(a) ^ a ^ b ^ c ^ xt(d);
  return [x, y, z, w];
}

// ─────────────────────────────────────────────────────────────────────────────
// AES blok şifreleyici (şifreleme)
// ─────────────────────────────────────────────────────────────────────────────
function aesEncryptBlock(blk, ks) {
  const { rk, Nr } = ks;
  let s0 = blk.readUInt32BE(0) ^ rk[0];
  let s1 = blk.readUInt32BE(4) ^ rk[1];
  let s2 = blk.readUInt32BE(8) ^ rk[2];
  let s3 = blk.readUInt32BE(12) ^ rk[3];

  for (let r = 1; r < Nr; r++) {
    const a0 = (s0 >> 24) & 0xff, a1 = (s1 >> 24) & 0xff, a2 = (s2 >> 24) & 0xff, a3 = (s3 >> 24) & 0xff;
    const b0 = (s0 >> 16) & 0xff, b1 = (s1 >> 16) & 0xff, b2 = (s2 >> 16) & 0xff, b3 = (s3 >> 16) & 0xff;
    const c0 = (s0 >> 8) & 0xff,  c1 = (s1 >> 8) & 0xff,  c2 = (s2 >> 8) & 0xff,  c3 = (s3 >> 8) & 0xff;
    const d0 = s0 & 0xff,         d1 = s1 & 0xff,         d2 = s2 & 0xff,         d3 = s3 & 0xff;
    const [m00, m10, m20, m30] = mc(SBOX[a0], SBOX[b1], SBOX[c2], SBOX[d3]);
    const [m01, m11, m21, m31] = mc(SBOX[a1], SBOX[b2], SBOX[c3], SBOX[d0]);
    const [m02, m12, m22, m32] = mc(SBOX[a2], SBOX[b3], SBOX[c0], SBOX[d1]);
    const [m03, m13, m23, m33] = mc(SBOX[a3], SBOX[b0], SBOX[c1], SBOX[d2]);
    s0 = (((m00 << 24) | (m10 << 16) | (m20 << 8) | m30) ^ rk[r * 4]) >>> 0;
    s1 = (((m01 << 24) | (m11 << 16) | (m21 << 8) | m31) ^ rk[r * 4 + 1]) >>> 0;
    s2 = (((m02 << 24) | (m12 << 16) | (m22 << 8) | m32) ^ rk[r * 4 + 2]) >>> 0;
    s3 = (((m03 << 24) | (m13 << 16) | (m23 << 8) | m33) ^ rk[r * 4 + 3]) >>> 0;
  }

  // Son tur (MixColumns yok)
  const a0 = (s0 >> 24) & 0xff, a1 = (s1 >> 24) & 0xff, a2 = (s2 >> 24) & 0xff, a3 = (s3 >> 24) & 0xff;
  const b0 = (s0 >> 16) & 0xff, b1 = (s1 >> 16) & 0xff, b2 = (s2 >> 16) & 0xff, b3 = (s3 >> 16) & 0xff;
  const c0 = (s0 >> 8) & 0xff,  c1 = (s1 >> 8) & 0xff,  c2 = (s2 >> 8) & 0xff,  c3 = (s3 >> 8) & 0xff;
  const d0 = s0 & 0xff,         d1 = s1 & 0xff,         d2 = s2 & 0xff,         d3 = s3 & 0xff;
  const t0 = ((((SBOX[a0] << 24) | (SBOX[b1] << 16) | (SBOX[c2] << 8) | SBOX[d3]) >>> 0) ^ rk[Nr * 4]) >>> 0;
  const t1 = ((((SBOX[a1] << 24) | (SBOX[b2] << 16) | (SBOX[c3] << 8) | SBOX[d0]) >>> 0) ^ rk[Nr * 4 + 1]) >>> 0;
  const t2 = ((((SBOX[a2] << 24) | (SBOX[b3] << 16) | (SBOX[c0] << 8) | SBOX[d1]) >>> 0) ^ rk[Nr * 4 + 2]) >>> 0;
  const t3 = ((((SBOX[a3] << 24) | (SBOX[b0] << 16) | (SBOX[c1] << 8) | SBOX[d2]) >>> 0) ^ rk[Nr * 4 + 3]) >>> 0;

  const out = Buffer.alloc(16);
  out.writeUInt32BE(t0, 0); out.writeUInt32BE(t1, 4);
  out.writeUInt32BE(t2, 8); out.writeUInt32BE(t3, 12);
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// GCM — GHASH ve GCTR
// ─────────────────────────────────────────────────────────────────────────────
const GCM_R = 0xe1000000000000000000000000000000n;

function bufTo128(buf, off) {
  let v = 0n;
  for (let i = 0; i < 16; i++) v = (v << 8n) | BigInt(buf[off + i]);
  return v;
}
function big128ToBuf(v) {
  const b = Buffer.alloc(16);
  for (let i = 15; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}
function gf128Mul(X, Y) {
  let Z = 0n, V = X;
  for (let i = 127; i >= 0; i--) {
    if ((Y >> BigInt(i)) & 1n) Z ^= V;
    if (V & 1n) V = (V >> 1n) ^ GCM_R;
    else V >>= 1n;
  }
  return Z;
}
function ghash(H, data) {
  let Y = 0n;
  const hBig = bufTo128(H, 0);
  const paddedLen = data.length % 16 === 0 ? data.length : data.length + (16 - data.length % 16);
  const padded = Buffer.alloc(paddedLen);
  data.copy(padded);
  for (let i = 0; i < paddedLen; i += 16) {
    Y = gf128Mul(Y ^ bufTo128(padded, i), hBig);
  }
  return Y;
}

function _gctrStream(ks, J0, data) {
  const out = Buffer.alloc(data.length);
  let ctr = 2;
  for (let i = 0; i < data.length; i += 16) {
    const ctrBlk = Buffer.from(J0);
    ctrBlk.writeUInt32BE(ctr++, 12);
    const ks_block = aesEncryptBlock(ctrBlk, ks);
    const take = Math.min(16, data.length - i);
    for (let j = 0; j < take; j++) out[i + j] = data[i + j] ^ ks_block[j];
  }
  return out;
}

function _gcmTag(ks, J0, ct, aad) {
  const hBlock = Buffer.alloc(16);
  const H = aesEncryptBlock(hBlock, ks);
  const EJ0 = aesEncryptBlock(Buffer.from(J0), ks);

  // GHASH giriş: AAD (padded) || CT (padded) || len(AAD)||len(CT) (64+64 bit)
  const paddedAAD = Buffer.alloc(aad.length % 16 === 0 ? aad.length : aad.length + (16 - aad.length % 16));
  aad.copy(paddedAAD);
  const paddedCT = Buffer.alloc(ct.length % 16 === 0 ? ct.length : ct.length + (16 - ct.length % 16));
  ct.copy(paddedCT);
  const lenBlock = Buffer.alloc(16);
  lenBlock.writeBigUInt64BE(BigInt(aad.length) * 8n, 0);
  lenBlock.writeBigUInt64BE(BigInt(ct.length) * 8n, 8);

  const S = ghash(H, Buffer.concat([paddedAAD, paddedCT, lenBlock]));
  const sBuf = big128ToBuf(S);
  const tag = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) tag[i] = sBuf[i] ^ EJ0[i];
  return tag;
}

/**
 * AES-GCM şifreleyici.
 * @param {Buffer} key   16, 24 veya 32 bayt (AES-128/192/256)
 * @param {Buffer} iv    12 bayt nonce
 * @param {Buffer} pt    Açık metin
 * @param {Buffer} [aad] Kimliği doğrulanmış ek veri
 * @returns {{ ciphertext: Buffer, tag: Buffer }}
 */
function gcmEncrypt(key, iv, pt, aad = Buffer.alloc(0)) {
  if (![16, 24, 32].includes(key.length)) throw new Error('AES: anahtar 16/24/32 bayt olmalı');
  if (iv.length !== 12) throw new Error('GCM: IV 12 bayt olmalı');
  const ks = aesExpandKey(key);
  const J0 = Buffer.alloc(16); iv.copy(J0); J0.writeUInt32BE(1, 12);
  const ct = _gctrStream(ks, J0, pt);
  const tag = _gcmTag(ks, J0, ct, aad);
  return { ciphertext: ct, tag };
}

/**
 * AES-GCM çözücü — tag doğrulaması başarısız olursa hata fırlatır.
 * @param {Buffer} key
 * @param {Buffer} iv
 * @param {Buffer} ct   Şifreli metin
 * @param {Buffer} aad
 * @param {Buffer} tag  16 bayt kimlik doğrulama etiketi
 * @returns {Buffer} Açık metin
 */
function gcmDecrypt(key, iv, ct, aad, tag) {
  if (![16, 24, 32].includes(key.length)) throw new Error('AES: anahtar 16/24/32 bayt olmalı');
  if (iv.length !== 12) throw new Error('GCM: IV 12 bayt olmalı');
  const ks = aesExpandKey(key);
  const J0 = Buffer.alloc(16); iv.copy(J0); J0.writeUInt32BE(1, 12);
  const expTag = _gcmTag(ks, J0, ct, aad);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= expTag[i] ^ tag[i];
  if (diff !== 0) throw new Error('GCM: Kimlik doğrulama etiketi geçersiz');
  return _gctrStream(ks, J0, ct);
}

module.exports = { gcmEncrypt, gcmDecrypt, aesEncryptBlock, aesExpandKey };
