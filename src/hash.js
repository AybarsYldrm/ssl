'use strict';
/**
 * SHA-1, SHA-256, SHA-384, SHA-512 saf JavaScript uygulamaları.
 * NIST FIPS 180-4 standardına uygundur.
 *
 * NOT (SHA-1): Yeni imzalar için KULLANILMAMALIDIR (kriptografik olarak
 * kırılmıştır). Burada SADECE RFC 6960 (OCSP) uyumluluğu için bulunur:
 * OCSP ResponderID.byKey (KeyHash) alanı protokol tarafından SABİT SHA-1
 * olarak tanımlanmıştır ve hashAlgorithm seçimine bağlı değildir. Bu
 * kütüphanede SHA-1, imza/sertifika üretiminde ASLA kullanılmaz.
 */

// ─────────────────────────────────────────────────────────────────────────────
// SHA-1 (RFC 3174) — SADECE OCSP ResponderID/KeyHash uyumluluğu için
// ─────────────────────────────────────────────────────────────────────────────
function sha1(input) {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  const bitLen = buf.length * 8;
  const padLen = (buf.length % 64 < 56) ? (56 - buf.length % 64) : (120 - buf.length % 64);
  const padded = Buffer.alloc(buf.length + padLen + 8);
  buf.copy(padded);
  padded[buf.length] = 0x80;
  padded.writeUInt32BE(Math.floor(bitLen / 0x100000000), padded.length - 8);
  padded.writeUInt32BE(bitLen >>> 0, padded.length - 4);

  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const W = new Uint32Array(80);
  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = padded.readUInt32BE(off + i * 4);
    for (let i = 16; i < 80; i++) {
      W[i] = rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    }
    let [a, b, c, d, e] = [h0, h1, h2, h3, h4];
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20)      { f = (b & c) | (~b & d);        k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d;                 k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else             { f = b ^ c ^ d;                 k = 0xca62c1d6; }
      const temp = (rotl(a, 5) + f + e + k + W[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  const out = Buffer.alloc(20);
  out.writeUInt32BE(h0, 0); out.writeUInt32BE(h1, 4); out.writeUInt32BE(h2, 8);
  out.writeUInt32BE(h3, 12); out.writeUInt32BE(h4, 16);
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256
// ─────────────────────────────────────────────────────────────────────────────
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const SHA256_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

function sha256(input) {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  const bitLen = buf.length * 8;
  const padLen = (buf.length % 64 < 56) ? (56 - buf.length % 64) : (120 - buf.length % 64);
  const padded = Buffer.alloc(buf.length + padLen + 8);
  buf.copy(padded);
  padded[buf.length] = 0x80;
  padded.writeUInt32BE(Math.floor(bitLen / 0x100000000), padded.length - 8);
  padded.writeUInt32BE(bitLen >>> 0, padded.length - 4);

  const H = new Uint32Array(SHA256_IV);
  const W = new Uint32Array(64);
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = padded.readUInt32BE(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) out.writeUInt32BE(H[i], i * 4);
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-512 / SHA-384 (64-bit kelimeler — BigInt tabanlı)
// ─────────────────────────────────────────────────────────────────────────────
const M64 = 0xffffffffffffffffn;

const SHA512_K = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

const SHA512_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SHA384_IV = [
  0xcbbb9d5dc1059ed8n, 0x629a292a367cd507n, 0x9159015a3070dd17n, 0x152fecd8f70e5939n,
  0x67332667ffc00b31n, 0x8eb44a8768581511n, 0xdb0c2e0d64f98fa7n, 0x47b5481dbefa4fa4n,
];

function rotr64b(x, n) { return ((x >> n) | (x << (64n - n))) & M64; }

function _sha512core(buf, IV, outBytes) {
  if (typeof buf === 'string') buf = Buffer.from(buf, 'utf8');
  // Dolgu: 1024-bit (128 bayt) bloklar
  const byteLen = buf.length;
  // Ekleme: 0x80, sonra sıfırlar, sonra 128-bit uzunluk
  const blockLen = 128;
  const padLen = ((byteLen + 16) % blockLen <= 15)
    ? (blockLen - 1 - ((byteLen + 16) % blockLen) + 16)
    : (blockLen - 1 - ((byteLen + 16) % blockLen) + 16);
  // Daha açık: padded length = smallest N where N ≡ 112 (mod 128) and N >= byteLen+1
  const paddedLen = byteLen + 1 + (((112 - byteLen - 1) % 128 + 128) % 128) + 16;
  const padded = Buffer.alloc(paddedLen);
  buf.copy(padded);
  padded[byteLen] = 0x80;
  // 128-bit uzunluk: bitCount = byteLen * 8
  // Yüksek 64-bit sıfır (pratik mesaj boyutu için)
  const bitCount = BigInt(byteLen) * 8n;
  padded.writeBigUInt64BE(0n, paddedLen - 16);
  padded.writeBigUInt64BE(bitCount, paddedLen - 8);

  let H = [...IV];
  const W = new Array(80);

  for (let off = 0; off < paddedLen; off += 128) {
    // Mesaj takvimi
    for (let i = 0; i < 16; i++) {
      W[i] = padded.readBigUInt64BE(off + i * 8);
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64b(W[i - 15], 1n) ^ rotr64b(W[i - 15], 8n) ^ (W[i - 15] >> 7n);
      const s1 = rotr64b(W[i - 2], 19n) ^ rotr64b(W[i - 2], 61n) ^ (W[i - 2] >> 6n);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & M64;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr64b(e, 14n) ^ rotr64b(e, 18n) ^ rotr64b(e, 41n);
      const ch = (e & f) ^ (~e & g & M64);
      const T1 = (h + S1 + ch + SHA512_K[i] + W[i]) & M64;
      const S0 = rotr64b(a, 28n) ^ rotr64b(a, 34n) ^ rotr64b(a, 39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const T2 = (S0 + maj) & M64;
      h = g; g = f; f = e; e = (d + T1) & M64;
      d = c; c = b; b = a; a = (T1 + T2) & M64;
    }
    H[0] = (H[0] + a) & M64; H[1] = (H[1] + b) & M64;
    H[2] = (H[2] + c) & M64; H[3] = (H[3] + d) & M64;
    H[4] = (H[4] + e) & M64; H[5] = (H[5] + f) & M64;
    H[6] = (H[6] + g) & M64; H[7] = (H[7] + h) & M64;
  }

  const out = Buffer.alloc(outBytes);
  for (let i = 0; i < Math.ceil(outBytes / 8); i++) {
    const v = H[i];
    const start = i * 8;
    const take = Math.min(8, outBytes - start);
    for (let j = 0; j < take; j++) {
      out[start + j] = Number((v >> BigInt(56 - j * 8)) & 0xffn);
    }
  }
  return out;
}

function sha384(input) {
  return _sha512core(input, SHA384_IV, 48);
}

function sha512(input) {
  return _sha512core(input, SHA512_IV, 64);
}

/**
 * Algoritma adına göre hash fonksiyonu seçer.
 * @param {'sha256'|'sha384'|'sha512'} alg
 */
function hashByName(alg, data) {
  if (alg === 'sha1')   return sha1(data);
  if (alg === 'sha256') return sha256(data);
  if (alg === 'sha384') return sha384(data);
  if (alg === 'sha512') return sha512(data);
  throw new Error(`Bilinmeyen hash algoritması: ${alg}`);
}

module.exports = { sha1, sha256, sha384, sha512, hashByName };