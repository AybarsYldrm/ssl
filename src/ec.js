'use strict';
/**
 * Eliptik Eğri Kriptografisi
 *   - P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1)
 *   - ECDSA imzalama / doğrulama (RFC 6979 deterministik k)
 *   - ECDH anahtar değişimi
 *   - X25519 (Curve25519 ECDHE)
 *
 * Jacobian projektif koordinatlar kullanılır.
 * Tüm eğrilerde a = p − 3 (CMO hızlandırmalı katlama).
 */
const { modPow, modInverse } = require('./bigint');
const { randomBigIntRange } = require('./random');
const { hashByName } = require('./hash');
const { hmac } = require('./hmac');

// ─────────────────────────────────────────────────────────────────────────────
// Eğri parametreleri (NIST / SEC 2)
// ─────────────────────────────────────────────────────────────────────────────
const CURVES = {
  'P-256': {
    p:  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    a:  0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
    b:  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
    n:  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    h: 1n, byteLen: 32, hashAlg: 'sha256',
    oidCurve: '2a8648ce3d030107',
    oidSig:   '2a8648ce3d040302',
  },
  'P-384': {
    p:  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
    a:  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffcn,
    b:  0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
    Gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
    Gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
    n:  0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
    h: 1n, byteLen: 48, hashAlg: 'sha384',
    oidCurve: '2b81040022',
    oidSig:   '2a8648ce3d040303',
  },
  'P-521': {
    p:  (1n << 521n) - 1n,
    a:  (1n << 521n) - 4n,
    b:  0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
    Gx: 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
    Gy: 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
    n:  0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
    h: 1n, byteLen: 66, hashAlg: 'sha512',
    oidCurve: '2b81040023',
    oidSig:   '2a8648ce3d040304',
  },
};

function getCurve(name) {
  const c = CURVES[name];
  if (!c) throw new Error(`Bilinmeyen eğri: ${name}. Desteklenenler: P-256, P-384, P-521`);
  return c;
}

// ─────────────────────────────────────────────────────────────────────────────
// Alan aritmetiği
// ─────────────────────────────────────────────────────────────────────────────
function modP(p) { return v => ((v % p) + p) % p; }

// ─────────────────────────────────────────────────────────────────────────────
// Jacobian projektif nokta aritmetiği
// (X, Y, Z) → affine (X/Z², Y/Z³)
// Sonsuz nokta: Z === 0n
// ─────────────────────────────────────────────────────────────────────────────

function isInfinity(P) { return P === null || P.Z === 0n; }

function _affine(P, curve) {
  if (isInfinity(P)) return null;
  const { p } = curve;
  const m = modP(p);
  const zinv  = modInverse(P.Z, p);
  const zinv2 = m(zinv * zinv);
  const zinv3 = m(zinv2 * zinv);
  return { x: m(P.X * zinv2), y: m(P.Y * zinv3) };
}

/** Noktayı Jacobian'a çevir (affine → Jacobian) */
function _toJac(pt) {
  if (pt === null) return null;
  return { X: pt.x, Y: pt.y, Z: 1n };
}

/**
 * Jacobian çift (a=p-3 için CMO formülü)
 */
function _double(P, curve) {
  if (isInfinity(P) || P.Y === 0n) return null;
  const { p } = curve;
  const m = modP(p);
  const { X, Y, Z } = P;

  const delta = m(Z * Z);
  const gamma = m(Y * Y);
  const beta  = m(X * gamma);
  const alpha = m(3n * m((X - delta) * (X + delta)));   // a = -3 optimizasyonu
  const X3    = m(m(alpha * alpha) - 8n * beta);
  const Z3    = m(m((Y + Z) * (Y + Z)) - gamma - delta);
  const Y3    = m(m(alpha * (4n * beta - X3)) - 8n * m(gamma * gamma));
  return { X: X3, Y: Y3, Z: Z3 };
}

/**
 * Jacobian toplama: P1 (Jacobian) + P2 (affine → Jacobian)
 * Hem genel hem karma (Z2=1) durumları kapsanır.
 */
function _addMixed(P1, P2, curve) {
  if (isInfinity(P1)) return P2 ? _toJac(P2) : null;
  if (!P2)            return P1;

  const { p } = curve;
  const m = modP(p);
  const { X: X1, Y: Y1, Z: Z1 } = P1;
  const { x: X2, y: Y2 } = P2;

  const Z1Z1 = m(Z1 * Z1);
  const U2   = m(X2 * Z1Z1);
  const S2   = m(m(Y2 * Z1) * Z1Z1);
  const H    = m(U2 - X1);
  const R    = m(S2 - Y1);

  if (H === 0n) {
    if (R === 0n) return _double(_toJac(P2) /* = P1 in affine */, curve);
    return null; // sonsuz
  }

  const HH   = m(H * H);
  const I    = m(4n * HH);
  const J    = m(H * I);
  const r    = m(2n * R);
  const V    = m(X1 * I);
  const X3   = m(m(r * r) - J - 2n * V);
  const Y3   = m(m(r * (V - X3)) - 2n * m(Y1 * J));
  const Z3   = m(m((Z1 + H) * (Z1 + H)) - Z1Z1 - HH);
  return { X: X3, Y: Y3, Z: Z3 };
}

/** Skaler çarpım: k * G (veya k * P) — double-and-add */
function _scalarMul(k, G, curve) {
  let R = null;
  let Q = _toJac(G);
  const bits = k.toString(2);
  for (let i = 0; i < bits.length; i++) {
    R = _double(R, curve);
    if (bits[i] === '1') R = _addMixed(R, _affine(Q, curve) || G, curve);
  }
  return R;
}

// ─────────────────────────────────────────────────────────────────────────────
// Noktayı seri hale getir / çözümle
// ─────────────────────────────────────────────────────────────────────────────
function _pointToUncompressed(pt, byteLen) {
  const buf = Buffer.alloc(1 + byteLen * 2);
  buf[0] = 0x04;
  let x = pt.x, y = pt.y;
  for (let i = byteLen - 1; i >= 0; i--) {
    buf[1 + i]          = Number(x & 0xffn); x >>= 8n;
    buf[1 + byteLen + i] = Number(y & 0xffn); y >>= 8n;
  }
  return buf;
}

function _uncompressedToPoint(buf, byteLen) {
  if (buf[0] !== 0x04 || buf.length !== 1 + byteLen * 2)
    throw new Error('EC: geçersiz sıkıştırılmamış nokta formatı');
  let x = 0n, y = 0n;
  for (let i = 0; i < byteLen; i++) {
    x = (x << 8n) | BigInt(buf[1 + i]);
    y = (y << 8n) | BigInt(buf[1 + byteLen + i]);
  }
  return { x, y };
}

function _bigIntToFixedBuf(v, len) {
  let hex = v.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const pad = len * 2;
  hex = hex.padStart(pad, '0').slice(-pad);
  return Buffer.from(hex, 'hex');
}

function _bufToBigInt(buf) {
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC 6979 — Deterministik k üretimi
// ─────────────────────────────────────────────────────────────────────────────
function _rfc6979k(curve, privKey, msgHash) {
  const { n, byteLen, hashAlg } = curve;
  const qLen = byteLen;
  const hLen = msgHash.length;

  // bits2int: hash'i tamsayıya çevir (n'den büyükse sağa kaydır)
  function bits2int(h) {
    let v = _bufToBigInt(h);
    const nBits = n.toString(2).length;
    const hBits = h.length * 8;
    if (hBits > nBits) v >>= BigInt(hBits - nBits);
    return v;
  }

  // int2octets: tamsayıyı qLen bayta dönüştür
  function int2octets(x) { return _bigIntToFixedBuf(x, qLen); }

  // bits2octets: hash → tamsayı → mod n → qLen bayt
  function bits2octets(h) {
    let z1 = bits2int(h);
    let z2 = ((z1 % n) + n) % n;
    return int2octets(z2);
  }

  const x = int2octets(privKey);
  const h1 = bits2octets(msgHash);
  const extra = Buffer.concat([x, h1]);

  let V = Buffer.alloc(qLen > hLen ? qLen : hLen, 0x01);
  let K = Buffer.alloc(V.length, 0x00);

  K = hmac(hashAlg, K, Buffer.concat([V, Buffer.from([0x00]), extra]));
  V = hmac(hashAlg, K, V);
  K = hmac(hashAlg, K, Buffer.concat([V, Buffer.from([0x01]), extra]));
  V = hmac(hashAlg, K, V);

  for (let attempt = 0; attempt < 1000; attempt++) {
    let T = Buffer.alloc(0);
    while (T.length < qLen) {
      V = hmac(hashAlg, K, V);
      T = Buffer.concat([T, V]);
    }
    const k = bits2int(T.subarray(0, qLen));
    if (k >= 1n && k < n) return k;
    K = hmac(hashAlg, K, Buffer.concat([V, Buffer.from([0x00])]));
    V = hmac(hashAlg, K, V);
  }
  throw new Error('RFC 6979: k üretilemedi');
}

// ─────────────────────────────────────────────────────────────────────────────
// ECDSA
// ─────────────────────────────────────────────────────────────────────────────

/**
 * EC anahtar çifti üretir.
 * @param {'P-256'|'P-384'|'P-521'} curveName
 * @returns {{ curve, privateKey: bigint, publicKey: {x,y}, publicKeyBuf: Buffer }}
 */
function generateEcKeyPair(curveName = 'P-256') {
  const curve = getCurve(curveName);
  const { n, Gx, Gy, byteLen } = curve;
  const G = { x: Gx, y: Gy };
  const privKey = randomBigIntRange(1n, n - 1n);
  const pubJac  = _scalarMul(privKey, G, curve);
  const pub     = _affine(pubJac, curve);
  return {
    curve: curveName,
    privateKey:    privKey,
    publicKey:     pub,
    publicKeyBuf:  _pointToUncompressed(pub, byteLen),
  };
}

/**
 * ECDSA imzası — DER kodlu SEQUENCE { INTEGER r, INTEGER s } döner.
 * k, RFC 6979'a göre deterministik üretilir.
 * @param {'P-256'|'P-384'|'P-521'} curveName
 * @param {bigint} privateKey
 * @param {Buffer} message
 * @param {string} [hashAlg]  Varsayılan: eğrinin hashAlg alanı
 */
function ecdsaSign(curveName, privateKey, message, hashAlg) {
  const curve = getCurve(curveName);
  const { n, Gx, Gy } = curve;
  const G = { x: Gx, y: Gy };
  const alg = hashAlg || curve.hashAlg;
  const mHash = hashByName(alg, message);

  // Hash'i tamsayıya çevir (n bit uzunluğuna göre kırp)
  const nBits  = n.toString(2).length;
  let z = _bufToBigInt(mHash);
  if (mHash.length * 8 > nBits) z >>= BigInt(mHash.length * 8 - nBits);
  z = z % n;

  const k = _rfc6979k(curve, privateKey, mHash);
  const R_jac = _scalarMul(k, G, curve);
  const R_aff = _affine(R_jac, curve);
  if (!R_aff) throw new Error('ECDSA: R noktası sonsuz');

  const r = R_aff.x % n;
  if (r === 0n) throw new Error('ECDSA: r=0, yeniden dene');
  const kInv = modInverse(k, n);
  const s = kInv * (z + r * privateKey) % n;
  if (s === 0n) throw new Error('ECDSA: s=0, yeniden dene');

  // DER kodlama: SEQUENCE { INTEGER r, INTEGER s }
  return _encodeEcdsaDer(r, s);
}

/**
 * ECDSA imzası doğrulama.
 * @param {'P-256'|'P-384'|'P-521'} curveName
 * @param {{ x: bigint, y: bigint }|Buffer} publicKey
 * @param {Buffer} message
 * @param {Buffer} derSig  DER kodlu imza
 * @param {string} [hashAlg]
 */
function ecdsaVerify(curveName, publicKey, message, derSig, hashAlg) {
  const curve = getCurve(curveName);
  const { n, Gx, Gy, byteLen } = curve;
  const G = { x: Gx, y: Gy };
  const alg = hashAlg || curve.hashAlg;

  const { r, s } = _decodeEcdsaDer(derSig);
  if (r < 1n || r >= n || s < 1n || s >= n) return false;

  const pub = Buffer.isBuffer(publicKey)
    ? _uncompressedToPoint(publicKey, byteLen)
    : publicKey;

  const mHash = hashByName(alg, message);
  const nBits = n.toString(2).length;
  let z = _bufToBigInt(mHash);
  if (mHash.length * 8 > nBits) z >>= BigInt(mHash.length * 8 - nBits);
  z = z % n;

  const sInv = modInverse(s, n);
  const u1 = z * sInv % n;
  const u2 = r * sInv % n;

  const R1 = _scalarMul(u1, G, curve);
  const R2 = _scalarMul(u2, pub, curve);

  // R1 + R2 (her ikisi de Jacobian)
  const R1a = _affine(R1, curve);
  const R2a = _affine(R2, curve);
  if (!R1a || !R2a) return false;

  // Genel toplama
  const R1j = _toJac(R1a);
  const Rj  = _addMixed(R1j, R2a, curve);
  const Ra  = _affine(Rj, curve);
  if (!Ra) return false;

  return Ra.x % n === r;
}

/**
 * ECDH paylaşılan sır hesabı.
 * @param {'P-256'|'P-384'|'P-521'} curveName
 * @param {bigint} privateKey
 * @param {{ x, y }|Buffer} peerPublicKey
 * @returns {Buffer} Paylaşılan sır (x koordinatı)
 */
function ecdhCompute(curveName, privateKey, peerPublicKey) {
  const curve = getCurve(curveName);
  const { byteLen } = curve;
  const pub = Buffer.isBuffer(peerPublicKey)
    ? _uncompressedToPoint(peerPublicKey, byteLen)
    : peerPublicKey;
  const shared = _scalarMul(privateKey, pub, curve);
  const aff    = _affine(shared, curve);
  if (!aff) throw new Error('ECDH: paylaşılan nokta sonsuz');
  return _bigIntToFixedBuf(aff.x, byteLen);
}

// ─────────────────────────────────────────────────────────────────────────────
// DER imza kodlama / çözümleme
// ─────────────────────────────────────────────────────────────────────────────
function _encIntDer(v) {
  let h = v.toString(16);
  if (h.length % 2) h = '0' + h;
  let b = Buffer.from(h, 'hex');
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
  const lenBuf = Buffer.alloc(b.length < 0x80 ? 1 : 2);
  if (b.length < 0x80) lenBuf[0] = b.length;
  else { lenBuf[0] = 0x81; lenBuf[1] = b.length; }
  return Buffer.concat([Buffer.from([0x02]), lenBuf, b]);
}

function _encodeEcdsaDer(r, s) {
  const rBuf = _encIntDer(r);
  const sBuf = _encIntDer(s);
  const inner = Buffer.concat([rBuf, sBuf]);
  const lenBuf = inner.length < 0x80
    ? Buffer.from([inner.length])
    : Buffer.from([0x81, inner.length]);
  return Buffer.concat([Buffer.from([0x30]), lenBuf, inner]);
}

function _readDerInt(buf, off) {
  if (buf[off] !== 0x02) throw new Error('DER: INTEGER beklendi');
  off++;
  let len = buf[off++];
  if (len & 0x80) {
    const ll = len & 0x7f;
    len = 0;
    for (let i = 0; i < ll; i++) len = (len << 8) | buf[off++];
  }
  const raw = buf.subarray(off, off + len);
  let v = 0n;
  for (const b of raw) v = (v << 8n) | BigInt(b);
  return { v, nextOff: off + len };
}

function _decodeEcdsaDer(buf) {
  if (buf[0] !== 0x30) throw new Error('DER: SEQUENCE beklendi');
  let off = 1;
  let len = buf[off++];
  if (len & 0x80) { const ll = len & 0x7f; len = 0; for (let i = 0; i < ll; i++) len = (len << 8) | buf[off++]; }
  const { v: r, nextOff } = _readDerInt(buf, off);
  const { v: s }          = _readDerInt(buf, nextOff);
  return { r, s };
}

// ─────────────────────────────────────────────────────────────────────────────
// X25519 — Curve25519 ECDHE (RFC 7748)
// ─────────────────────────────────────────────────────────────────────────────
const X25519_P   = (1n << 255n) - 19n;
const X25519_A24 = 121665n;
const X25519_BASE = Buffer.alloc(32); X25519_BASE[0] = 9;

function _x25519Clamp(kBuf) {
  const b = Buffer.from(kBuf);
  b[0]  &= 248; b[31] &= 127; b[31] |= 64;
  return b;
}

function _x25519(scalarBuf, uBuf) {
  const P   = X25519_P;
  const mod = v => ((v % P) + P) % P;
  const k   = _x25519Clamp(scalarBuf);
  let kn = 0n, u = 0n;
  for (let i = 31; i >= 0; i--) { kn = (kn << 8n) | BigInt(k[i]); u = (u << 8n) | BigInt(uBuf[i]); }

  let [x1, x2, z2, x3, z3, swap] = [u, 1n, 0n, u, 1n, 0n];
  for (let t = 254n; t >= 0n; t--) {
    const kt = (kn >> t) & 1n;
    if (kt ^ swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    swap = kt;
    const A  = mod(x2 + z2), AA = mod(A * A);
    const B  = mod(x2 - z2), BB = mod(B * B);
    const E  = mod(AA - BB);
    const C  = mod(x3 + z3), D  = mod(x3 - z3);
    const DA = mod(D * A),   CB = mod(C * B);
    x3 = mod((DA + CB) ** 2n);
    z3 = mod(x1 * mod((DA - CB) ** 2n));
    x2 = mod(AA * BB);
    z2 = mod(E * mod(AA + mod(X25519_A24 * E)));
  }
  if (swap) { [x2, x3] = [x3, x2]; }
  const result = mod(x2 * modPow(z2, P - 2n, P));
  const buf = Buffer.alloc(32);
  let rv = result;
  for (let i = 0; i < 32; i++) { buf[i] = Number(rv & 0xffn); rv >>= 8n; }
  return buf;
}

/**
 * X25519 anahtar çifti üretir.
 */
function generateX25519KeyPair() {
  const { randomBytes } = require('./random');
  const priv = randomBytes(32);
  const pub  = _x25519(priv, X25519_BASE);
  return { privateKey: priv, publicKey: pub };
}

/**
 * X25519 paylaşılan sır hesabı.
 */
function x25519(privateKey, peerPublicKey) {
  return _x25519(privateKey, peerPublicKey);
}

// ─────────────────────────────────────────────────────────────────────────────
// İhracat
// ─────────────────────────────────────────────────────────────────────────────
module.exports = {
  CURVES, getCurve,
  generateEcKeyPair, ecdsaSign, ecdsaVerify, ecdhCompute,
  generateX25519KeyPair, x25519,
  // Dahili yardımcılar (PKI için)
  _pointToUncompressed, _uncompressedToPoint,
  _bigIntToFixedBuf, _bufToBigInt: _bufToBigInt,
  _encodeEcdsaDer, _decodeEcdsaDer,
};
