'use strict';
/**
 * ASN.1 / DER kodlama yardımcıları.
 * X.509 sertifika, CSR ve CRL oluşturma için gerekli tüm ilkeller.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Temel DER ilkeller
// ─────────────────────────────────────────────────────────────────────────────
function encLen(len) {
  if (len < 0x80) return Buffer.from([len]);
  let h = len.toString(16);
  if (h.length % 2) h = '0' + h;
  return Buffer.concat([Buffer.from([0x80 | (h.length >> 1)]), Buffer.from(h, 'hex')]);
}

function tlv(tag, content) {
  const c = Buffer.isBuffer(content) ? content : Buffer.alloc(0);
  return Buffer.concat([Buffer.from([tag]), encLen(c.length), c]);
}

const SEQ   = (...parts) => tlv(0x30, Buffer.concat(parts.filter(Boolean)));
const SET   = (...parts) => tlv(0x31, Buffer.concat(parts.filter(Boolean)));
const BIT   = buf => tlv(0x03, Buffer.concat([Buffer.from([0x00]), buf]));
const OCT   = buf => tlv(0x04, buf);
const NULL  = ()  => tlv(0x05, Buffer.alloc(0));
const OID   = hex => tlv(0x06, Buffer.from(hex.replace(/\s/g, ''), 'hex'));
const UTF8  = str => tlv(0x0c, Buffer.from(str, 'utf8'));
const PRINT = str => tlv(0x13, Buffer.from(str, 'ascii'));
const BOOL  = val => tlv(0x01, Buffer.from([val ? 0xff : 0x00]));
const ENUM  = val => tlv(0x0a, Buffer.from([val]));
const CTX   = (n, c) => tlv(0xa0 | n, c);
const CTXI  = (n, c) => tlv(0x80 | n, c);

function INT(bigInt) {
  if (typeof bigInt === 'number') bigInt = BigInt(bigInt);
  let hex = bigInt.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let buf = Buffer.from(hex, 'hex');
  if (buf[0] >= 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
  return tlv(0x02, buf);
}

function intSmall(v) { return tlv(0x02, Buffer.from([v & 0xff])); }

function UTCTime(d) {
  const p = n => String(n).padStart(2, '0');
  const s = `${String(d.getUTCFullYear()).slice(2)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(s));
}

function GenTime(d) {
  const p = n => String(n).padStart(2, '0');
  const s = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x18, Buffer.from(s));
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal DER okuyucu (parser) — sertifika/CSR/CRL/OCSP çözümleme için
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Tek bir TLV düğümünü `off` konumundan okur.
 * @returns {{ tag:number, len:number, headerLen:number, contentOff:number, totalLen:number, content:Buffer }}
 */
function readTLV(buf, off = 0) {
  if (off >= buf.length) throw new Error('DER: beklenmeyen veri sonu');
  const tag = buf[off];
  let p = off + 1;
  let len = buf[p++];
  if (len & 0x80) {
    const ll = len & 0x7f;
    if (ll === 0) throw new Error('DER: belirsiz uzunluk desteklenmiyor');
    len = 0;
    for (let i = 0; i < ll; i++) len = (len * 256) + buf[p++];
  }
  const contentOff = p;
  const totalLen = (contentOff - off) + len;
  return {
    tag, len, headerLen: contentOff - off, contentOff,
    totalLen, content: buf.subarray(contentOff, contentOff + len),
  };
}

/** Bir SEQUENCE/SET içeriğindeki tüm üst-seviye TLV düğümlerini döner. */
function readChildren(content) {
  const out = [];
  let off = 0;
  while (off < content.length) {
    const node = readTLV(content, off);
    out.push(node);
    off += node.totalLen;
  }
  return out;
}

/** DER INTEGER içeriğini bigint'e çevirir (işaretsiz, X.509 seri no vb. için). */
function derIntToBigInt(content) {
  let v = 0n;
  for (const b of content) v = (v << 8n) | BigInt(b);
  return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// OID tablosu
// ─────────────────────────────────────────────────────────────────────────────
const OIDs = {
  // RSA
  rsaEncryption:            '2a864886f70d010101',
  sha256WithRSAEncryption:  '2a864886f70d01010b',
  sha384WithRSAEncryption:  '2a864886f70d01010c',
  sha512WithRSAEncryption:  '2a864886f70d01010d',
  // EC
  ecPublicKey:              '2a8648ce3d0201',
  // ECDSA imza algoritmaları
  ecdsaWithSHA256:          '2a8648ce3d040302',
  ecdsaWithSHA384:          '2a8648ce3d040303',
  ecdsaWithSHA512:          '2a8648ce3d040304',
  // EC eğrileri
  prime256v1:               '2a8648ce3d030107',   // P-256
  secp384r1:                '2b81040022',          // P-384
  secp521r1:                '2b81040023',          // P-521
  // Hash
  sha1:                     '2b0e03021a',
  sha256:                   '608648016503040201',
  sha384:                   '608648016503040202',
  sha512:                   '608648016503040203',
  // DN bileşenleri
  commonName:               '550403',
  orgName:                  '55040a',
  orgUnit:                  '55040b',
  country:                  '550406',
  locality:                 '550407',
  state:                    '550408',
  // X.509 uzantıları
  basicConstraints:         '551d13',
  keyUsage:                 '551d0f',
  extKeyUsage:              '551d25',
  subjectKeyId:             '551d0e',
  authorityKeyId:           '551d23',
  subjectAltName:           '551d11',
  crlDistPoints:            '551d1f',
  authorityInfoAccess:      '2b06010505070101',
  ocsp:                     '2b06010505073001',
  caIssuers:                '2b06010505073002',
  serverAuth:               '2b06010505070301',
  clientAuth:               '2b06010505070302',
  crlNumber:                '551d14',
  extensionReq:             '2a864886f70d01090e',
  // Diğer
  pkcs9EmailAddress:        '2a864886f70d010901',
};

// KeyUsage bit konumları
const KU = {
  digitalSignature: 0, nonRepudiation: 1, keyEncipherment: 2,
  dataEncipherment: 3, keyAgreement: 4, keyCertSign: 5, cRLSign: 6,
};

// ─────────────────────────────────────────────────────────────────────────────
// SPKI (Subject Public Key Info) oluşturucular
// ─────────────────────────────────────────────────────────────────────────────
function buildRsaSPKI(n, e) {
  const rsaAlg = SEQ(OID(OIDs.rsaEncryption), NULL());
  const pubKey = BIT(SEQ(INT(n), INT(e)));
  return SEQ(rsaAlg, pubKey);
}

function buildEcSPKI(curveName, pubKeyBuf) {
  const { CURVES } = require('./ec');
  const curve = CURVES[curveName];
  if (!curve) throw new Error(`SPKI: bilinmeyen eğri ${curveName}`);
  const ecAlg = SEQ(OID(OIDs.ecPublicKey), OID(curve.oidCurve));
  return SEQ(ecAlg, BIT(pubKeyBuf));
}

// ─────────────────────────────────────────────────────────────────────────────
// İsim (DN) oluşturma
// ─────────────────────────────────────────────────────────────────────────────
function buildName(attrs) {
  return SEQ(...attrs.map(([oid, val]) => {
    const encoded = (oid === OIDs.country) ? PRINT(val) : UTF8(val);
    return SET(SEQ(OID(oid), encoded));
  }));
}

// ─────────────────────────────────────────────────────────────────────────────
// SKID (Subject Key Identifier) hesaplama
// ─────────────────────────────────────────────────────────────────────────────
function computeRsaSKID(n, e) {
  const { sha256 } = require('./hash');
  return sha256(SEQ(INT(n), INT(e))).subarray(0, 20);
}

function computeEcSKID(pubKeyBuf) {
  const { sha256 } = require('./hash');
  return sha256(pubKeyBuf).subarray(0, 20);
}

// ─────────────────────────────────────────────────────────────────────────────
// X.509 Uzantı oluşturucular
// ─────────────────────────────────────────────────────────────────────────────
function ext(oid, critical, value) {
  const parts = [OID(oid)];
  if (critical) parts.push(BOOL(true));
  parts.push(OCT(value));
  return SEQ(...parts);
}

function extBasicConstraints(isCA, pathLen) {
  let inner;
  if (!isCA)                   inner = SEQ();
  else if (pathLen !== undefined) inner = SEQ(BOOL(true), intSmall(pathLen));
  else                          inner = SEQ(BOOL(true));
  return ext(OIDs.basicConstraints, true, inner);
}

function extKeyUsage(bits) {
  let v = 0;
  for (const b of bits) v |= (0x80 >> b);
  const maxBit = bits.reduce((m, b) => Math.max(m, b + 1), 0);
  const unused = (maxBit % 8 === 0) ? 0 : (8 - maxBit % 8);
  // İki byte'lık bit dizisi (KeyUsage en fazla 9 bit)
  const bytes = v > 0xff
    ? [unused, (v >> 8) & 0xff, v & 0xff]
    : [unused, v & 0xff];
  // Kullanılmayan bit konumlarındaki bitler sıfır olmalı (DER kuralı)
  bytes[bytes.length - 1] &= (0xff << unused) & 0xff;
  return ext(OIDs.keyUsage, true, tlv(0x03, Buffer.from(bytes)));
}

function extEKU(oids) {
  return ext(OIDs.extKeyUsage, false, SEQ(...oids.map(o => OID(o))));
}

function extSKID(skid) { return ext(OIDs.subjectKeyId, false, OCT(skid)); }
function extAKID(akid) { return ext(OIDs.authorityKeyId, false, SEQ(CTXI(0, akid))); }

function extSAN(names) {
  const gnames = names.map(n => {
    if (n.type === 'dns')   return CTXI(2, Buffer.from(n.value, 'ascii'));
    if (n.type === 'ip')    return CTXI(7, Buffer.from(n.value.split('.').map(Number)));
    if (n.type === 'email') return CTXI(1, Buffer.from(n.value, 'ascii'));
    throw new Error(`SAN: bilinmeyen tür ${n.type}`);
  });
  return ext(OIDs.subjectAltName, false, SEQ(...gnames));
}

function extCDP(urls) {
  const dps = urls.map(u => SEQ(CTX(0, CTX(0, CTXI(6, Buffer.from(u, 'ascii'))))));
  return ext(OIDs.crlDistPoints, false, SEQ(...dps));
}

function extAIA(ocspUrl, caIssuersUrl) {
  const parts = [];
  if (ocspUrl)      parts.push(SEQ(OID(OIDs.ocsp),      CTXI(6, Buffer.from(ocspUrl, 'ascii'))));
  if (caIssuersUrl) parts.push(SEQ(OID(OIDs.caIssuers), CTXI(6, Buffer.from(caIssuersUrl, 'ascii'))));
  return ext(OIDs.authorityInfoAccess, false, SEQ(...parts));
}

// ─────────────────────────────────────────────────────────────────────────────
// İmza algoritması tanımlayıcısı
// ─────────────────────────────────────────────────────────────────────────────
/**
 * @param {'rsa'|'ec'} keyType
 * @param {'sha256'|'sha384'|'sha512'} hashAlg
 * @param {string} [curveName]
 */
function algId(keyType, hashAlg, curveName) {
  if (keyType === 'rsa') {
    const oidMap = {
      sha256: OIDs.sha256WithRSAEncryption,
      sha384: OIDs.sha384WithRSAEncryption,
      sha512: OIDs.sha512WithRSAEncryption,
    };
    const o = oidMap[hashAlg];
    if (!o) throw new Error(`RSA algId: bilinmeyen hash ${hashAlg}`);
    return SEQ(OID(o), NULL());   // RSA → parameters = NULL
  }
  if (keyType === 'ec') {
    const { CURVES } = require('./ec');
    const curve = CURVES[curveName];
    if (!curve) throw new Error(`EC algId: bilinmeyen eğri ${curveName}`);
    return SEQ(OID(curve.oidSig));  // ECDSA → parameters ABSENT
  }
  throw new Error(`algId: bilinmeyen anahtar türü ${keyType}`);
}

module.exports = {
  // İlkeller
  tlv, SEQ, SET, BIT, OCT, NULL, OID, UTF8, PRINT, BOOL, ENUM, INT, intSmall,
  CTX, CTXI, UTCTime, GenTime,
  // DER okuyucu (parser)
  readTLV, readChildren, derIntToBigInt,
  // OID tablosu ve KU
  OIDs, KU,
  // SPKI / isim
  buildRsaSPKI, buildEcSPKI, buildName,
  computeRsaSKID, computeEcSKID,
  // Uzantılar
  ext, extBasicConstraints, extKeyUsage, extEKU,
  extSKID, extAKID, extSAN, extCDP, extAIA,
  // İmza algoritması tanımlayıcısı
  algId,
};