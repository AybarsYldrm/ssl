'use strict';
/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  SAF KRİPTOGRAFİ & PKI MOTORU — Modül İhracatları              ║
 * ║  crypto modülü yok · sıfır harici bağımlılık                   ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * Hash     : sha256, sha384, sha512
 * MAC/KDF  : hmac, hmac256/384/512, hkdf
 * Simetrik : gcmEncrypt, gcmDecrypt  (AES-128/192/256-GCM)
 * RSA      : generateRsaKeyPair(bits), rsaSign, rsaVerify,
 *            rsaOaepEncrypt, rsaOaepDecrypt
 * EC       : generateEcKeyPair(curve), ecdsaSign, ecdsaVerify,
 *            ecdhCompute (P-256/384/521)
 * X25519   : generateX25519KeyPair, x25519
 * PKI      : generateRootCA, generateIntermediateCA,
 *            generateEndEntityCert, generateEcRootCA,
 *            generateEcEndEntityCert, generateCSR, generateCRL,
 *            createCertificate
 * Rastgele : randomBytes
 */

// ── Temel ────────────────────────────────────────────────────────────────────
const { randomBytes, randomBigIntRange } = require('./src/random');

// ── Hash ─────────────────────────────────────────────────────────────────────
const { sha1, sha256, sha384, sha512, hashByName } = require('./src/hash');

// ── MAC / KDF ─────────────────────────────────────────────────────────────────
const {
  hmac, hmac256, hmac384, hmac512, hkdfExtract, hkdfExpand, hkdf
} = require('./src/hmac');

// ── Simetrik (AES-GCM) ───────────────────────────────────────────────────────
const { gcmEncrypt, gcmDecrypt, aesEncryptBlock, aesExpandKey } = require('./src/aes');

// BigInt 

const { modPow, modInverse, isProbablePrime, generatePrime } = require('./src/bigint')

// ── RSA ───────────────────────────────────────────────────────────────────────
const {
  generateRsaKeyPair, rsaSign, rsaVerify,
  rsaOaepEncrypt, rsaOaepDecrypt, _bufToBigInt, _bigIntToBuf
} = require('./src/rsa');

// ── EC / X25519 ───────────────────────────────────────────────────────────────
const {
  CURVES, getCurve,
  generateEcKeyPair, ecdsaSign, ecdsaVerify, ecdhCompute,
  generateX25519KeyPair, x25519,
  // Dahili yardımcılar (PKI için)
  _pointToUncompressed, _uncompressedToPoint,
  _bigIntToFixedBuf,
  _encodeEcdsaDer, _decodeEcdsaDer,
} = require('./src/ec');

// ── PKI ───────────────────────────────────────────────────────────────────────
const {
  generateRootCA, generateIntermediateCA, generateEndEntityCert,
  generateEcRootCA, generateEcIntermediateCA, generateEcEndEntityCert,
  generateCSR, generateCRL, parseCRL, createCertificate, newSerial,
  generateOcspResponse, parseOcspRequest, verifyOcspResponse,
} = require('./src/pki');

// ── Anahtar Serileştirme (PEM ↔ ham anahtar) ──────────────────────────────────
const {
  rsaPrivToPem, ecPrivToPem, crlToPem,
  pemToEcPriv, pemToRsaPriv, certInfoFromPem,
} = require('./src/keys');

const {
  mlkem768GenerateKeyPair, mlkemEncapsulate, mlkemDecapsulate, MLKEM768,
  sha3_256, sha3_512, shake128, shake256, keccakF1600,
  ntt, nttInv, baseMul, polyAdd, polySub, compress, decompress,
  byteEncode, byteDecode, sampleCBD, sampleNTT,
  _kPkeKeyGen, _kPkeEncrypt, _kPkeDecrypt
} = require('./src/mlkem');

const {
  mldsaKeyGen,
  mldsaSign,
  mldsaVerify,
  MLDSA65,
  // Dahili test yardımcıları
  dntt, dnttInv, dbaseMul, expandA, sampleInBall,
} = require('./src/mldsa');

// ── ASN.1 / DER ───────────────────────────────────────────────────────────────
const asn1 = require('./src/asn1');

// ─────────────────────────────────────────────────────────────────────────────
module.exports = {
  // Temel
  randomBytes, randomBigIntRange,

  // Hash
  sha1, sha256, sha384, sha512, hashByName,

  // MAC / KDF
  hmac, hmac256, hmac384, hmac512, hkdfExtract, hkdfExpand, hkdf,

  // Simetrik
  gcmEncrypt, gcmDecrypt, aesEncryptBlock, aesExpandKey,

  // RSA (2048 / 3072 / 4096)
  generateRsaKeyPair, rsaSign, rsaVerify,
  rsaOaepEncrypt, rsaOaepDecrypt,
  _bufToBigInt, _bigIntToBuf,

  // EC (P-256 / P-384 / P-521)
  CURVES, getCurve,
  generateEcKeyPair, ecdsaSign, ecdsaVerify, ecdhCompute,
  generateX25519KeyPair, x25519,
  // Dahili yardımcılar (PKI için)
  _pointToUncompressed, _uncompressedToPoint,
  _bigIntToFixedBuf,
  _encodeEcdsaDer, _decodeEcdsaDer,

  // PKI
  generateRootCA, generateIntermediateCA, generateEndEntityCert,
  generateEcRootCA, generateEcIntermediateCA, generateEcEndEntityCert,
  generateCSR, generateCRL, parseCRL, createCertificate, newSerial,
  generateOcspResponse, parseOcspRequest, verifyOcspResponse,

  // Anahtar Serileştirme (PEM ↔ ham anahtar)
  rsaPrivToPem, ecPrivToPem, crlToPem,
  pemToEcPriv, pemToRsaPriv, certInfoFromPem,

  //bigint
  modPow, modInverse, isProbablePrime, generatePrime,

  // Mlkem
  mlkem768GenerateKeyPair, mlkemEncapsulate, mlkemDecapsulate, MLKEM768,
  sha3_256, sha3_512, shake128, shake256, keccakF1600,
  ntt, nttInv, baseMul, polyAdd, polySub, compress, decompress,
  byteEncode, byteDecode, sampleCBD, sampleNTT,
  _kPkeKeyGen, _kPkeEncrypt, _kPkeDecrypt,

  // Mldsa
  mldsaKeyGen,
  mldsaSign,
  mldsaVerify,
  MLDSA65,
  // Dahili test yardımcıları
  dntt, dnttInv, dbaseMul, expandA, sampleInBall,
  // ASN.1 / DER (ileri düzey kullanım)
  asn1,
};