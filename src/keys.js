'use strict';

// ASN.1 ve EC modüllerinden gerekli olan temel fonksiyonları içeri alıyoruz
const { SEQ, INT, intSmall, OCT, BIT, OID, CTX, readTLV, readChildren, derIntToBigInt } = require('./asn1');
const { CURVES, _bigIntToFixedBuf, _bufToBigInt, _uncompressedToPoint } = require('./ec');

/**
 * RSA Özel Anahtarını (Ham N, E, D vb. değerlerinden) PKCS#1 PEM formatına çevirir.
 */
function rsaPrivToPem(key) {
  const der = SEQ(intSmall(0), INT(key.n), INT(key.e), INT(key.d), INT(key.p), INT(key.q), INT(key.dp), INT(key.dq), INT(key.qInv));
  const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN RSA PRIVATE KEY-----\n${b64}\n-----END RSA PRIVATE KEY-----\n`;
}

/**
 * Eliptik Eğri (EC) Özel Anahtarını SEC1 PEM formatına çevirir.
 */
function ecPrivToPem(key) {
  const cName = key.curve || key.curveName; 
  const curveOid = CURVES[cName].oidCurve;
  const der = SEQ(intSmall(1), OCT(_bigIntToFixedBuf(key.privateKey, CURVES[cName].byteLen)), CTX(0, OID(curveOid)), CTX(1, BIT(key.publicKeyBuf)));
  const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN EC PRIVATE KEY-----\n${b64}\n-----END EC PRIVATE KEY-----\n`;
}

/**
 * DER formatındaki CRL Buffer'ını PEM formatına sarmalar.
 */
function crlToPem(derBuf) {
  const b64 = derBuf.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN X509 CRL-----\n${b64}\n-----END X509 CRL-----\n`;
}

/** PEM zarfını (BEGIN/END başlıkları) soyup ham DER Buffer'ı döner. */
function _pemToDer(pem) {
  const b64 = pem
    .split('\n')
    .filter(line => line && !line.startsWith('-----'))
    .join('');
  return Buffer.from(b64, 'base64');
}

/**
 * PKCS#1 "EC PRIVATE KEY" (SEC1) PEM'ini çözümler.
 * @returns {{ curveName, privateKey: bigint, publicKeyBuf: Buffer }}
 */
function pemToEcPriv(pem) {
  const der = _pemToDer(pem);
  const top = readTLV(der, 0);             // ECPrivateKey SEQUENCE
  const children = readChildren(top.content);
  // children: [version INTEGER, privateKey OCTET STRING, [0] parameters, [1] publicKey]
  const privOct = children[1];
  const privateKey = _bufToBigInt(privOct.content);

  let curveName = null, publicKeyBuf = null;
  for (let i = 2; i < children.length; i++) {
    const node = children[i];
    if (node.tag === 0xa0) {
      // [0] EXPLICIT parameters → OID
      const oidNode = readTLV(node.content, 0);
      const oidHex = oidNode.content.toString('hex');
      curveName = Object.keys(CURVES).find(name => CURVES[name].oidCurve === oidHex) || null;
    } else if (node.tag === 0xa1) {
      // [1] EXPLICIT publicKey → BIT STRING
      const bitNode = readTLV(node.content, 0);
      publicKeyBuf = bitNode.content.subarray(1); // unused-bits baytı hariç
    }
  }
  if (!curveName) throw new Error('pemToEcPriv: eğri (curve) tanımlanamadı');
  return { curveName, curve: curveName, privateKey, publicKeyBuf };
}

/**
 * PKCS#1 "RSA PRIVATE KEY" PEM'ini çözümler.
 * @returns {{ n, e, d, p, q, dp, dq, qInv: bigint }}
 */
function pemToRsaPriv(pem) {
  const der = _pemToDer(pem);
  const top = readTLV(der, 0);
  const children = readChildren(top.content);
  // children: [version, n, e, d, p, q, dp, dq, qInv]
  const [, n, e, d, p, q, dp, dq, qInv] = children.map(c => derIntToBigInt(c.content));
  return { n, e, d, p, q, dp, dq, qInv };
}

/**
 * X.509 sertifikası PEM'inden OCSP/CRL imzalama için gereken temel alanları
 * çıkarır: issuer/subject Name (DER), SKID (varsa) ve geçerlilik tarihleri.
 * Not: Bu fonksiyon sertifika imzasını DOĞRULAMAZ — sadece yapısal alanları okur.
 */
function certInfoFromPem(pem) {
  const der = _pemToDer(pem);
  const top = readTLV(der, 0);              // Certificate SEQUENCE
  const certChildren = readChildren(top.content);
  const tbs = certChildren[0];               // tbsCertificate SEQUENCE
  const tbsChildren = readChildren(tbs.content);

  // tbsCertificate ::= SEQUENCE { version [0], serialNumber, signature,
  //                               issuer, validity, subject, subjectPublicKeyInfo, ... }
  let idx = 0;
  if (tbsChildren[idx].tag === 0xa0) idx++; // version [0]
  const serialNode = tbsChildren[idx++];
  idx++; // signature AlgorithmIdentifier
  const issuerNode = tbsChildren[idx++];
  idx++; // validity
  const subjectNode = tbsChildren[idx++];
  const spkiNode = tbsChildren[idx++];

  // ÖNEMLİ: her node'un contentOff/totalLen değeri, KENDİSİNİN okunduğu
  // ebeveyn buffer'a (burada tbs.content) göre relatiftir — orijinal `der`
  // buffer'ına göre DEĞİL. Tam TLV baytlarını (tag+length+content) elde
  // etmek için tbs.content üzerinden, node'un kendi başlangıç offset'i
  // (contentOff - headerLen) ile totalLen kullanılarak dilimleme yapılır.
  const fullTlv = (node) => tbs.content.subarray(
    node.contentOff - node.headerLen,
    node.contentOff - node.headerLen + node.totalLen,
  );

  return {
    serialNumber: derIntToBigInt(serialNode.content),
    issuerNameDer: fullTlv(issuerNode),
    subjectNameDer: fullTlv(subjectNode),
    spkiDer: fullTlv(spkiNode),
    certDer: der,
  };
}

module.exports = {
  rsaPrivToPem, ecPrivToPem, crlToPem,
  pemToEcPriv, pemToRsaPriv, certInfoFromPem,
};