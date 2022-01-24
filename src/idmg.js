import nodeforge from '@dugrema/node-forge'
import multihash from 'multihashes'
import multibase from 'multibase'
import base58 from 'base-58'

import {calculerDigest, comparerArraybuffers} from './hachage'

const {pki, md, asn1, util} = nodeforge

const VERSION_IDMG = 2,
      HASHING_CODE = 'blake2s-256',
      ENCODING_IDMG = 'base58btc'

export async function encoderIdmg(pem, opts) {
  opts = opts || {}

  const cert = pki.certificateFromPem(pem)
  const certBuffer = new Uint8Array(Buffer.from(asn1.toDer(pki.certificateToAsn1(cert)).getBytes(), 'binary'))

  const digestView = await calculerDigest(certBuffer, HASHING_CODE)
  const mhValeur = multihash.encode(digestView, HASHING_CODE)

  // console.debug("DIGEST multihash : %O", mhValeur)

  const bufferExpiration = _calculerExpiration(cert)

  // Set version courante dans le premier byte
  const arrayBufferIdmg = new ArrayBuffer(5 + mhValeur.length)
  const viewUint8Idmg = new Uint8Array(arrayBufferIdmg)
  viewUint8Idmg[0] = VERSION_IDMG

  // Set date expiration du cert dans bytes 1-5
  viewUint8Idmg.set(new Uint8Array(bufferExpiration), 1)

  // Set multihash dans bytes 5+
  viewUint8Idmg.set(mhValeur, 5)

  // console.debug("viewUint8Idmg : %O", viewUint8Idmg)

  // Encoder en multibase
  var mbValeur = multibase.encode(ENCODING_IDMG, viewUint8Idmg)
  // console.debug("mbValeur : %s", mbValeur)
  mbValeur = String.fromCharCode.apply(null, mbValeur)

  return mbValeur
}

export async function verifierIdmg(idmg, pem) {
  var idmgBytes
  try {
    idmgBytes = multibase.decode(idmg)
  } catch(err) {
    // Tenter de lire comme version 1
    idmgBytes = base58.decode(idmg)
  }
  const view = new Uint8Array(idmgBytes)
  const version = view[0]

  const cert = pki.certificateFromPem(pem)
  const certBuffer = Buffer.from(asn1.toDer(pki.certificateToAsn1(cert)).getBytes(), 'binary')
  const bufferExpiration = _calculerExpiration(cert)

  let dateExpBytes, hachageRecu, hachageCalcule
  if(version == 1) {
    dateExpBytes = view.slice(29, 33)
    hachageRecu = view.slice(1, 29)

    const bufferByteString = util.createBuffer(certBuffer, 'raw').getBytes()
    const digest = md.sha512.sha224.create().update(bufferByteString).digest()
    hachageCalcule = new Uint8Array(Buffer.from(digest.getBytes(), 'binary'))

  } else if(version == 2) {
    dateExpBytes = view.slice(1, 5)
    var mhBytes = new Uint8Array(view.slice(5))
    var mh = multihash.decode(mhBytes)

    const hashingCode = mh.name
    hachageRecu = mh.digest

    hachageCalcule = await calculerDigest(certBuffer, hashingCode)
  }

  // Comparer hachage
  if( ! comparerArraybuffers(hachageRecu, hachageCalcule) ) {
    throw new Error("Idmg invalide, hachage mismatch")
  }
  if( ! comparerArraybuffers(dateExpBytes, bufferExpiration) ) {
    throw new Error("Idmg invalide, date expiration mismatch")
  }

  return true
}

export async function getIdmg(pem) {
  if(typeof(pem) !== 'string') {
    pem = pem[0]
  }

  const certClient = pki.certificateFromPem(pem)

  console.debug(certClient)
  if(certClient.issuer.hash === certClient.subject.hash) {
    // Self signed
    return encoderIdmg(pem)
  } else {
    return certClient.subject.getField('O').value
  }

}

function _calculerExpiration(cert) {
  const date_expiration = cert.validity.notAfter
  const dateExpEpoch_1000 = Math.ceil(date_expiration.getTime() / 1000000)
  const bufferExpiration = new ArrayBuffer(4)
  const view32Uint = new Uint32Array(bufferExpiration)
  view32Uint[0] = dateExpEpoch_1000

  return bufferExpiration
}

export default {
  encoderIdmg, verifierIdmg, getIdmg
}
