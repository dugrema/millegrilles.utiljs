import {pki, md, asn1, util} from '@dugrema/node-forge'
import multihash from 'multihashes'
import multibase from 'multibase'
import base58 from 'base-58'
import { base58btc } from 'multiformats/bases/base58'
// import { blake2s256 } from '@multiformats/blake2/blake2s'

import {calculerDigest, comparerArraybuffers} from './hachage'

const VERSION_IDMG = 2

export async function encoderIdmg(pem, opts) {
  opts = opts || {}

  const cert = pki.certificateFromPem(pem)
  // const certBuffer = new Uint8Array(Buffer.from(asn1.toDer(pki.certificateToAsn1(cert)).getBytes(), 'binary'))
  const certBuffer = Buffer.from(asn1.toDer(pki.certificateToAsn1(cert)).getBytes(), 'binary')

  // console.debug("Cert Buffer : %O", certBuffer)
  console.debug("!!! DIGESTING avec %O", blake2s256)
  const digestView = await blake2s256.digest(certBuffer)
  console.error("!!! digestView : %O", digestView)
  // const digestView = await calculerDigest(certBuffer, hashingCode)
  const mhValeur = multihash.encode(digestView, hashingCode)

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

  // Encoder en multibase
  var mbValeur = base58btc.encode(viewUint8Idmg)
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
    // console.debug("Hachage calcule : %O\nHachage recu : %O", hachageCalcule, hachageRecu)

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
