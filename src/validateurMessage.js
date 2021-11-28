// const debug = require('debug')('millegrilles:common:validateurMessage')
// const stringify = require('json-stable-stringify')
// const multibase = require('multibase')
// const {util: forgeUtil, pss: forgePss, md: forgeMd, mgf: forgeMgf} = require('node-forge')
// const {verifierHachage, calculerDigest} = require('./hachage')
import debugLib from 'debug'
import stringify from 'json-stable-stringify'
import multibase from 'multibase'

import {verifierHachage, calculerDigest} from './hachage'

const debug = debugLib('millegrilles:common:validateurMessage')

export function verifierMessage(message, certificat) {
  return Promise.all([
    verifierHachageMessage(message),
    verifierSignatureMessage(message, certificat)
  ])
}

export async function verifierHachageMessage(message) {
  // Valider le contenu du message - hachage et signature
  const entete = message['en-tete']

  const copieMessage = {}
  for(let champ in message) {
    if(champ !== 'en-tete' && ! champ.startsWith('_') ) {
      copieMessage[champ] = message[champ]
    }
  }

  if(entete) {
    const hashTransactionRecu = entete['hachage_contenu']
    const messageString = stringify(copieMessage)

    // Verifier le hachage, lance une Error en cas de mismatch
    debug("Message a verifier pour hachage :\n%O", copieMessage)
    await verifierHachage(hashTransactionRecu, messageString)

  } else {
    debug("Reponse sans entete -- on verifie la signature");
  }
}

export async function verifierSignatureMessage(message, certificat, opts) {
  opts = opts || {}

  const entete = message['en-tete']
  const signature = message['_signature']

  const copieMessage = {}
  for(let champ in message) {
    if(champ.startsWith('_') ) {
      copieMessage[champ] = message[champ]
    }
  }
  const messageString = stringify(copieMessage)

  debug("Message a verifier pour signature :\n%O\n: Signature : %s", copieMessage, signature)

  var signatureBuffer = multibase.decode(signature)
  debug("Signature buffer 1 : %O", signatureBuffer)
  const versionSignature = signatureBuffer[0]

  if(versionSignature === 1) {
    signatureBuffer = signatureBuffer.slice(1)
    signatureBuffer = String.fromCharCode.apply(null, signatureBuffer)
    debug("Signature buffer 2 : %O", signatureBuffer)
    const publicKey = certificat.publicKey

    const pss = forgePss.create({
      md: forgeMd.sha512.create(),
      mgf: forgeMgf.mgf1.create(forgeMd.sha512.create()),
      saltLength: 64,
    })

    const digestView = await calculerDigest(messageString, 'sha2-512')
    const digestInfo = forgeUtil.createBuffer(digestView, 'raw').getBytes()

    // Verifier la signature. Lance une exception si invalide (retourne false quand valide... mouais)
    publicKey.verify(digestInfo, signatureBuffer, pss)

    // Aucune exception, la signature est valide
    return true

  } else {
    throw new Error(`Version signature ${versionSignature} non supportee`)
  }
}

export default {
  verifierMessage, verifierHachageMessage, verifierSignatureMessage,
}
