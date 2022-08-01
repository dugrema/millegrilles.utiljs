// const debug = require('debug')('millegrilles:common:validateurMessage')
// const stringify = require('json-stable-stringify')
// const multibase = require('multibase')
// const {util: forgeUtil, pss: forgePss, md: forgeMd, mgf: forgeMgf} = require('node-forge')
// const {verifierHachage, calculerDigest} = require('./hachage')
const debug = require('debug')('millegrilles:common:validateurMessage')
const stringify = require('json-stable-stringify')
const multibase = require('multibase')
const { util: forgeUtil, pss: forgePss, md: forgeMd, mgf: forgeMgf } = require('@dugrema/node-forge')

const {verifierHachage, calculerDigest} = require('./hachage')

// const debug = debugLib('millegrilles:common:validateurMessage')
// const { util: forgeUtil, pss: forgePss, md: forgeMd, mgf: forgeMgf } = nodeforge

function verifierMessage(message, certificat) {
  return Promise.all([
    verifierHachageMessage(message),
    verifierSignatureMessage(message, certificat)
  ])
}

async function verifierHachageMessage(message) {
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
    const messageString = stringify(copieMessage).normalize()

    // Verifier le hachage, lance une Error en cas de mismatch
    debug("Message a verifier pour hachage :\n%O\n%s", copieMessage, hashTransactionRecu)
    return await verifierHachage(hashTransactionRecu, messageString)

  } else {
    debug("Reponse sans entete -- on verifie la signature");
    throw new Error("Message sans entete")
  }
}

async function verifierSignatureMessage(message, certificat, opts) {
  opts = opts || {}

  if(typeof(message) === 'string') {
    const encoder = new TextEncoder()
    message = encoder.encode(message.normalize())
  }

  const entete = message['en-tete']
  const signature = message['_signature']

  const copieMessage = {}
  for(let champ in message) {
    if( ! champ.startsWith('_') ) {
      copieMessage[champ] = message[champ]
    }
  }
  const messageString = stringify(copieMessage).normalize()

  debug("Message a verifier pour signature :\n%O\n: Signature : %s", copieMessage, signature)

  var signatureBuffer = multibase.decode(signature)
  const versionSignature = signatureBuffer[0]

  if(versionSignature === 1) {
    signatureBuffer = signatureBuffer.slice(1)
    signatureBuffer = String.fromCharCode.apply(null, signatureBuffer)
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
  } else if(versionSignature === 2) {
    signatureBuffer = signatureBuffer.slice(1)
    debug("Signature v2 buffer : %O", signatureBuffer)
    const publicKey = certificat.publicKey

    // Stringify en json trie
    const messageBuffer = new Uint8Array(Buffer.from(messageString))
    // Calculer digest du message
    const digestView = await calculerDigest(messageBuffer, 'blake2b-512')
    
    // Verifier la signature. Lance une exception si invalide
    const resultat = publicKey.verify(digestView, signatureBuffer)
    if( resultat !== true ) {
      throw new Error("Erreur verification signature")
    }

    return true

  } else {
    throw new Error(`Version signature ${versionSignature} non supportee`)
  }
}

module.exports = {
  verifierMessage, verifierHachageMessage, verifierSignatureMessage,
}
