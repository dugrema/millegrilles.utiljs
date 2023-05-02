const { ed25519 } = require('@dugrema/node-forge')
const { hacherMessage } = require('./formatteurMessage')

/// Verifie un message, lance une Error si une des etapes echoue
async function verifierMessage(message, opts) {
  opts = opts || {}
  const certificat = opts.certificat

  if(certificat) {
    // S'assurer que la pubkey du certificat correspond a pubkey
    verifierCorrespondanceCertificat(message.pubkey, certificat)
  }

  // Verifier la signature du message (id, pubkey, sig)
  verifierSignatureMessage(message)

  // Verifier le hachage du message hash(pubkey, estampille, kind, contenu, routage) === id
  await verifierHachageMessage(message)
 
  return true
}

function verifierCorrespondanceCertificat(pubkey, certificat) {
  const pubKeyCertificat = Buffer.from(certificat.publicKey.publicKeyBytes).toString('hex')
  // console.debug("Comparer pubkey %O avec %O", pubkey, pubKeyCertificat)
  if(pubkey !== pubKeyCertificat) {
    throw new Error("Erreur verification pubkey (mismatch certificat)")
  }
  return true
}

async function verifierHachageMessage(message) {

  const messageHachage = [
    message.pubkey,
    message.estampille,
    message.kind,
    message.contenu,
  ]

  const champsOptionnels = ['routage', 'origine', 'dechiffrage']
  for (const champ of champsOptionnels) {
    if(message[champ]) messageHachage.push(message[champ])
  }

  // Hacher le message
  const hachageMessage = await hacherMessage(messageHachage)
  if(message.id !== hachageMessage) {
    throw new Error('Hachage invalide')
  }
  return true
}

function verifierSignatureMessage(message, opts) {
  opts = opts || {}

  const sig = Buffer.from(message.sig, 'hex'),
        pubkey = Buffer.from(message.pubkey, 'hex'),
        hachage = Buffer.from(message.id, 'hex')

  // Verifier la signature. Lance une exception si invalide
  // const resultat = publicKey.verify(hachage, sig)
  const resultat = ed25519.verify({publicKey: pubkey, message: hachage, signature: sig})
  if( resultat !== true ) {
    throw new Error("Erreur verification signature")
  }

  return resultat
}

module.exports = {
  verifierMessage, verifierHachageMessage, verifierSignatureMessage,
}
