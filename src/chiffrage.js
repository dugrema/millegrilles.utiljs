const multibase = require('multibase')
const pako = require('pako')
const { base64 } = require('multiformats/bases/base64')
const { pki: forgePki, ed25519 } = require('@dugrema/node-forge')
const { 
  genererCleSecrete: genererCleSecreteEd25519, 
  chiffrerCle: chiffrerCleEd25519,
  dechiffrerCle: dechiffrerCleEd25519,
} = require('./chiffrage.ed25519')
const stringify = require('json-stable-stringify')

const {hacher, hacherCertificat} = require('./hachage')
const { getCipher } = require('./chiffrage.ciphers')
const {extraireExtensionsMillegrille} = require('./forgecommon')
const { SignatureDomaines } = require('./maitredescles')

const VERSION_SIGNATURE = 0x2

/**
 * Chiffrer une string utf-8 ou un Buffer
 * @param {*} contenu 
 * @param {*} opts 
 */
async function chiffrer(data, opts) {
  opts = opts || {}
  const cipherAlgo = opts.cipherAlgo || opts.format || 'mgs4',
        clePubliqueEd25519 = opts.clePubliqueEd25519,
        digestAlgo = opts.digestAlgo || 'blake2b-512'

  if( ! data instanceof ArrayBuffer && ! ArrayBuffer.isView(data) ) {
    throw new Error(`Data n'est pas de format Buffer`)
  }

  // Faire un chiffrage one-pass
  const chiffreur = getCipher(cipherAlgo)
  if(!chiffreur) throw new Error(`Algorithme de chiffrage (${cipherAlgo}) non supporte`)
  
  // Generer nonce, cle
  let secretKey, secretChiffre = null
  if(opts.key) {
    secretKey = opts.key
    if(typeof(secretKey) === 'string') secretKey = multibase.decode(secretKey)
  } else if(clePubliqueEd25519) {
    // Generer cle secrete derivee avec la cle publique
    const cle = await genererCleSecreteEd25519(clePubliqueEd25519)
    secretKey = cle.cle
    secretChiffre = cle.peer
  }

  // Chiffrer
  const resultat = await chiffreur.encrypt(data, {key: secretKey, digestAlgo, ...opts})

  secretKey = secretKey || resultat.key

  let tag = resultat.tag
  if(resultat.rawTag) {
    tag = base64.encode(resultat.rawTag)
  }

  const champsMeta = ['iv', 'nonce', 'tag', 'header']
  const meta = champsMeta.reduce((acc, champ)=>{
    const value = resultat[champ]
    if(value) {
      if(typeof(value) === 'string') {
        acc[champ] = value
      } else {
        acc[champ] = base64.encode(value)
      }
    }
    return acc
  }, {})

  return {
    ...resultat,
    secretKey,
    secretChiffre,
    meta: {
      ...meta,
      // iv: base64.encode(iv),
      // tag: base64.encode(tag),
      hachage_bytes: resultat.hachage,
      format: resultat.format,
      tag,
    },
  }

}

async function dechiffrer(key, ciphertext, opts) {
  opts = opts || {}
  const algo = opts.algo || opts.format || 'mgs4'

  if( ! key instanceof ArrayBuffer && ! ArrayBuffer.isView(key) ) {
    throw new Error(`La cle symmetrique doit etre un Buffer`)
  }

  // Trouver decipher
  const dechiffreur = getCipher(algo)
  if(!dechiffreur) throw new Error(`Algorithme de chiffrage (${algo}) non supporte`)
  
  // Convertir params multibase en buffer si applicable
  if(typeof(ciphertext) === 'string') ciphertext = multibase.decode(ciphertext)
  // if(typeof(iv) === 'string') iv = multibase.decode(iv)
  // if(typeof(tag) === 'string') tag = multibase.decode(tag)

  // Faire un dechiffrage one-pass
  const resultat = await dechiffreur.decrypt(key, ciphertext, opts)
  return Uint8Array.from(resultat)
  // if( ArrayBuffer.isView(resultat) ) return resultat
  // else if( Buffer.isBuffer(resultat) ) {
  //   return new Uint8Array(resultat)
  // } else if( Array.isArray(resultat) ) {
  //   return new Uint8Array(resultat)
  // } else {
  //   console.error("Format resultat incorrect : %O", resultat)
  //   throw new Error("Erreur interne - format resultat incorrect")
  // }
}

async function preparerCipher(opts) {
  opts = opts || {}
  const cipherAlgo = opts.cipherAlgo || opts.format || 'mgs4',
        clePubliqueEd25519 = opts.clePubliqueEd25519,
        digestAlgo = opts.digestAlgo || 'blake2b-512'

  // Faire un chiffrage one-pass
  const chiffreur = getCipher(cipherAlgo)
  if(!chiffreur) throw new Error(`Algorithme de chiffrage (${cipherAlgo}) non supporte`)
  
  // Generer nonce, cle
  let secretKey, secretChiffre = null
  if(opts.key) {
    secretKey = opts.key
  } else if(clePubliqueEd25519) {
    // Generer cle secrete derivee avec la cle publique
    const cle = await genererCleSecreteEd25519(clePubliqueEd25519)
    secretKey = cle.cle
    secretChiffre = cle.peer
  }

  const paramsCipher = {...opts, key: secretKey, digestAlgo}
  const cipher = await chiffreur.getCipher(paramsCipher)
  
  return {
    cipher,
    secretKey,
    secretChiffre,
  }
}

async function preparerDecipher(key, opts) {
  opts = opts || {}
  const algo = opts.algo || opts.format || 'mgs4'

  if( ! key instanceof ArrayBuffer && ! ArrayBuffer.isView(key) ) {
    throw new Error(`La cle symmetrique doit etre un Buffer`)
  }

  // Trouver decipher
  const dechiffreur = getCipher(algo)
  if(!dechiffreur) throw new Error(`Algorithme de chiffrage (${algo}) non supporte`)

  const decipher = await dechiffreur.getDecipher(key, opts)

  return decipher
}


async function preparerCommandeMaitrecles(certificatsPem, password, signatureDomaines, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG
        // format = opts.cipherAlgo || opts.format || 'mgs4', //
        // peerPublic = opts.peer
  // const userId = opts.userId

  // hachage_bytes, iv, tag,

  if(DEBUG) console.debug("preparerCommandeMaitrecles PEM : %O, signatureDomaines", certificatsPem, signatureDomaines)

  // Verifier elements obligatoires
  if(!signatureDomaines) throw new Error(`preparerCommandeMaitrecles SignatureDomaines manquant`)

  let signatureDomainesObj = signatureDomaines
  if(!signatureDomaines.getCleRef) {
    // Recreer object SignatureDomaines (non transfere si workers)
    signatureDomainesObj = new SignatureDomaines(signatureDomaines.domaines)
    signatureDomainesObj.version = signatureDomaines.version
    signatureDomainesObj.ca = signatureDomaines.ca
    signatureDomainesObj.signature = signatureDomaines.signature
  }

  const cleId = await signatureDomainesObj.getCleRef()
  if(DEBUG) console.debug("preparerCommandeMaitrecles Identite cle : %O", cleId)

  // Chiffrer le password pour chaque certificat en parametres
  const cles = {}
  if(typeof(certificatsPem) === 'string') certificatsPem = [certificatsPem]
  for(let idx in certificatsPem) {
    const pem = certificatsPem[idx]

    // Chiffrer le mot de passe avec le certificat fourni
    const certForge = forgePki.certificateFromPem(pem)
    const certCN = certForge.subject.getField('CN').value
    const publicKey = certForge.publicKey.publicKeyBytes
    const fingerprint = await hacherCertificat(certForge)

    // Choisir une partition de MaitreDesCles
    let extensionsCertificat = extraireExtensionsMillegrille(certForge)
    let roles = extensionsCertificat['roles']
    if(certCN.toLowerCase() === 'millegrille') {
      // Skip
      continue
    } else if(roles && roles.includes('maitredescles')) {
      // Ok
    } else {
      if(DEBUG) console.info("preparerCommandeMaitrecles Certificat n'as pas le role maitre des cles\nCERT:%O\nEXT:%O", certForge.subject.attributes, extensionsCertificat)
      throw new Error(`preparerCommandeMaitrecles Certificat n'a pas le role 'maitredescles' (cn: ${certCN}, roles: ${roles})`)
    }

    var passwordChiffre = null
    passwordChiffre = await chiffrerCleEd25519(password, publicKey)
    passwordChiffre = passwordChiffre.slice(1)  // Retirer le 'm' multibase

    if(DEBUG) console.debug("preparerCommandeMaitrecles Password chiffre pour %s : %s", fingerprint, passwordChiffre)
    cles[fingerprint] = passwordChiffre
  }

  // Creer l'identitie de cle (permet de determiner qui a le droit de recevoir un dechiffrage)
  // Signer l'itentite avec la cle secrete - prouve que l'emetteur de cette commande possede la cle secrete
  // const identiteCle = { domaine, identificateurs_document, hachage_bytes }
  // if(DEBUG) console.debug("Identite cle : %O", identiteCle)
  // // if(userId) identiteCle.user_id = userId

  // const clePriveeEd25519 = await hacher(password, {encoding: 'bytes', hashingCode: 'blake2s-256'})

  // const cleEd25519 = ed25519.generateKeyPair({seed: clePriveeEd25519})
  // const signateur = new SignateurMessageEd25519(cleEd25519.privateKey)
  // await signateur.ready
  // const signatureIdentiteCle = await signateur.signer(identiteCle)
  // const signatureIdentiteCle = await signerIdentiteCle(password, domaine, identificateurs_document, hachage_bytes)

  if(DEBUG) console.debug("Info password chiffres par fingerprint : %O", cles)
  var commandeMaitrecles = {
    // Information d'identification signee par cle (preuve de possession de cle secrete)
    signature: signatureDomaines,

    // Cle chiffrees pour chaque maitre des cles connus
    cles, 
  }

  return commandeMaitrecles
}

/**
 * Genere une nouvelle commande de maitre des cles pour ajouter une cle a des domaines.
 * 
 * @param {*} certificatsPem Liste de certificats a utiliser pour le rechiffrage de la cle. Supporte string si 1 seul certificat.
 * @param {string} clePeerCa Cle peer public X25519 utilisee pour deriver la cle avec le CA.
 * @param {Uint8Array} cleSecrete Cle secrete
 * @param {*} domaines Array de string des domaines a signer. Supporte aussi string si 1 seul domaine.
 * @param {*} opts 
 * @returns {Object} Contenu de la commande ajouter cle domaines. 
 */
async function preparerCommandeAjouterCleDomaines(certificatsPem, clePeerCa, cleSecrete, domaines, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(DEBUG) console.debug("preparerCommandeAjouterCleDomaines domaines %O", domaines)

  // Ajuster parametres
  if(typeof(domaines) === 'string') domaines = [domaines]  // Convertir domaines en array de strings
  if(typeof(certificatsPem) === 'string') certificatsPem = [certificatsPem]
  
  // Verifier elements obligatoires
  if(typeof(clePeerCa) !== 'string') throw new Error(`clePeerCa absent`)
  if(!cleSecrete) throw new Error(`cleSecrete absente`)
  if(!domaines || domaines.length === 0) throw new Error("domaines absents")
  if(!certificatsPem || certificatsPem.length === 0) throw new Error("Aucun certificat de rechiffrage")

  // Chiffrer le password pour chaque certificat en parametres
  const cles = {}
  for(const pem of certificatsPem) {
    // Chiffrer le mot de passe avec le certificat fourni
    const certForge = forgePki.certificateFromPem(pem)
    const certCN = certForge.subject.getField('CN').value
    const publicKey = certForge.publicKey.publicKeyBytes
    const fingerprint = await hacherCertificat(certForge)

    // Choisir une partition de MaitreDesCles
    let extensionsCertificat = extraireExtensionsMillegrille(certForge)
    let roles = extensionsCertificat['roles']
    if(certCN.toLowerCase() === 'millegrille') {
      // Ok
    } else if(roles && roles.includes('maitredescles')) {
      // Ok
    } else {
      if(DEBUG) console.info("Certificat n'as pas le role maitre des cles\nCERT:%O\nEXT:%O", certForge.subject.attributes, extensionsCertificat)
      throw new Error(`Certificat n'a pas le role 'maitredescles' (cn: ${certCN}, roles: ${roles})`)
    }

    const passwordChiffre = await chiffrerCleEd25519(cleSecrete, publicKey)
    if(DEBUG) console.debug("preparerCommandeAjouterCleDomaines Password chiffre pour %s : %s", fingerprint, passwordChiffre)
    cles[fingerprint] = passwordChiffre.slice(1)  // retirer 'm' multibase
  }

  // Creer la SignatureDomaines
  const signature = new SignatureDomaines(domaines)
  await signature.signerEd25519(clePeerCa, cleSecrete)

  return { cles, signature }
}

async function chiffrerDocument(docChamps, domaine, certificatChiffragePem, identificateurs_document, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(DEBUG) console.debug("Chiffrer document %O\nopts: %O\nIdentificateurs_document: %O", docChamps, opts, identificateurs_document)
  // if(DEBUG) console.debug("Verification du certificat pour chiffrer la cle")
  // const {publicKey: clePublique, fingerprint} = await _getPublicKeyFromCertificat(certificatChiffragePem, opts)

  var docString = opts.nojson?docChamps:stringify(docChamps).normalize()  // string
  const typeBuffer = opts.type || 'utf-8'
  if(typeBuffer == 'binary') {
    // Rien a faire
  } else if(typeof(TextEncoder) !== 'undefined') {
    docString = new TextEncoder().encode(docString)  // buffer
  } else {
    docString = Buffer.from(docString, typeBuffer)
  }

  if(opts.lzma) {
    docString = pako.deflate(docString, {gzip: true})
  }

  const certForge = forgePki.certificateFromPem(certificatChiffragePem)
  const fingerprintCert = await hacherCertificat(certForge)
  const clePublique = certForge.publicKey
  const optsChiffrage = {...opts}
  if(!opts.clePubliqueEd25519 && clePublique.keyType === '1.3.101.112') {
    // Format EdDSA25519
    optsChiffrage.clePubliqueEd25519 = clePublique.publicKeyBytes
    if(DEBUG) console.debug("Cle publique Ed25519, opts : %O", optsChiffrage)
  }

  const infoDocumentChiffre = await chiffrer(docString, optsChiffrage)
  const meta = infoDocumentChiffre.meta

  if(DEBUG) console.debug("Document chiffre : %O", infoDocumentChiffre)

  const ciphertextString = base64.encode(infoDocumentChiffre.ciphertext)
  
  const cleSecrete = infoDocumentChiffre.secretKey

  const certificatsAdditionnels = opts.certificats || []
  const certificatsChiffrage = [certificatChiffragePem, ...certificatsAdditionnels]
  if(DEBUG) console.debug("Certificats chiffrage : %O", certificatsChiffrage)
  const commandeMaitrecles = await preparerCommandeMaitrecles(
    certificatsChiffrage, cleSecrete, domaine, meta.hachage_bytes, 
    identificateurs_document,
    {...opts, ...meta}
  )

  // Override cle secrete chiffree pour certificat avec secret pour rederiver la cle (plus court)
  if(infoDocumentChiffre.secretChiffre) {
    const clesChiffrees = commandeMaitrecles.cles
    clesChiffrees[fingerprintCert] = infoDocumentChiffre.secretChiffre
  }

  const docChiffre = {
    data_chiffre: ciphertextString, 
    header: infoDocumentChiffre.header, 
    format: infoDocumentChiffre.format, 
    ref_hachage_bytes: commandeMaitrecles.hachage_bytes,
  }

  const resultat = {doc: docChiffre, commandeMaitrecles}
  if(opts.retourSecret === true) resultat.cleSecrete = cleSecrete
  return resultat
}

async function dechiffrerDocument(ciphertext, messageCle, clePrivee, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(typeof(ciphertext) === 'string') {
    // Assumer format multibase
    ciphertext = multibase.decode(ciphertext)
  }
  const {iv, nonce, tag, cle: passwordChiffre, format} = messageCle

  if(DEBUG) console.debug(`Dechiffrer message format ${format} avec iv: ${iv}, tag: ${tag}\nmessage: %O`, ciphertext)

  // Dechiffrer le password a partir de la cle chiffree
  var password = null
  if( Buffer.isBuffer(clePrivee) || ArrayBuffer.isView(clePrivee) ) {
    password = await dechiffrerCleEd25519(messageCle.cle, clePrivee, opts)
  } else {
    throw new Error("Format de la cle privee de dechiffrage inconnu")
  }

  if(DEBUG) console.debug("Password dechiffre : %O, iv: %s, tag: %s", password, iv, tag)

  var contenuDocument = null
  if(getCipher(format)) {
    var documentString = await dechiffrer(password, ciphertext, {...opts, format, nonce: nonce||iv, tag})
    if(opts.unzip) {
      documentString = await new Promise((resolve, reject)=>{
        throw new Error('fix me')
        // unzip(documentString, (err, buffer)=>{
        //   if(err) reject(err)
        //   resolve(buffer)
        // })
      })
    }
    if(opts.lzma) {
      // Decompresser
      documentString = pako.inflate(documentString).buffer
    }    
    if(typeof(TextDecoder) !== 'undefined') {
      documentString = new TextDecoder().decode(documentString)  // buffer
    } else {
      documentString = forgeUtil.decodeUtf8(documentString)
    }
    if(!opts.nojson) {
      contenuDocument = JSON.parse(documentString)
    } else {
      contenuDocument = documentString
    }
  } else {
    throw new Error(`Format dechiffrage ${format} non supporte`)
  }

  return contenuDocument
}

async function chiffrerChampsV2(docChamps, domaine, clePubliqueCa, certificatsChiffragePem, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(DEBUG) console.debug("Chiffrer document %O\nopts: %O", 
    docChamps, opts)

  var docString = opts.nojson?docChamps:stringify(docChamps).normalize()  // string
  const typeBuffer = opts.type || 'utf-8'
  if(typeBuffer == 'binary') {
    // Rien a faire
  } else if(typeof(TextEncoder) !== 'undefined') {
    docString = new TextEncoder().encode(docString)  // buffer
  } else {
    docString = Buffer.from(docString, typeBuffer)
  }

  // Options de compression
  if(opts.gzip) {
    throw new Error("to do")
    //docString = pako.gzip(docString)
  }

  const optsChiffrage = {...opts}
  optsChiffrage.clePubliqueEd25519 = clePubliqueCa

  const infoDocumentChiffre = await chiffrer(docString, optsChiffrage)
  const meta = infoDocumentChiffre.meta

  const ciphertextString = base64.encode(infoDocumentChiffre.ciphertext)
  if(DEBUG) console.debug("Document chiffre : %O\nCiphertext base64: %s", infoDocumentChiffre, ciphertextString)
  
  const cleSecrete = infoDocumentChiffre.secretKey

  if(DEBUG) console.debug("Certificats chiffrage : %O", certificatsChiffragePem)
  const peerCa = infoDocumentChiffre.secretChiffre.slice(1)  // Retirer 'm' multibase
  const commandeMaitrecles = await preparerCommandeAjouterCleDomaines(
    certificatsChiffragePem, peerCa, cleSecrete, domaine, opts
  )
  const cleId = await commandeMaitrecles.signature.getCleRef()

  let nonce = meta.nonce || meta.iv || meta.header
  if(nonce) nonce = nonce.slice(1)  // Retirer 'm' multibase

  let verification = meta.verification
  if(!verification && meta.tag) {
    verification = meta.tag.slice(1)  // Retirer 'm' multibase
  } else {
    verification = meta.hachage_bytes
  }

  const docChiffre = {
    data_chiffre: ciphertextString.slice(1), // Retirer 'm' multibase
    format: meta.format, 
    nonce, 
    verification,
    cle_id: cleId,
  }

  const resultat = {doc: docChiffre, commandeMaitrecles}
  if(opts.retourSecret === true) resultat.cleSecrete = cleSecrete
  return resultat
}

function convertirChampsV1ToV2(champs) {
  if(champs.header) {
    return {
      // Retirer 'm' multibase
      data_chiffre: champs.data_chiffre.slice(1),  
      nonce: champs.header.slice(1),  

      // Renommer
      verification: null,

      // Transferer valeurs
      format: champs.format,
    }
  }
  return champs  // Rien a faire
}

async function dechiffrerChampsV2(message, cleSecrete, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  message = convertirChampsV1ToV2(message)

  const bytesCiphertext = base64.decode('m' + message.data_chiffre)
  if(message.nonce) message.nonce = multibase.decode('m' + message.nonce)
  if(message.verification && !message.verification.startsWith('z')) {
    message.verification = multibase.decode('m'+message.verification)
  }

  const decipher = await preparerDecipher(cleSecrete, message)

  // Dechiffrer message
  let messageDechiffre = null
  let outputDechiffre = await decipher.update(bytesCiphertext)
  messageDechiffre = concatArrays(messageDechiffre, outputDechiffre)
  const outputFinalize = await decipher.finalize(message.verification)
  messageDechiffre = concatArrays(messageDechiffre, outputFinalize.message)
  
  if(DEBUG) console.debug("dechiffrerChampsChiffres Contenu dechiffre bytes ", messageDechiffre)

  // Decompresser
  if(opts.gzip) {
    try {
      messageDechiffre = pako.inflate(messageDechiffre).buffer
    } catch(err) {
      console.error("Erreur decompression avec pako : ", err)
      throw err
    }
    if(DEBUG) console.debug("dechiffrerChampsChiffres Contenu inflate gzip ", messageDechiffre)
  }

  // Decoder bytes en JSON
  const messageJson = new TextDecoder().decode(messageDechiffre)
  if(DEBUG) console.debug("dechiffrerChampsChiffres Resultat dechiffre ", messageJson)
  return JSON.parse(messageJson)
}

async function updateChampsChiffres(docChamps, secretKey, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG
  const cipherAlgo = opts.cipherAlgo || opts.format || 'mgs4',
        digestAlgo = opts.digestAlgo || 'blake2b-512',
        ref_hachage_bytes = opts.ref_hachage_bytes
  
  if(DEBUG) console.debug("updateChampsChiffres Chiffrer document %O\nopts: %O", docChamps, opts)

  let docBytes = new TextEncoder().encode(stringify(docChamps).normalize())
  if(opts.lzma) {
    docBytes = pako.deflate(docBytes, {gzip: true})
  }

  // Chiffrer
  const chiffreur = getCipher(cipherAlgo)
  if(!chiffreur) throw new Error(`Algorithme de chiffrage (${cipherAlgo}) non supporte`)
  const infoDocumentChiffre = await chiffreur.encrypt(docBytes, {key: secretKey, digestAlgo})
  if(DEBUG) console.debug("updateChampsChiffres Document chiffre ", infoDocumentChiffre)
  const ciphertextString = base64.encode(infoDocumentChiffre.ciphertext)

  let nonce = infoDocumentChiffre.nonce || infoDocumentChiffre.iv || infoDocumentChiffre.header
  nonce = nonce.slice(1)  // Retirer 'm' multibase

  const champsChiffres = {
    data_chiffre: ciphertextString.slice(1),  // Retirer 'm' multibase
    nonce,
    format: infoDocumentChiffre.format
  }
  if(ref_hachage_bytes) champsChiffres.ref_hachage_bytes = ref_hachage_bytes

  return champsChiffres
}

async function dechiffrerChampsChiffres(docChamps, cle, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG
    // Override champs au besoin (header, iv, tag, format, etc)
  const cleCombinee = {...cle, ...docChamps}
  
  const bytesCiphertext = base64.decode(docChamps.data_chiffre)
  const decipher = await preparerDecipher(cleCombinee.cleSecrete, cleCombinee)

  // Dechiffrer message
  let messageDechiffre = null
  let outputDechiffre = await decipher.update(bytesCiphertext)
  messageDechiffre = concatArrays(messageDechiffre, outputDechiffre)
  const outputFinalize = await decipher.finalize()
  messageDechiffre = concatArrays(messageDechiffre, outputFinalize.message)
  
  if(DEBUG) console.debug("dechiffrerChampsChiffres Contenu dechiffre bytes ", messageDechiffre)

  // Decompresser
  if(opts.lzma) {
    try {
      messageDechiffre = pako.inflate(messageDechiffre).buffer
    } catch(err) {
      console.error("Erreur decompression avec pako : ", err)
      throw err
    }
    if(DEBUG) console.debug("dechiffrerChampsChiffres Contenu inflate LZMA ", messageDechiffre)
  }

  // Decoder bytes en JSON
  const messageJson = new TextDecoder().decode(messageDechiffre)
  if(DEBUG) console.debug("dechiffrerChampsChiffres Resultat dechiffre ", messageJson)
  return JSON.parse(messageJson)
}

function concatArrays(array1, array2) {
  if(!array2 || array2.length === 0) return array1
  if(!array1 || array1.length === 0) return array2
  const lengthFinal = array1.length + array2.length
  const arrayOut = new Uint8Array(lengthFinal)
  arrayOut.set(array1)
  arrayOut.set(array2, array1.length)
  return arrayOut
}

async function dechiffrerDocumentAvecMq(mq, ciphertext, opts) {
  /* Permet de dechiffrer un ciphertext avec un minimum d'information. */
  opts = opts || {}
  const permission = opts.permission

  // Calculer hachage_bytes du ciphertext
  const ciphertextBytes = multibase.decode(ciphertext)
  const hachage_bytes = await hacher(ciphertextBytes, {encoding: 'base58btc'})

  // Executer requete pour recuperer cle de dechiffrage
  const requeteCle = {
    liste_hachage_bytes: [hachage_bytes],
    permission,
  }
  const domaineActionCle = 'MaitreDesCles.dechiffrage'
  const reponseDemandeCle = await mq.transmettreRequete(
    domaineActionCle, requeteCle, {attacherCertificat: true})

  // Dechiffrer le ciphertext
  const infoCleRechiffree = reponseDemandeCle.cles[hachage_bytes]
  const secretContent = await dechiffrerDocument(
    ciphertextBytes, infoCleRechiffree, mq.pki.cleForge, opts)

  return secretContent
}

module.exports = {
  chiffrer, dechiffrer, preparerCipher, preparerDecipher, preparerCommandeMaitrecles, 
  chiffrerDocument, dechiffrerDocument, dechiffrerDocumentAvecMq,
  updateChampsChiffres, dechiffrerChampsChiffres,
  
  chiffrerChampsV2, dechiffrerChampsV2, preparerCommandeAjouterCleDomaines,

  // Obsolete
  // signerIdentiteCle, 
}
