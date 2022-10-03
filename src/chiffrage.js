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
const { SignateurMessageEd25519 } = require('./formatteurMessage')

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
  } else if(clePubliqueEd25519) {
    // Generer cle secrete derivee avec la cle publique
    const cle = await genererCleSecreteEd25519(clePubliqueEd25519)
    secretKey = cle.cle
    secretChiffre = cle.peer
  }

  // Chiffrer
  const resultat = await chiffreur.encrypt(data, {key: secretKey, digestAlgo, ...opts})

  secretKey = secretKey || resultat.key

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


async function preparerCommandeMaitrecles(certificatsPem, password, domaine, hachage_bytes, identificateurs_document, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG,
        format = opts.format || 'mgs4' //
  // const userId = opts.userId

  // hachage_bytes, iv, tag,

  if(DEBUG) console.debug("preparerCommandeMaitrecles PEM !!: %O", certificatsPem)

  // Verifier elements obligatoires
  if(typeof(domaine) !== 'string') throw new Error(`Domaine mauvais format ${domaine}`)
  if(typeof(hachage_bytes) !== 'string') throw new Error(`hachage_bytes mauvais format : ${hachage_bytes}`)

  // if(Buffer.isBuffer(iv) || ArrayBuffer.isView(iv)) {
  //   iv = base64.encode(iv)
  // } else if(typeof(iv) !== 'string') throw new Error(`iv mauvais format : ${iv}`)
  // if(Buffer.isBuffer(tag) || ArrayBuffer.isView(tag)) {
  //   tag = base64.encode(tag)
  // } else if(typeof(tag) !== 'string') throw new Error(`tag mauvais format : ${tag}`)

  const champsMeta = ['iv', 'nonce', 'tag', 'header']
  const meta = champsMeta.reduce((acc, champ)=>{
    let value = opts[champ]
    if(champ === 'nonce') champ = 'iv'  // Utiliser iv pour la commande
    if(value) {
      if(typeof(value) !== 'string') value = base64.encode(value)
      acc[champ] = value
    }
    return acc
  }, {})

  // Chiffrer le password pour chaque certificat en parametres
  const cles = {}
  let partition = ''
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
      partition = fingerprint
    } else {
      if(DEBUG) console.info("Certificat n'as pas le role maitre des cles\nCERT:%O\nEXT:%O", certForge.subject.attributes, extensionsCertificat)
      throw new Error(`Certificat n'a pas le role 'maitredescles' (cn: ${certCN}, roles: ${roles})`)
    }
    // let ou = certForge.subject.getField('OU')
    // if(ou && ou.value === 'maitrecles') {
    //   partition = fingerprint
    // }

    var passwordChiffre = null
    passwordChiffre = await chiffrerCleEd25519(password, publicKey)

    if(DEBUG) console.debug("Password chiffre pour %s : %s", fingerprint, passwordChiffre)
    cles[fingerprint] = passwordChiffre
  }

  // Creer l'identitie de cle (permet de determiner qui a le droit de recevoir un dechiffrage)
  // Signer l'itentite avec la cle secrete - prouve que l'emetteur de cette commande possede la cle secrete
  const identiteCle = { domaine, identificateurs_document, hachage_bytes }
  // if(userId) identiteCle.user_id = userId

  const clePriveeEd25519 = await hacher(password, {encoding: 'bytes', hashingCode: 'blake2s-256'})

  const cleEd25519 = ed25519.generateKeyPair({seed: clePriveeEd25519})
  const signateur = new SignateurMessageEd25519(cleEd25519.privateKey)
  await signateur.ready
  const signatureIdentiteCle = await signateur.signer(identiteCle)
  console.debug("Identite cle : %O", identiteCle)

  if(DEBUG) console.debug("Info password chiffres par fingerprint : %O", cles)
  var commandeMaitrecles = {
    // Information d'identification signee par cle (preuve de possession de cle secrete)
    ...identiteCle,
    signature_identite: signatureIdentiteCle,

    // Information de dechfifrage
    format,
    ...meta,  // nonce, iv, tag, header, etc.
    cles, 
    _partition: partition
  }

  return commandeMaitrecles
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

  const certForge = forgePki.certificateFromPem(certificatChiffragePem)
  const fingerprintCert = await hacherCertificat(certForge)
  const clePublique = certForge.publicKey
  const optsChiffrage = {...opts}
  if(!opts.clePubliqueEd25519 && clePublique.keyType === '1.3.101.112') {
    // Format EdDSA25519
    optsChiffrage.clePubliqueEd25519 = clePublique.publicKeyBytes
    console.debug("Cle publique Ed25519, opts : %O", optsChiffrage)
  }

  const infoDocumentChiffre = await chiffrer(docString, optsChiffrage)
  const meta = infoDocumentChiffre.meta

  if(DEBUG) console.debug("Document chiffre : %O", infoDocumentChiffre)

  const ciphertextString = base64.encode(infoDocumentChiffre.ciphertext)
  
  const cleSecrete = infoDocumentChiffre.secretKey

  const certificatsAdditionnels = opts.certificats || []
  const certificatsChiffrage = [certificatChiffragePem, ...certificatsAdditionnels]
  console.debug("Certificats chiffrage : %O", certificatsChiffrage)
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
  return {doc: docChiffre, commandeMaitrecles}
}

async function dechiffrerDocument(ciphertext, messageCle, clePrivee, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(typeof(ciphertext) === 'string') {
    // Assumer format multibase
    ciphertext = multibase.decode(ciphertext)
  }
  const {iv, tag, cle: passwordChiffre, format} = messageCle

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
  if(format === 'mgs3') {
    var documentString = await dechiffrer(ciphertext, password, iv, tag)
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

async function updateChampsChiffres(docChamps, secretKey, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG
  const cipherAlgo = opts.cipherAlgo || opts.format || 'mgs4',
        digestAlgo = opts.digestAlgo || 'blake2b-512',
        ref_hachage_bytes = opts.ref_hachage_bytes
  
  if(DEBUG) console.debug("updateChampsChiffres Chiffrer document %O\nopts: %O", docChamps, opts)

  const docBytes = new TextEncoder().encode(stringify(docChamps).normalize())
  
  // Chiffrer
  const chiffreur = getCipher(cipherAlgo)
  if(!chiffreur) throw new Error(`Algorithme de chiffrage (${cipherAlgo}) non supporte`)
  const infoDocumentChiffre = await chiffreur.encrypt(docBytes, {key: secretKey, digestAlgo})
  if(DEBUG) console.debug("updateChampsChiffres Document chiffre ", infoDocumentChiffre)
  const ciphertextString = base64.encode(infoDocumentChiffre.ciphertext)

  const champsChiffres = {data_chiffre: ciphertextString, header: infoDocumentChiffre.header, format: infoDocumentChiffre.format}
  if(ref_hachage_bytes) champsChiffres.ref_hachage_bytes = ref_hachage_bytes

  return champsChiffres
}

async function dechiffrerChampsChiffres(docChamps, cle, opts) {
  opts = opts || {}
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
  
  console.debug("dechiffrerChampsChiffres Contenu dechiffre bytes ", messageDechiffre)

  // Decompresser
  if(opts.lzma) {
    messageDechiffre = pako.inflate(messageDechiffre).buffer
    console.debug("dechiffrerChampsChiffres Contenu inflate LZMA ", messageDechiffre)
  }

  // Decoder bytes en JSON
  const messageJson = new TextDecoder().decode(messageDechiffre)
  console.debug("dechiffrerChampsChiffres Resultat dechiffre ", messageJson)
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
}
