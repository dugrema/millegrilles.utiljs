const multibase = require('multibase')
const { base64 } = require('multiformats/bases/base64')
const { pki: forgePki } = require('@dugrema/node-forge')
const { 
  genererCleSecrete: genererCleSecreteEd25519, 
  chiffrerCle: chiffrerCleEd25519,
  dechiffrerCle: dechiffrerCleEd25519,
} = require('./chiffrage.ed25519')
const stringify = require('json-stable-stringify')

const {hacher, hacherCertificat} = require('./hachage')
const { getCipher } = require('./chiffrage.ciphers')
const {extraireExtensionsMillegrille} = require('./forgecommon')

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

  const cipher = await chiffreur.getCipher({key: secretKey, digestAlgo, ...opts})
  
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
        format = opts.format || 'mgs4'

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

  if(DEBUG) console.debug("Info password chiffres par fingerprint : %O", cles)
  var commandeMaitrecles = {
    domaine, identificateurs_document,
    hachage_bytes, format,
    // iv, tag, 
    ...meta,
    cles, _partition: partition
  }

  return commandeMaitrecles
}

async function chiffrerDocument(doc, domaine, certificatChiffragePem, identificateurs_document, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(DEBUG) console.debug("Chiffrer document %O\nopts: %O", doc, opts)
  // if(DEBUG) console.debug("Verification du certificat pour chiffrer la cle")
  // const {publicKey: clePublique, fingerprint} = await _getPublicKeyFromCertificat(certificatChiffragePem, opts)

  var _doc = opts.nojson?doc:stringify(doc)  // string
  const typeBuffer = opts.type || 'utf-8'
  if(typeBuffer == 'binary') {
    // Rien a faire
  } else if(typeof(TextEncoder) !== 'undefined') {
    _doc = new TextEncoder().encode(_doc)  // buffer
  } else {
    _doc = Buffer.from(_doc, typeBuffer)
  }

  const certForge = forgePki.certificateFromPem(certificatChiffragePem)
  const fingerprintCert = await hacherCertificat(certForge)
  const clePublique = certForge.publicKey
  const optsChiffrage = {...opts}
  if(clePublique.keyType === '1.3.101.112') {
    // Format EdDSA25519
    optsChiffrage.clePubliqueEd25519 = clePublique.publicKeyBytes
    console.debug("Cle publique Ed25519, opts : %O", optsChiffrage)
  }

  const infoDocumentChiffre = await chiffrer(_doc, optsChiffrage)
  const meta = infoDocumentChiffre.meta

  if(DEBUG) console.debug("Document chiffre : %O", infoDocumentChiffre)

  const ciphertextString = base64.encode(infoDocumentChiffre.ciphertext)
  
  const cleSecrete = infoDocumentChiffre.secretKey

  const certificatsAdditionnels = opts.certificats || []
  const certificatsChiffrage = [certificatChiffragePem, ...certificatsAdditionnels]
  console.debug("Certificats chiffrage : %O", certificatsChiffrage)
  const commandeMaitrecles = await preparerCommandeMaitrecles(
    certificatsChiffrage, cleSecrete, domaine,
    meta.hachage_bytes, meta.iv, meta.tag, identificateurs_document,
    opts
  )

  // Override cle secrete chiffree pour certificat avec secret pour rederiver la cle (plus court)
  if(infoDocumentChiffre.secretChiffre) {
    const clesChiffrees = commandeMaitrecles.cles
    clesChiffrees[fingerprintCert] = infoDocumentChiffre.secretChiffre
  }

  return {ciphertext: ciphertextString, commandeMaitrecles}
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

async function updateChampsChiffres(docChamps, ref_hachage_bytes, secretKey, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG
  const cipherAlgo = opts.cipherAlgo || opts.format || 'mgs4',
        digestAlgo = opts.digestAlgo || 'blake2b-512'
  
  if(DEBUG) console.debug("updateChampsChiffres Chiffrer document %O\nopts: %O", docChamps, opts)

  const docBytes = new TextEncoder().encode(stringify(docChamps).normalize())
  
  // Chiffrer
  const chiffreur = getCipher(cipherAlgo)
  if(!chiffreur) throw new Error(`Algorithme de chiffrage (${cipherAlgo}) non supporte`)
  const infoDocumentChiffre = await chiffreur.encrypt(docBytes, {key: secretKey, digestAlgo})
  if(DEBUG) console.debug("updateChampsChiffres Document chiffre ", infoDocumentChiffre)
  const ciphertextString = base64.encode(infoDocumentChiffre.ciphertext)

  return {data_chiffre: ciphertextString, header: infoDocumentChiffre.header, format: infoDocumentChiffre.format, ref_hachage_bytes}
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
  updateChampsChiffres,
}
