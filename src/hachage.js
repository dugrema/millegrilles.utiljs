// Module de hachage, utilise subtle dans le navigateur lorsque c'est approprie
// Fallback sur node-forge
// const stringify = require('json-stable-stringify')
const multihash = require('multihashes')
const multibase = require('multibase')
const {util: forgeUtil, md: forgeMd, asn1: forgeAsn1, pki: forgePki} = require('@dugrema/node-forge')

// Hacheurs optimises pour la plateforme (C++, WASM, etc)
// format: { algo: constructor }
// exemple: const hacheurInstance = new _hacheurs['blake2s-256']()
//          await hacheurInstance.update(buffer)
//          const digestBuffer = await hacheurInstance.finalize()  // Retourne Buffer
//             ... ou ...
//          const digestBuffer = await hacheurInstance.digest(buffer)
var _hacheurs = {}

export function setHacheurs(hacheurs) {
  console.debug("Set Hacheurs : %O", hacheurs)
  _hacheurs = hacheurs
}

// // Charger subtle si disponible dans le navigateur
// function detecterSubtle() {
//   if( typeof(window) !== 'undefined' && window.crypto) return window.crypto.subtle
//   return null
// }
// const _subtle = detecterSubtle()

/**
 * Calcule le hachage du buffer, retourne le multihash encode sous forme de multibase (str).
 * opts par defaut: hashingCode: 'blake2b-512', encoding: 'base58btc'
 * @param {*} valeur Buffer en parametre
 * @param {*} opts {hashingCode str, encoding str}
 * @returns 
 */
export async function hacher(valeur, opts) {
  opts = opts || {}
  const hashingCode = opts.hashingCode || 'blake2b-512'
  const encoding = opts.encoding || 'base58btc'

  // Convertir la valeur en ArrayBuffer
  // console.debug(`Type de la valeur : ${typeof(valeur)}`)

  // Hacher la valeur
  const digestView = await calculerDigest(valeur, hashingCode)

  // Creer le multihash
  const mhValeur = multihash.encode(digestView, hashingCode)

  // Encoder en base58btc avec multibase
  var mbValeur = multibase.encode(encoding, mhValeur)
  mbValeur = String.fromCharCode.apply(null, mbValeur)

  return mbValeur
}

export async function calculerDigest(valeur, hashingCode) {
  const hacheurConstructor = _hacheurs[hashingCode]
  let digest
  if(hacheurConstructor) {
    const hacheur = await hacheurConstructor()
    // Utiliser subtle dans le navigateur (native)
    digest = await hacheur.digest(valeur)
  } else {
    // Fallback sur node-forge
    digest = _calculerHachageForge(valeur, {hash: hashingCode})
  }
  const digestView = new Uint8Array(digest)
  return digestView
}

// function _calculerHachageSubtle(valeur, opts) {
//   var hachageSubtle = opts.hash || 'sha2-512'

//   if(typeof(valeur) === 'string') {
//     valeur = new TextEncoder().encode(valeur)
//   }

//   if(hachageSubtle.indexOf('sha2-') > -1) {
//     hachageSubtle = hachageSubtle.replace('sha2-', 'sha-')
//   } else if(hachageSubtle.indexOf('sha') > -1 && hachage.indexOf('-') == -1) {
//     hachageSubtle = hachageSubtle.replace('sha', 'sha-')
//   }

//   // console.debug("Hachage subtle avec algo : %O", hachageSubtle)
//   return _subtle.digest(hachageSubtle, valeur)  // Promise
// }

function _calculerHachageForge(valeur, opts) {
  var hachage = opts.hash || 'sha2-512'

  const fonctionHachage = _mapFonctionHachageForge(hachage)

  if(typeof(valeur) === 'string') {
    valeur = forgeUtil.encodeUtf8(valeur)
  } else {
    // Convertir AB vers byte string
    valeur = forgeUtil.createBuffer(valeur, 'raw').getBytes()
  }

  // console.debug("Valeur : %O", valeur)

  var resultatHachage = fonctionHachage.create()
    .update(valeur)
    .digest()
    .getBytes()

  return Buffer.from(resultatHachage, 'binary')
}

function _mapFonctionHachageForge(hachage) {
  let fonctionHachage
  if(hachage === 'sha2-512') {
    fonctionHachage = forgeMd.sha512
  } else if(hachage === 'sha2-256') {
    fonctionHachage = forgeMd.sha256
  } else {
    throw new Error(`Fonction hachage non supportee : ${hachage}`)
  }
  return fonctionHachage
}

export async function verifierHachage(hachageMultibase, valeur, opts) {
  opts = opts || {}

  const mbBytes = multibase.decode(hachageMultibase)
  const mh = multihash.decode(mbBytes)

  const algo = mh.name
  const digest = mh.digest

  const hacheurConstructor = _hacheurs[algo]
  let digestCalcule
  if(hacheurConstructor) {
    const hacheur = await hacheurConstructor()
    // Utiliser subtle dans le navigateur (native)
    digestCalcule = await hacheur.digest(valeur)
  } else {
    // Fallback sur node-forge
    digestCalcule = _calculerHachageForge(valeur, {hash: algo})
  }

  digestCalcule = new Uint8Array(digestCalcule)

  if( comparerArraybuffers(digest, digestCalcule) ) {
    return true
  } else {
    throw new Error("Erreur hachage, mismatch")
  }
}

export function comparerArraybuffers(buf1, buf2) {
  // https://stackoverflow.com/questions/21553528/how-to-test-for-equality-in-arraybuffer-dataview-and-typedarray
  if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Uint8Array(buf1);
    var dv2 = new Uint8Array(buf2);
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
}

// Faire await sur .ready avant d'utiliser
export class Hacheur {
  constructor(opts) {
    opts = opts || {}
    this.encoding = opts.encoding || 'base58btc'
    this.hashingCode = opts.hashingCode || opts.hash || 'blake2b-512'
    this._digest = null
    this.mh = null

    const constructeur = _hacheurs[this.hashingCode]
    this.ready = constructeur().then(digester=>this._digester=digester)

    this._textEncoder = new TextEncoder()
  }

  async update(data) {
    if(typeof(data) === 'string') {
      // data = forgeUtil.encodeUtf8(data)
      data = this._textEncoder.encode(data)
    } else {
      // Convertir AB vers byte string
      // data = forgeUtil.createBuffer(data, 'raw').getBytes()
    }
    await this._digester.update(data)
  }

  async digest() {
    if(this._digest) return this._digest

    this._digest = await this._digester.finalize()

    this._digester = null
    return this._digest
  }

  async finalize() {
    if(this.mh) return this.mh

    const digest = await this.digest()
    const digestView = new Uint8Array(digest)

    // Creer le multihash
    const mhValeur = multihash.encode(digestView, this.hashingCode)

    // Encoder en base58btc avec multibase
    var mbValeur = multibase.encode(this.encoding, mhValeur)
    this.mh = String.fromCharCode.apply(null, mbValeur)

    return this.mh
  }
}

// Faire await .ready avant d'utiliser
export class VerificateurHachage {

  constructor(hachage) {
    const mb = multibase.decode(hachage)
    this.mh = multihash.decode(mb)

    // Creer contexte de hachage
    const hashingCode = this.mh.name
    // const fonctionHachage = _mapFonctionHachageForge(hashingCode)
    // this._digester = fonctionHachage.create()
    const constructeur = _hacheurs[hashingCode]
    this.ready = constructeur().then(digester=>this._digester=digester)
    this._textEncoder = new TextEncoder()
  }

  async update(data) {
    if(typeof(data) === 'string') {
      // data = forgeUtil.encodeUtf8(data)
      data = this._textEncoder.encode(data)
    } else {
      // Convertir AB vers byte string
      // data = forgeUtil.createBuffer(data, 'raw').getBytes()
    }
    await this._digester.update(data)
  }

  async digest() {
    if(this._digest) return this._digest

    this._digest = this._digester.finalize()
    // var resultatHachage = this._digester.digest().getBytes()
    // this._digest = Buffer.from(resultatHachage, 'binary')
    this._digester = null
    return this._digest
  }

  async verify() {
    var digestCalcule = await this.digest()
    digestCalcule = new Uint8Array(digestCalcule)

    const digestRecu = this.mh.digest

    if( comparerArraybuffers(digestRecu, digestCalcule) ) {
      return true
    } else {
      throw new Error("Erreur hachage, mismatch")
    }
  }

}

export function hacherCertificat(cert) {
  if(typeof(cert) === 'string') {
    cert = forgePki.certificateFromPem(cert)
  }
  const derBytes = forgeAsn1.toDer(forgePki.certificateToAsn1(cert)).getBytes()
  const certArray = new Uint8Array(Buffer.from(derBytes, 'binary'))

  // console.debug("!!! Hacher certificat : %O, hacheurs disponibles : %O", certArray, Object.keys(_hacheurs))

  // Retourner promise
  return hacher(certArray, {hashingCode: 'blake2s-256'})
}

// export function hacherPassword(password, iterations, salt) {
//   // Retourne promise
//   if(_subtle) {
//     // crypto.subtle est disponible (navigateur)
//     return hacherPasswordSubtle(password, iterations, salt)
//   }
//   return hacherPasswordCrypto(password, iterations, salt)
// }

// export async function hacherPasswordCrypto(password, iterations, salt, opts) {
//   opts = opts || {}
//   const hash = opts.hash || 'sha256',
//         keySize = opts.keySize || 32

//   // console.debug("Calculer password iterations : %d, salt : %O", iterations, salt)
//   var saltBuffer = multibase.decode(salt)
//   // console.debug("Salt buffer : %O", saltBuffer)

//   var key = await new Promise((resolve, reject)=>{
//     cryptoPbkdf2(password, saltBuffer, iterations, keySize, hash, (err, derivedKey)=>{
//       if(err) return reject(err)
//       resolve(derivedKey)
//     })
//   })

//   // console.debug("Key : %O", key)
//   key = new Uint8Array(Buffer.from(key, 'binary'))
//   // console.debug("Key derivee : %O", key)
//   const exportedKey = String.fromCharCode.apply(null, multibase.encode('base64', key))

//   return exportedKey
// }

// export async function hacherPasswordSubtle(password, iterations, salt) {
//   var saltBuffer = multibase.decode(salt)

//   let enc = new TextEncoder()
//   const keyMaterial = await _subtle.importKey(
//     "raw",
//     enc.encode(password),
//     {name: "PBKDF2"},
//     false,
//     ["deriveBits", "deriveKey"]
//   )

//   const key = await window.crypto.subtle.deriveKey(
//     {
//       "name": "PBKDF2",
//       salt: saltBuffer,
//       iterations,
//       "hash": "SHA-256"
//     },
//     keyMaterial,
//     { "name": "AES-GCM", "length": 256},
//     true,
//     [ "encrypt", "decrypt" ]
//   )

//   console.debug("Key : %O", key)

//   var exportedKey = Buffer.from(await _subtle.exportKey('raw', key))

//   console.debug("Key exportee : %O", exportedKey)
//   exportedKey = String.fromCharCode.apply(null, multibase.encode('base64', exportedKey))

//   return exportedKey
// }

// export function hacherMessageSync(message, opts) {
//   opts = opts || {}
  
//   const messageFiltre = {}
//   for(let key in message) {
//     if(!key.startsWith('_')) {
//       messageFiltre[key] = message[key]
//     }
//   }

//   const messageJsonStable = stringify(message)
//   return _calculerHachageForge(messageJsonStable, opts)
// }

export default {
  hacher, verifierHachage, 
  Hacheur, VerificateurHachage, 
  calculerDigest,
  hacherCertificat, comparerArraybuffers,
  // hacherPassword, 
  // hacherPasswordCrypto, 
  // hacherPasswordSubtle,
  // hacherMessageSync,
}