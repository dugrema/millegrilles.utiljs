// Module de hachage, utilise subtle dans le navigateur lorsque c'est approprie
// Fallback sur node-forge
const multihash = require('multihashes')
const multibase = require('multibase')
const { pki: forgePki, asn1: forgeAsn1 } = require('@dugrema/node-forge')

// const { pki: forgePki, asn1: forgeAsn1 } = nodeforge

// Hacheurs optimises pour la plateforme (C++, WASM, etc)
// format: { algo: constructor }
// exemple: const hacheurInstance = new _hacheurs['blake2s-256']()
//          await hacheurInstance.update(buffer)
//          const digestBuffer = await hacheurInstance.finalize()  // Retourne Buffer
//             ... ou ...
//          const digestBuffer = await hacheurInstance.digest(buffer)
var _hacheurs = {}

function setHacheurs(hacheurs, opts) {
  opts = opts || {}
  if(opts.DEBUG) console.debug("Set Hacheurs : %O", hacheurs)
  if(opts.update) {
    _hacheurs = {..._hacheurs, ...hacheurs}
  } else {
    _hacheurs = hacheurs
  }
}

/**
 * Calcule le hachage du buffer, retourne le multihash encode sous forme de multibase (str).
 * opts par defaut: hashingCode: 'blake2b-512', encoding: 'base58btc'
 * @param {*} valeur Buffer en parametre
 * @param {*} opts {hashingCode str, encoding str}
 * @returns 
 */
async function hacher(valeur, opts) {
  opts = opts || {}
  const hashingCode = opts.hashingCode || 'blake2b-512'
  const encoding = opts.encoding || 'base58btc'

  // Convertir la valeur en ArrayBuffer
  // console.debug(`Type de la valeur : ${typeof(valeur)}`)

  // Hacher la valeur
  const digestView = await calculerDigest(valeur, hashingCode)

  if(opts.bytesOnly === true || encoding === 'bytes') return digestView  // Retourner les bytes directement

  // Creer le multihash
  const mhValeur = multihash.encode(digestView, hashingCode)

  // Encoder en base58btc avec multibase
  var mbValeur = multibase.encode(encoding, mhValeur)
  mbValeur = String.fromCharCode.apply(null, mbValeur)

  return mbValeur
}

async function calculerDigest(valeur, hashingCode) {
  const hacheurConstructor = _hacheurs[hashingCode]
  let digest
  if(hacheurConstructor) {
    const hacheur = await hacheurConstructor()
    // Utiliser subtle dans le navigateur (native)
    digest = await hacheur.digest(valeur)
  } else {
    const err = new Error(`Hachage ${hashingCode} non disponible`)
    console.error("Erreur algo hachage : %O, algos: %O", err, _hacheurs)
    throw err

    // throw new Error(`Hachage ${hashingCode} non disponible`)
    // console.warn("Hachage %s pas optimise, hacheurs : %O", hashingCode, Object.keys(_hacheurs))
    // // Fallback sur node-forge
    // digest = _calculerHachageForge(valeur, {hash: hashingCode})
  }
  const digestView = new Uint8Array(digest)
  return digestView
}

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

async function verifierHachage(hachageMultibase, valeur, opts) {
  opts = opts || {}

  if(typeof(valeur) === 'string') {
    const encoder = new TextEncoder()
    valeur = encoder.encode(valeur)
  }

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
    const err = new Error(`Hachage ${hashingCode} non disponible`)
    console.error("Erreur algo hachage : %O", err)
    throw err
    // // Fallback sur node-forge
    // digestCalcule = _calculerHachageForge(valeur, {hash: algo})
  }

  digestCalcule = new Uint8Array(digestCalcule)

  if( comparerArraybuffers(digest, digestCalcule) ) {
    return true
  } else {
    throw new Error("Erreur hachage, mismatch")
  }
}

function comparerArraybuffers(buf1, buf2) {
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
// export function Hacheur(opts) {
//   return new HacheurClass(opts)
// }
class Hacheur {
  constructor(opts) {
    opts = opts || {}
    this.DEBUG = opts.DEBUG || false
    this.encoding = opts.encoding || 'base58btc'
    this.hashingCode = opts.hashingCode || opts.hash || 'blake2b-512'
    this._digest = null
    this.mh = null

    const constructeur = _hacheurs[this.hashingCode]
    const inst = constructeur()
    this.ready = Promise.resolve(true)
    if(inst instanceof Promise) {
      this.ready = inst.then( digester => {
        if(this.DEBUG) console.debug("Digester ready : %O", digester)
        this._digester = digester
      })
      if(this.DEBUG) console.debug("ready const", this.ready)
    } else {
      this._digester = inst
    }

    this._textEncoder = new TextEncoder()
  }

  async update(data) {
    await this.ready
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
    if(this.DEBUG) console.debug("Digest pre-calcule : %O", this._digest)
    if(this._digest) return this._digest

    await this.ready
    this._digest = await this._digester.finalize()
    if(this.DEBUG) console.debug("Digest calcule : %O", this._digest)

    if(! 'reset' in this._digester) this._digester = null
    return this._digest
  }

  async finalize() {
    if(this.mh) return this.mh

    const digest = await this.digest()
    const digestView = new Uint8Array(digest)

    if(this.encoding === 'bytes') {
      this.mh = digestView
      return digestView
    }

    // Creer le multihash
    const mhValeur = multihash.encode(digestView, this.hashingCode)

    // Encoder en base58btc avec multibase
    var mbValeur = multibase.encode(this.encoding, mhValeur)
    this.mh = String.fromCharCode.apply(null, mbValeur)

    return this.mh
  }

  async reset() {
    if(this.DEBUG) console.debug("Hacheur reset ", this)
    this._digest = null
    if('reset' in this._digester) {
      await this.ready
      await this._digester.reset()
      if(this.DEBUG) console.debug("Hacheur resette ", this)
    } else {
      throw new Error('reset non supporte')
    }
  }
}

// Faire await .ready avant d'utiliser
class VerificateurHachage {

  constructor(hachage) {
    const mb = multibase.decode(hachage)
    this.mh = multihash.decode(mb)

    const hashingCode = this.mh.name

    // Creer contexte de hachage
    const constructeur = _hacheurs[hashingCode]
    if(!constructeur) throw new Error(`Hachage ${hashingCode} non supporte`)
    const hacheur = constructeur()
    if(hacheur instanceof Promise) {
      this.ready = hacheur.then(digester=>this._digester=digester)
    } else {
      this._digester = hacheur
      this.ready = Promise.resolve(true)
    }

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

async function hacherCertificat(cert) {
  if(typeof(cert) === 'string') {
    cert = forgePki.certificateFromPem(cert)
  }

  const publicKeyBytes = cert.publicKey.publicKeyBytes
  const publicKeyString = Buffer.from(publicKeyBytes).toString('hex')
  // console.debug("!!! hachage.hacherCertificat bytes %O -> %O", publicKeyBytes, publicKeyString)

  return publicKeyString

  // Ancienne methode
  // const derBytes = forgeAsn1.toDer(forgePki.certificateToAsn1(cert)).getBytes()
  // const certArray = new Uint8Array(Buffer.from(derBytes, 'binary'))

  // // console.debug("!!! Hacher certificat : %O, hacheurs disponibles : %O", certArray, Object.keys(_hacheurs))

  // // Retourner promise
  // return hacher(certArray, {hashingCode: 'blake2s-256'})
}

module.exports = {
  hacher, verifierHachage, 
  Hacheur, VerificateurHachage, 
  calculerDigest,
  hacherCertificat, comparerArraybuffers,
  setHacheurs,
}