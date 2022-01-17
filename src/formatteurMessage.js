import debugLib from 'debug'
import stringify from 'json-stable-stringify'
import multibase from 'multibase'
import {pki as forgePki, md as forgeMd, util as forgeUtil, mgf as forgeMgf, pss as forgePss, ed25519} from '@dugrema/node-forge'
import {v4 as uuidv4} from 'uuid'

import {hacher, calculerDigest, hacherCertificat, setHacheurs} from './hachage'
import {detecterSubtle} from './chiffrage'
import {chargerPemClePriveeEd25519} from './certificats'

const debug = debugLib('millegrilles:common:formatteurMessage')

const BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
const VERSION_SIGNATURE = 0x2

const {subtle: _subtle} = detecterSubtle()

export function setHacheurs2(hacheurs) {
  setHacheurs(hacheurs)
}

export function splitPEMCerts(certs) {
  var splitCerts = certs.split(BEGIN_CERTIFICATE).map(c=>{
    return (BEGIN_CERTIFICATE + c).trim()
  })
  return splitCerts.slice(1)
}

export function hacherMessage(message, opts) {
  opts = opts || {}

  // Copier le message sans l'entete
  const copieMessage = {}
  for(let key in message) {
    if ( key !== 'en-tete' && ! key.startsWith('_') ) {
      copieMessage[key] = message[key]
    }
  }

  // Stringify en json trie, encoder en UTF_8
  const encoder = new TextEncoder()
  const messageBuffer = encoder.encode(stringify(copieMessage))

  // debug("hacherMessage: messageBuffer = %O", messageBuffer)

  // Retourner promise de hachage
  return hacher(messageBuffer, {hashingCode: 'blake2s-256', encoding: 'base64', ...opts})

}

export class FormatteurMessage {

  constructor(chainePem, cle, opts) {
    console.debug("FormatteurMessage opts : %O", opts)
    opts = opts || {}

    if(opts.hacheurs) setHacheurs2(opts.hacheurs)

    if( typeof(chainePem) === 'string' ) {
      this.chainePem = splitPEMCerts(chainePem)
    } else {
      this.chainePem = chainePem
    }

    this.err = ''

    // Charger une instance de certificat
    this.cert = forgePki.certificateFromPem(this.chainePem[0])

    // Le IDMG est place dans le champ organizationName du subject
    // Note: on assume que le certificat a deja ete valide.
    this.idmg = this.cert.issuer.getField("O").value

    // Permettre de conserver le contexte et attendre initialisation au besoin
    const this_inst = this
    this._promisesInit = []

    // Calculer le fingerprint du certificat - il sera insere dans l'en-tete
    this._promisesInit.push(
      hacherCertificat(this.cert)
        .then(fingerprint=>{
          console.debug("Fingerprint certificat local recalcule: %s", fingerprint)
          this_inst.fingerprint = fingerprint
        })
    )

    // Creer une instance de signateur
    this._promisesInit.push(
      this.initialiserSignateur(cle)
        .then(signateur=>{
          this.signateurMessage = signateur
        })
    )

    // Supporter attribut pour indiquer que la preparation est completee
    this._ready = false
    Promise.all(this_inst._promisesInit).then(_=>{
      this_inst._promisesInit = null
      this_inst._ready = true
    }).catch(err=>{
      console.error("FormatteurMessage Erreur initialisation signateur : %O", err)
      this_inst.err = err
    })
  }

  async ready() {
    if(this._promisesInit) {
      await Promise.all(this._promisesInit)
    }
    return this._ready
  }

  async initialiserSignateur(cle) {
    return new SignateurMessage(cle)
  }

  async formatterMessage(message, domaineAction, opts) {
    if(!this.fingerprint) throw new Error("formatteurMessage.formatterMessage Certificat n'est pas initialise")
    if(this.err) throw new Error(`Erreur initialisation FormatteurMessage : ${this.err}` )

    // Formatte le message
    var messageCopy = {...message}

    messageCopy = this._formatterInfoMessage(messageCopy, domaineAction, opts)

    // Hacher le message
    const hachageMessage = await hacherMessage(messageCopy)
    messageCopy['en-tete'].hachage_contenu = hachageMessage

    // Signer le message
    const signature = await this.signateurMessage.signer(messageCopy)
    messageCopy['_signature'] = signature

    return messageCopy
  }

  _formatterInfoMessage(message, domaineAction, opts) {
    opts = opts || {}

    const version = opts.version || 1
    const uuidTransaction = opts.uuidTransaction || uuidv4()

    const dateUTC = (Date.now() / 1000)  // + new Date().getTimezoneOffset() * 60
    const tempsLecture = Math.trunc(dateUTC)

    var entete = message['en-tete'] || {}
    entete = {...entete}  // Copie
    message['en-tete'] = entete

    entete.domaine = domaineAction
    if(opts.action) {
      entete.action = opts.action
    }
    if(opts.partition) {
      entete.partition = opts.partition
    }
    entete.idmg = this.idmg
    entete.uuid_transaction = uuidTransaction
    entete.estampille = tempsLecture
    entete.fingerprint_certificat = this.fingerprint
    entete.hachage_contenu = ''
    entete.version = version

    if(opts.attacherCertificat || opts.ajouterCertificat) {
      message['_certificat'] = this.chainePem
    }

    return message
  }
}

export class FormatteurMessageEd25519 extends FormatteurMessage {

  // Override avec signateur ed25519
  async initialiserSignateur(cle) {
    return new SignateurMessageEd25519(cle)
  }

}

// export class FormatteurMessageSubtle extends FormatteurMessage {

//   // Override avec signateur subtle
//   async initialiserSignateur(cle) {
//     return new SignateurMessageSubtle(cle)
//   }

// }

export class SignateurMessageEd25519 {

  constructor(cle) {
    if (typeof(cle) === 'string') {
      console.debug("Charger cle PEM : %O", cle)
      this.cle = chargerPemClePriveeEd25519(cle)
      console.debug('Cle privee chargee: %O', this.cle)
    } else if (cle.privateKeyBytes) {
      // Format interne
      this.cle = cle
    } else {
      throw new Error("Format cle privee inconnu")
    }
  }

  async signer(message) {
    const copieMessage = {}
    for(let key in message) {
      if ( ! key.startsWith('_') ) {
        copieMessage[key] = message[key]
      }
    }
    // Stringify en json trie
    const encoder = new TextEncoder()
    const messageBuffer = new Uint8Array(Buffer.from(encoder.encode(stringify(copieMessage))))

    // Calculer digest du message
    const digestView = await calculerDigest(messageBuffer, 'blake2b-512')

    // Signer avec la cle
    const signatureAvecCle = this.cle.sign(digestView)
    const signature = Buffer.from(signatureAvecCle, 'binary')
    const signatureBuffer = new Uint8Array(signature.length + 1)
    signatureBuffer.set([VERSION_SIGNATURE], 0)
    signatureBuffer.set(signature, 1)

    const mbValeur = multibase.encode('base64', signatureBuffer)
    const mbString = String.fromCharCode.apply(null, mbValeur)

    return mbString
  }

}

// export class SignateurMessage {

//   constructor(cle) {
//     if(cle.privateKeyBytes) {
//       // Format interne
//       this.cle = cle
//     } else {
//       this.cle = chargerPemClePriveeEd25519(cle)
//     }
//   }

//   async signer(message) {
//     const copieMessage = {}
//     for(let key in message) {
//       if ( ! key.startsWith('_') ) {
//         copieMessage[key] = message[key]
//       }
//     }
//     // Stringify en json trie
//     const encoder = new TextEncoder()
//     const messageBuffer = new Uint8Array(Buffer.from(encoder.encode(stringify(copieMessage))))

//     // Calculer digest du message
//     const digestView = await calculerDigest(messageBuffer, 'sha2-512')

//     const digestInfo = {digest: _=>forgeUtil.createBuffer(digestView, 'raw')}
//     let pss = forgePss.create({
//       md: forgeMd.sha512.create(),
//       mgf: forgeMgf.mgf1.create(forgeMd.sha512.create()),
//       saltLength: 64
//     })

//     // Signer avec la cle
//     const signature = forgeUtil.encode64(this.cle.sign(digestInfo, pss));
//     var signatureStringBuffer = this.cle.sign(digestInfo, pss)
//     const versionBuffer = forgeUtil.createBuffer()
//     versionBuffer.putByte(VERSION_SIGNATURE)
//     versionBuffer.putBytes(signatureStringBuffer)
//     signatureStringBuffer = versionBuffer.getBytes()
//     console.debug("Version + Signature buffer digest : %O", versionBuffer)
//     console.debug("Signature string buffer : %O", signatureStringBuffer)
//     const signatureBuffer = Buffer.from(signatureStringBuffer, 'binary')

//     signatureBuffer.set([VERSION_SIGNATURE], 0)
//     signatureBuffer.set(signature, 1)

//     const mbValeur = multibase.encode('base64', signatureBuffer)
//     const mbString = String.fromCharCode.apply(null, mbValeur)

//     return mbString
//   }

// }

// export class SignateurMessageSubtle {

//   constructor(cleSubtle) {
//     this.cle = cleSubtle
//   }

//   async signer(message) {

//     const copieMessage = {}
//     for(let key in message) {
//       if ( ! key.startsWith('_') ) {
//         copieMessage[key] = message[key]
//       }
//     }
//     // Stringify en json trie
//     const messageString = stringify(copieMessage)

//     const clePrivee = this.cle

//     // Calcul taille salt:
//     // http://bouncy-castle.1462172.n4.nabble.com/Is-Bouncy-Castle-SHA256withRSA-PSS-compatible-with-OpenSSL-RSA-PSS-padding-with-SHA256-digest-td4656843.html
//     // Salt - changer pour 64, maximum supporte sur le iPhone
//     const modulusLength = clePrivee.algorithm.modulusLength
//     const saltLength = 64 // (modulusLength - 512) / 8 - 2

//     const paramsSignature = {
//       name: clePrivee.algorithm.name,
//       saltLength,
//     }

//     const encoder = new TextEncoder()
//     const contenuAb = encoder.encode(messageString)

//     var signature = await _subtle.sign(paramsSignature, clePrivee, contenuAb)

//     // Ajouter version
//     const bufferVersion = new ArrayBuffer(1)
//     const viewBuffer = new Uint8Array(bufferVersion)
//     viewBuffer.set([VERSION_SIGNATURE], 0)
//     // console.debug("Signature buffer info : %O", signature)
//     signature = Buffer.concat([Buffer.from(bufferVersion), Buffer.from(signature)])

//     const mbValeur = multibase.encode('base64', new Uint8Array(signature))
//     const mbString = String.fromCharCode.apply(null, mbValeur)

//     return mbString
//   }

// }

export default {
  FormatteurMessage, FormatteurMessageEd25519, 
  hacherMessage, 
  SignateurMessageEd25519,
  splitPEMCerts, 
  //SignateurMessageSubtle,
}
