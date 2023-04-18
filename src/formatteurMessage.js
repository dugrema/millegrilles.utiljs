const debug = require('debug')('millegrilles:common:formatteurMessage')
const stringify = require('json-stable-stringify')
const multibase = require('multibase')
const { pki: forgePki } = require('@dugrema/node-forge')
const { v4: uuidv4 } = require('uuid')

const { hacher, calculerDigest, hacherCertificat, setHacheurs } = require('./hachage')
// import { detecterSubtle } from './chiffrage'
const { chargerPemClePriveeEd25519 } = require('./certificats')
const { KIND_REQUETE, KIND_COMMANDE, KIND_TRANSACTION, KIND_EVENEMENT } = require('./constantes')

const BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
const VERSION_SIGNATURE = 0x2

// const {subtle: _subtle} = detecterSubtle()

function setHacheurs2(hacheurs) {
  setHacheurs(hacheurs)
}

function splitPEMCerts(certs) {
  var splitCerts = certs.split(BEGIN_CERTIFICATE).map(c=>{
    return (BEGIN_CERTIFICATE + c).trim()
  })
  return splitCerts.slice(1)
}

function formatterDateString(date) {
  let year = date.getUTCFullYear();
  let month = date.getUTCMonth() + 1; if(month < 10) month = '0'+month;
  let day = date.getUTCDate(); if(day < 10) day = '0'+day;
  let hour = date.getUTCHours(); if(hour < 10) hour = '0'+hour;
  const dateFormattee = "" + year + month + day + hour;
  return dateFormattee
}

async function hacherMessage(message, opts) {
  // opts = opts || {}

  // // Copier le message sans l'entete
  // const copieMessage = {}
  // for(let key in message) {
  //   if ( key !== 'en-tete' && ! key.startsWith('_') ) {
  //     copieMessage[key] = message[key]
  //   }
  // }

  // Stringify en json trie, encoder en UTF_8
  const messageString = stringify(message).normalize()
  console.debug("hachageMessage Hacher:\n", messageString)
  const messageBuffer = new Uint8Array(Buffer.from(new TextEncoder().encode(messageString)))

  // console.debug("hacherMessage: messageBuffer = %O", messageBuffer)

  // Retourner promise de hachage
  const hachage = await hacher(messageBuffer, {hashingCode: 'blake2s-256', encoding: 'base16', ...opts})
  // Enlever 9 premiers caracteres (1 multibase marker, 4 bytes multihash)
  return hachage.slice(9)
}

class FormatteurMessage {

  constructor(chainePem, cle, opts) {
    // console.debug("FormatteurMessage opts : %O", opts)
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
    this.publicKey = this.cert.publicKey.publicKeyBytes.toString('hex')

    // Le IDMG est place dans le champ organizationName du subject
    // Note: on assume que le certificat a deja ete valide.
    this.idmg = this.cert.subject.getField("O").value

    // Permettre de conserver le contexte et attendre initialisation au besoin
    const this_inst = this
    this._promisesInit = []

    // Calculer le fingerprint du certificat - il sera insere dans l'en-tete
    this._promisesInit.push(
      hacherCertificat(this.cert)
        .then(fingerprint=>{
          // console.debug("Fingerprint certificat local recalcule: %s", fingerprint)
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
    return new SignateurMessageEd25519(cle)
  }

  async formatterMessage(kind, message, opts) {
    opts = opts || {}
    if(isNaN(Number.parseInt(kind))) throw new Error('formatterMessage param kind doit etre un int')
    if(!this.fingerprint) throw new Error("formatteurMessage.formatterMessage Certificat n'est pas initialise")
    if(this.err) throw new Error(`Erreur initialisation FormatteurMessage : ${this.err}` )

    // Formatte le message
    // var messageCopy = {...message}

    const enveloppeMessage = await this._formatterInfoMessage(kind, message, opts)

    // // Hacher le message
    // const hachageMessage = await hacherMessage(messageCopy)
    // messageCopy['en-tete'].hachage_contenu = hachageMessage

    // // Signer le message
    // const signature = await this.signateurMessage.signer(messageCopy)
    // messageCopy['_signature'] = signature

    return enveloppeMessage
  }

  async _formatterInfoMessage(kind, message, opts) {
    opts = opts || {}
    // const domaineAction = opts.domaine

    // const version = opts.version || 1
    // const uuidTransaction = opts.uuidTransaction || uuidv4()

    const messageString = stringify(message)

    const estampille = Math.floor(new Date() / 1000)

    const messageHachage = [
      this.publicKey,
      estampille,
      kind,
      messageString,
    ]
    const enveloppeMessage = {
      pubkey: this.publicKey,
      estampille,
      kind,
      contenu: messageString,
    }

    if([KIND_REQUETE, KIND_COMMANDE, KIND_TRANSACTION, KIND_EVENEMENT].includes(kind)) {
      // Routage
      const routage = {}
      if(opts.action) routage.action = opts.action
      if(opts.domaine) routage.domaine = opts.domaine
      if(opts.partition) routage.partition = opts.partition

      enveloppeMessage.routage = routage
      messageHachage.push(routage)
    }

    // Calculer hachage (id)
    const hachageMessage = await hacherMessage(messageHachage)
    enveloppeMessage.id = hachageMessage

    // Calculer signature
    const signature = this.signateurMessage.signer(hachageMessage)
    enveloppeMessage.sig = signature

    // var entete = message['en-tete'] || {}
    // entete = {...entete}  // Copie
    // message['en-tete'] = entete

    // if(domaineAction) {
    //   entete.domaine = domaineAction
    // }
    // if(opts.action) {
    //   entete.action = opts.action
    // }
    // if(opts.partition) {
    //   entete.partition = opts.partition
    // }
    // entete.idmg = this.idmg
    // entete.uuid_transaction = uuidTransaction
    // entete.estampille = tempsLecture
    // entete.fingerprint_certificat = this.fingerprint
    // entete.hachage_contenu = ''
    // entete.version = version

    if(opts.attacherCertificat || opts.ajouterCertificat) {
      enveloppeMessage['certificat'] = this.chainePem
    }

    return enveloppeMessage
  }
}

class FormatteurMessageEd25519 extends FormatteurMessage {

  // Override avec signateur ed25519
  async initialiserSignateur(cle) {
    return new SignateurMessageEd25519(cle)
  }

}

class SignateurMessageEd25519 {

  constructor(cle) {
    if (typeof(cle) === 'string') {
      // console.debug("Charger cle PEM : %O", cle)
      this.cle = chargerPemClePriveeEd25519(cle)
      // console.debug('Cle privee chargee: %O', this.cle)
    } else if (cle.privateKeyBytes) {
      // Format interne
      this.cle = cle
    } else {
      throw new Error("Format cle privee inconnu")
    }
  }

  // async signer(message) {
  //   const copieMessage = {}
  //   for(let key in message) {
  //     if ( ! key.startsWith('_') ) {
  //       copieMessage[key] = message[key]
  //     }
  //   }
  //   // Stringify en json trie
  //   const encoder = new TextEncoder()
  //   const messageBuffer = new Uint8Array(Buffer.from(encoder.encode(stringify(copieMessage).normalize())))

  //   // Calculer digest du message
  //   const digestView = await calculerDigest(messageBuffer, 'blake2b-512')

  //   // Signer avec la cle
  //   const signatureAvecCle = this.cle.sign(digestView)
  //   const signature = Buffer.from(signatureAvecCle, 'binary')
  //   const signatureBuffer = new Uint8Array(signature.length + 1)
  //   signatureBuffer.set([VERSION_SIGNATURE], 0)
  //   signatureBuffer.set(signature, 1)

  //   const mbValeur = multibase.encode('base64', signatureBuffer)
  //   const mbString = String.fromCharCode.apply(null, mbValeur)

  //   return mbString
  // }

  signer(hachage) {
    if(typeof(hachage) === 'string') hachage = Buffer.from(hachage, 'hex')
    const signatureAvecCle = this.cle.sign(hachage)
    const signatureBuffer = Buffer.from(signatureAvecCle, 'binary')
    const signatureString = signatureBuffer.toString('hex')
    return signatureString
  }

}

module.exports = {
  FormatteurMessage, FormatteurMessageEd25519, 
  hacherMessage, 
  SignateurMessageEd25519,
  splitPEMCerts, 
  formatterDateString,
  //SignateurMessageSubtle,
}
