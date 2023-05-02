const stringify = require('json-stable-stringify')
const { pki: forgePki } = require('@dugrema/node-forge')

const { hacher, hacherCertificat, setHacheurs } = require('./hachage')
const { chargerPemClePriveeEd25519 } = require('./certificats')
const { KIND_REQUETE, KIND_COMMANDE, KIND_TRANSACTION, KIND_EVENEMENT, MESSAGE_KINDS } = require('./constantes')

const BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"

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
  opts = opts || {}

  const hashingCode = opts.hashingCode || 'blake2s-256',
        encodingParam = opts.encoding || 'hex'
  let bytesOnly = opts.bytesOnly

  // Stringify en json trie, encoder en UTF_8
  const messageString = stringify(message).normalize()
  const messageBuffer = new Uint8Array(Buffer.from(new TextEncoder().encode(messageString)))

  // Retourner promise de hachage
  let encoding = encodingParam
  if(encodingParam === 'hex') {
    encoding = 'base16'
    bytesOnly = true
  }
  const hachage = await hacher(messageBuffer, {hashingCode, encoding, ...opts, bytesOnly})
  if(opts.bytesOnly) return hachage
  if(encodingParam === 'hex') return Buffer.from(hachage).toString('hex')

  return hachage
}

class FormatteurMessage {

  constructor(chainePem, cle, opts) {
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
    this.publicKey = Buffer.from(this.cert.publicKey.publicKeyBytes).toString('hex')

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
          if(opts.DEBUG) console.debug("FormatteurMessage Fingerprint certificat local recalcule: %s", fingerprint)
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
    const enveloppeMessage = await this._formatterInfoMessage(kind, message, opts)

    return enveloppeMessage
  }

  async _formatterInfoMessage(kind, message, opts) {
    opts = opts || {}

    const dechiffrage = opts.dechiffrage

    const messageString = stringify(message)

    const estampille = Math.floor(new Date() / 1000)

    if(opts.DEBUG) console.debug("utiljs.formatteruMessage._formatterInfoMessage publicKey ", this.publicKey)

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

    if([
      MESSAGE_KINDS.KIND_REQUETE, MESSAGE_KINDS.KIND_COMMANDE, MESSAGE_KINDS.KIND_TRANSACTION, 
      MESSAGE_KINDS.KIND_EVENEMENT, MESSAGE_KINDS.KIND_TRANSACTION_MIGREE, 
      MESSAGE_KINDS.KIND_TRANSACTION_MIGREE, MESSAGE_KINDS.KIND_COMMANDE_INTER_MILLEGRILLE
      ].includes(kind)) 
      {
      // Routage
      const routage = {}
      if(opts.action) routage.action = opts.action
      if(opts.domaine) routage.domaine = opts.domaine
      if(opts.partition) routage.partition = opts.partition

      enveloppeMessage.routage = routage
      messageHachage.push(routage)
    }

    if([MESSAGE_KINDS.KIND_COMMANDE_INTER_MILLEGRILLE]) {
      enveloppeMessage.origine = this.idmg
      messageHachage.push(this.idmg)

      if(!dechiffrage) throw new Error('kind:8 requiert un contenu chiffre et element dechiffrage')
      enveloppeMessage.dechiffrage = dechiffrage
      messageHachage.push(dechiffrage)
    }

    // Calculer hachage (id)
    const hachageMessage = await hacherMessage(messageHachage)
    enveloppeMessage.id = hachageMessage

    // Calculer signature
    const signature = this.signateurMessage.signer(hachageMessage)
    enveloppeMessage.sig = signature

    if(opts.attacherCertificat || opts.ajouterCertificat) {
      enveloppeMessage['certificat'] = this.chainePem
      if([MESSAGE_KINDS.KIND_COMMANDE_INTER_MILLEGRILLE].includes(kind)) {
        console.warn('utiljs.FormatteurMessage todo - ajouter CA')
      }
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
}
