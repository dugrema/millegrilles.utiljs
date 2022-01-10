import debugLib from 'debug'

import { pki } from '@dugrema/node-forge'
import stringify from 'json-stable-stringify'

import {hacher} from './hachage'
import {verifierIdmg, getIdmg} from './idmg'

const debug = debugLib('millegrilles:forgecommon')

const BEGIN_PUBLIC_KEY  = "-----BEGIN PUBLIC KEY-----",
      END_PUBLIC_KEY    = "-----END PUBLIC KEY-----",
      BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----",
      END_PRIVATE_KEY   = "-----END PRIVATE KEY-----",
      BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----",
      VERSION_IDMG      = 1


export function chiffrerPrivateKey(privateKey, motDePasse) {
  var pem = pki.encryptRsaPrivateKey(privateKey, motDePasse);
  return pem
}

export function sauvegarderPrivateKeyToPEM(privateKey) {
  // Exporte une cle privee Forge en format PKCS8 pour importer dans subtle

  var rsaPrivateKey = pki.privateKeyToAsn1(privateKey);
  // wrap an RSAPrivateKey ASN.1 object in a PKCS#8 ASN.1 PrivateKeyInfo
  var privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);
  // convert a PKCS#8 ASN.1 PrivateKeyInfo to PEM
  var pem = pki.privateKeyInfoToPem(privateKeyInfo);
  return pem
}

export function chiffrerPrivateKeyPEM(privateKeyPEM, motDePasse) {

  const privateKey = pki.privateKeyFromPem(privateKeyPEM);
  var pem = pki.encryptRsaPrivateKey(privateKey, motDePasse);
  // console.debug(pem);

  return pem
}

export function enveloppePEMPublique(clePubliqueStr) {
  return [BEGIN_PUBLIC_KEY, clePubliqueStr, END_PUBLIC_KEY].join('\n')
}

export function enveloppePEMPrivee(clePriveeStr) {
  return [BEGIN_PRIVATE_KEY, clePriveeStr, END_PRIVATE_KEY].join('\n')
}

export function splitPEMCerts(certs) {
  var splitCerts = certs.split(BEGIN_CERTIFICATE).map(c=>{
    return (BEGIN_CERTIFICATE + c).trim()
  })
  return splitCerts.slice(1)
}

export class CertificateStore {

  constructor(caCert, opts) {
    if(!opts) opts = {}

    this.DEBUG = opts.DEBUG

    let parsedCA;
    if(opts.isPEM) {
      parsedCA = pki.certificateFromPem(caCert)
    } else {
      parsedCA = caCert
    }

    if(this.DEBUG) console.debug("Certificat de millegrille (CA) charge : %O", parsedCA)

    this.caStore = pki.createCaStore([parsedCA])
    this.cert = parsedCA
  }


  verifierChaine(chainePEM, opts) {
    // opts:
    //   - validityCheckDate : new Date() object ou null pour aucune verification de date
    if(!opts) opts = {}

    // Charger PEMs vers format forge
    const chaineCerts = chainePEM.map(item=>{
      return pki.certificateFromPem(item)
    })

    if(this.DEBUG && opts.validityCheckDate) console.debug("Date validation certificats %s", opts.validityCheckDate)

    let valide = true;
    try {
      pki.verifyCertificateChain(this.caStore, chaineCerts, opts)
    } catch (err) {
      valide = false;
      if(this.DEBUG) console.debug('Certificate verification failure: %s', JSON.stringify(err, null, 2))
    }

    return valide
  }

}

export function matchCertificatKey(certificatPEM, keyPEM) {
  const cert = pki.certificateFromPem(certificatPEM)
  const key = pki.privateKeyFromPem(keyPEM)

  // console.debug("Cert, cle")
  // console.debug(cert.publicKey.n)
  // console.debug(key.n)

  const cleCertMatch = cert.publicKey.n.compareTo(key.n) === 0
  // console.debug("Match : %s", cleCertMatch)

  return cleCertMatch
}

export function genererRandomSerial() {
  const serial = '' + Math.floor(Math.random() * 10000000000000000000)
  if(serial.length < 2) {
    serial = '0' + serial
  }
  return serial
}

export function chargerClePrivee(clePriveePEM, opts) {
  opts = opts || {}

  // console.debug("Charger cle privee (password: %O): %O", opts.password, clePriveePEM)

  if(opts.password) {
    return pki.decryptRsaPrivateKey(clePriveePEM, opts.password)
  } else {
    return pki.privateKeyFromPem(clePriveePEM)
  }
}

export async function validerChaineCertificats(chainePEM, opts) {
  debug("validerChaineCertificats chainePEM : %O", chainePEM)
  if(typeof(chainePEM) === 'string') {
    chainePEM = splitPEMCerts(chainePEM)
  }

  if(chainePEM.length > 3) {
    throw new Error("Chaine de certificat > 3, le cross-signing n'est pas supporte pour l'authentification web")
  }
  if(!opts) opts = {}

  // Calculer idmg
  const certCa = chainePEM[2]
  if(!certCa) throw new Error("Chaine incomplete : " + chainePEM)
  const certCaForge = pki.certificateFromPem(certCa)

  // Verifier chaine de certificats du client
  const clientStore = opts.clientStore || new CertificateStore(certCa, {isPEM: true})
  const chaineOk = clientStore.verifierChaine(chainePEM)

  if(!chaineOk) throw new Error("Chaine de certificats invalide")

  const certClient = pki.certificateFromPem(chainePEM[0])

  // S'assurer que le certificat client correspond au IDMG (O=IDMG)
  const idmgExtrait = await getIdmg(chainePEM)  // certClient.subject.getField('O').value

  var idmg = opts.idmg
  if(idmg && idmgExtrait !== idmg) {
    throw new Error("Certificat (O=" + idmgExtrait + ") ne corespond pas au IDMG " + opts.idmg)
  } else {
    verifierIdmg(idmgExtrait, certCa)
    // Aucune erreur lancee, le IDMG est valide
    idmg = idmgExtrait
  }

  // Prendre le IDMG du issuer comme reference
  const idmgIssuer = certClient.issuer.getField('O').value
  if(idmgIssuer !== idmg) {
    throw new Error("Certificat intermediaire (O=" + idmgIssuer + ") ne corespond pas au IDMG calcule " + idmg)
  }

  return {cert: certClient, idmg: idmgIssuer, idmgCa: idmg, clientStore}
}

export function verifierChallengeCertificat(certClient, messageSigne) {
  // Verifier la signature du message
  const signature = messageSigne['_signature']
  if(!signature) throw new Error("Signature introuvable")

  const copieMessage = {...messageSigne}
  delete copieMessage['_signature']
  delete copieMessage['_signatures']
  const stableJsonStr = stringify(copieMessage)
  const signatureOk = verifierSignatureString(certClient.publicKey, stableJsonStr, signature)

  return signatureOk
}

export function extraireExtensionsMillegrille(certificatForge) {
  // Extraire niveaux de securite des extensions du certificat
  var niveauxSecurite = ''
  try {
    const niveauxSecuriteList = certificatForge.extensions.filter(ext=>{return ext.id === '1.2.3.4.0'}).map(item=>{return item.value.split(',')})
    niveauxSecurite = niveauxSecuriteList.reduce((array, item)=>{return [...array, ...item]}, [])
  } catch(err) {console.error("Erreur lecture niveaux de securite du certificat: %O", err)}

  // Extraire roles des extensions du certificat
  var roles = ''
  try {
    const rolesList = certificatForge.extensions.filter(ext=>{return ext.id === '1.2.3.4.1'}).map(item=>{return item.value.split(',')})
    roles = rolesList.reduce((array, item)=>{return [...array, ...item]}, [])
  } catch(err) {console.error("Erreur lecture roles du certificat: %O", err)}

  // Extraire userId de certificat de navigateur
  var userId = ''
  try {
    userId = certificatForge.extensions.filter(ext=>{return ext.id === '1.2.3.4.3'})[0].value
  } catch(err) {
    //console.error("Erreur lecture userId du certificat: %O", err)
  }

  var delegationGlobale = ''
  try {
    const ext = certificatForge.extensions.filter(ext=>{return ext.id === '1.2.3.4.4'})
    if(ext && ext[0]) {
      delegationGlobale = ext[0].value
    }
  } catch(err) {
    // console.error("Erreur lecture delegationGlobale du certificat: %O", err)
  }

  var delegationsDomaines = ''
  try {
    const ext = certificatForge.extensions.filter(ext=>{return ext.id === '1.2.3.4.5'})
    if(ext && ext[0]) {
      delegationsDomaines = ext[0].value
      if(delegationsDomaines) delegationsDomaines = delegationsDomaines.split(',')
    }
  } catch(err) {
    //console.error("Erreur lecture delegationsDomaines du certificat: %O", err)
  }

  var delegationsSousDomaines = ''
  try {
    const ext = certificatForge.extensions.filter(ext=>{return ext.id === '1.2.3.4.6'})
    if(ext && ext[0]) {
      delegationsSousDomaines = ext[0].value
      if(delegationsSousDomaines) delegationsSousDomaines = delegationsSousDomaines.split(',')
    }
  } catch(err) {
    // console.error("Erreur lecture delegationsSousDomaines du certificat: %O", err)
  }

  return {roles, niveauxSecurite, userId, delegationGlobale, delegationsDomaines, delegationsSousDomaines}
}

export function comparerArraybuffers(buf1, buf2) {
  // https://stackoverflow.com/questions/21553528/how-to-test-for-equality-in-arraybuffer-dataview-and-typedarray
  if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Int8Array(buf1);
    var dv2 = new Int8Array(buf2);
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
}

export function hacherPem(pem, opts) {
  opts = opts || {}
  const hashingCode = opts.hashingCode || 'sha2-256',
        encoding = opts.encoding || 'base64'

  /* Permet d'hacher un PEM directement, e.g. cle publique. */
  var lignes = pem.trim().split('\n')
  // console.debug("Ligne PEM : %O", lignes)
  lignes = lignes.slice(1, lignes.length-1)

  var pemSansEnveloppe = lignes.join('')
  console.debug("Pem sans enveloppe : %O", pemSansEnveloppe)


  var buffer = new Uint8Array(Buffer.from(pemSansEnveloppe, 'base64'))
  console.debug("Buffer pem : %O", buffer)

  return hacher(buffer, {hashingCode, encoding})
}

export default {
  chiffrerPrivateKeyPEM, enveloppePEMPublique, enveloppePEMPrivee,
  matchCertificatKey, CertificateStore, genererRandomSerial, splitPEMCerts,
  chargerClePrivee, chiffrerPrivateKey,
  validerChaineCertificats, verifierChallengeCertificat, sauvegarderPrivateKeyToPEM,
  comparerArraybuffers, extraireExtensionsMillegrille,
  hacherPem,
}
