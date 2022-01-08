import crypto from 'crypto'
import { pki, ed25519, oids as forgeOids } from '@dugrema/node-forge'
import { PrivateKey } from '@fidm/x509'
import debugLib from 'debug'
import { genererRandomSerial } from './forgecommon'
import { encoderIdmg } from './idmg'

const debug = debugLib("utiljs:certificats")

const OID_UISERID = '1.2.3.4.3'

const JOUR_EPOCH_MS = 24 * 60 * 60 * 1000,     // Jour en ms : 24h * 60min * 60secs * 1000ms
      CERT_NAV_DUREE = 6 * 7 * JOUR_EPOCH_MS,  // 6 semaines (6 * 7 jours)
      CERT_COMPTE_SIMPLE_DUREE = 3 * 366 * JOUR_EPOCH_MS,  // 3 ans
      CERT_COMPTE_COMPLET_DUREE = 18 * 31 * JOUR_EPOCH_MS  // 18 mois

/* 
Genere une nouvelle cle privee EdDSA25519
Parametres opts :
  - password str: Chiffre la cle privee, retournee dans pemChiffre
*/
export async function genererClePrivee(opts) {
    opts = opts || {}
    const password = opts.password

    const keyPair = await new Promise((resolve, reject)=>crypto.generateKeyPair(
        'ed25519', 
        {}, 
        (err, publicKey, privateKey)=>{
            if(err) return reject(err)
            resolve({publicKey, privateKey})
        }
    ))
    const publicKeyGenereePem = keyPair.publicKey.export({type: 'spki', format: 'pem'})

    const privateKeyGenereePem = keyPair.privateKey.export({type: 'pkcs8', format: 'pem'})

    const resultat = {
        pemPublic: publicKeyGenereePem,
        pemPrive: privateKeyGenereePem,
        ...keyPair,
    }

    if(password) {
        resultat.pemChiffre = keyPair.privateKey.export({type: 'pkcs8', format: 'pem', cipher: 'aes-128-cbc', passphrase: password})
    }

    return resultat
}

// Genere un nouveau certificat de MilleGrille a partir d'un keypair
export async function genererCertificatMilleGrille(clePriveePEM) {

  const {privateKey, publicKey} = chargerPemClePriveeEd25519(clePriveePEM)

  const cert = pki.createCertificate()
  cert.publicKey = publicKey
  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 20)

  var attrs = [{
    name: 'commonName',
    value: 'MilleGrille'
  }]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)  // Self, genere un certificat self-signed (racine)
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: true,
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: false
  }, {
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier',
    keyIdentifier: true,
  }])

  // Signer certificat
  // cert.md = md.sha512.create()
  cert.sign(privateKey)

  // Exporter sous format PEM
  var pem = pki.certificateToPem(cert)

  var idmg = await encoderIdmg(pem)

  return {cert, pem, idmg}
}

/*
  Genere un nouveau certificat intermediaire
  Parametres:
    - pemCsr str: PEM du CSR fourni par l'instance (certissuer)
    - pemRacine str: PEM du certificat racine de la MilleGrille
    - cleRacine obj: Cle privee avec function sign(bytes)
*/
export async function genererCertificatIntermediaire(pemCsr, pemRacine, cleRacine) {
  // Lire et verifier signature du CSR
  const csr = pki.certificationRequestFromPem(pemCsr)
  if(!csr.verify()) throw new Error("CSR invalide")

  const idmg = await encoderIdmg(pemRacine)
  const certificatRacine = pki.certificateFromPem(pemRacine)
  
  const cert = pki.createCertificate()
  cert.publicKey = csr.publicKey
  const commonName = csr.subject.getField('CN').value

  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()
  const expiration = cert.validity.notBefore.getTime() + CERT_COMPTE_COMPLET_DUREE
  cert.validity.notAfter = new Date(expiration)

  const akid = certificatRacine.generateSubjectKeyIdentifier().getBytes()

  const attrs = [
    {
      name: 'commonName',
      value: commonName
    },{
      name: 'organizationName',
      value: idmg
    }
  ]
  cert.setSubject(attrs)

  cert.setIssuer(certificatRacine.subject.attributes)

  cert.setExtensions([
    {
      name: 'basicConstraints',
      critical: true,
      cA: true,
      pathLenConstraint: 0,
    }, {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
    },
    {
      name: 'subjectKeyIdentifier',
    }, 
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: akid,
    }
  ])

  // Signer certificat
  cert.sign(cleRacine)

  // Exporter sous format PEM
  const pem = pki.certificateToPem(cert)

  return pem
}

/* 
Genere un CSR pour le navigateur - va etre signe par le certissuer 
Params:
  - nomUsager str: Nom de l'usager affiche a l'ecran
  - clePriveePEM str: PEM (non chiffre) de la cle privee Ed25519
  - opts dict:
    - userId: Le userId de l'usager, si connu
*/
export async function genererCsrNavigateur(nomUsager, clePriveePEM, opts) {
  opts = opts || {}
  const userId = opts.userId

  const {privateKey, publicKey} = chargerPemClePriveeEd25519(clePriveePEM)

  debug("Extraction nouvelles cles\nPublique: %O\nPrivee: %O", publicKey, privateKey)

    // Creer la CSR
    const csr = pki.createCertificationRequest()
    debug("Nouveau CSR : %O", csr)

    csr.publicKey = publicKey

    var attrs = [{
      name: 'commonName',
      value: nomUsager
    }]
    csr.setSubject(attrs)
  
    var extensions = []
  
    if(userId) {
      // Ajouter l'extension userId
      extensions.push({
        id: OID_UISERID,  // custom userId pour MilleGrilles
        value: userId,
      })
    }
  
    if(extensions.length > 0) {
      csr.setAttributes([
        {name: 'extensionRequest', extensions}
      ])
    }
  
    // Signer requete
    csr.sign(privateKey)
  
    // Exporter sous format PEM
    const csrPem = pki.certificationRequestToPem(csr)

    return csrPem
}

export function chargerPemClePriveeEd25519(pem, opts) {
  opts = opts || {}

  if(opts.password) {
    // Dechiffrer la cle privee
    const key = crypto.createPrivateKey({
      key: pem,
      passphrase: opts.password,
    })
    pem = key.export({type: 'pkcs8', format: 'pem'})
  }

  const privateKeyInfo = PrivateKey.fromPEM(pem),
        privateKeyBytes = new Uint8Array(privateKeyInfo.keyRaw),
        publicKeyBytes = new Uint8Array(privateKeyInfo.publicKeyRaw)

  // Preparer structure cle privee pour signature
  const privateKey = {
    privateKeyBytes: privateKeyBytes,
    keyType: forgeOids.EdDSA25519,
    sign: message => {
      return ed25519.sign({
        privateKey: privateKeyBytes, 
        encoding: 'binary', 
        message
      }).toString('binary')
    }
  }
  
  // Cle publique (sans verify)
  const publicKey = {
    publicKeyBytes: publicKeyBytes,
    keyType: forgeOids.EdDSA25519,
  }

  return {privateKey, publicKey}
}
