/* Chiffrage asymmetrique X25519. Supporte cles Ed25519 et X25519. */
import nodeforge from '@dugrema/node-forge'
import ed2curve from 'ed2curve'
import multibase from 'multibase'
import curve25519 from 'curve25519-js'
import hachage from './hachage'
import crypto from 'crypto'
import { base64 } from 'multiformats/bases/base64'

const { pki, ed25519 } = nodeforge,
      { convertSecretKey, convertPublicKey } = ed2curve

/**
 * 
 * @param {*} clePublique Certificat PEM, cle Ed25519 (format Uint8Array ou objet avec .publicKeyBytes) ou 
 *                        cle X25519 (avec opts.x25519 === true)
 * @param {Object} opts Options object
 * 
 * opts :
 *  - x25519 : true indique que la clePublique est un buffer x25519
 */
export async function genererCleSecrete(clePublique, opts) {
    opts = opts || {}

    const clePubliqueX25519 = convertirPublicEd25519VersX25519(clePublique, opts)
    console.debug("clePubliqueX25519 : %O", clePubliqueX25519)

    // Generer une cle Ed25519 "peer" pour deriver une cle secrete
    const { publicKey, privateKey } = ed25519.generateKeyPair()
    const peerPrivateX25519 = convertSecretKey(privateKey.privateKeyBytes),
          peerPublicX25519 = convertPublicKey(publicKey.publicKeyBytes)
    const peerPublic = base64.encode(peerPublicX25519)
    console.debug("Cle peer generee:\npublic %O\private %O\nprivate x25519: %O\npeer public: %O", publicKey, privateKey, peerPrivateX25519, peerPublicX25519)

    // Deriver la cle secrete a partir de la cle publique et peer prive
    const cleSecreteHachee = await _deriverCleSecrete(peerPrivateX25519, clePubliqueX25519)
    console.debug("Cle secrete hachee : %O", cleSecreteHachee)

    return {cle: cleSecreteHachee, peer: peerPublic, peerPublicBytes: peerPublicX25519}
}

export async function deriverCleSecrete(clePrivee, clePublique, opts) {
    opts = opts || {}

    console.debug("Cle privee: %O", clePrivee)
    const clePriveeX25519 = convertirPriveEd25519VersX25519(clePrivee, opts)

    let clePubliqueX25519
    if(typeof(clePublique) === 'string') {
        // Assumer format multibase de cle publique X25519
        clePubliqueX25519 = multibase.decode(clePublique)
    } else if(clePublique instanceof ArrayBuffer || ArrayBuffer.isView(clePublique)) {
        clePubliqueX25519 = clePublique
    } else {
        throw new Error("utiljs chiffrage.ed25519 deriverCleSecrete Format de cle publique inconnu")
    }

    const cleSecrete = await _deriverCleSecrete(clePriveeX25519, clePubliqueX25519)
    return cleSecrete
}

export async function chiffrerCle(cleSecrete, clePublique, opts) {
    opts = opts || {}

    if( ! (cleSecrete instanceof ArrayBuffer || ArrayBuffer.isView(cleSecrete)) ) {
        throw new Error("utiljs chiffrage.ed25519 chiffrerCle Format de cle prive inconnu")
    }
    // Obtenir une nouvelle cle peer pour le chiffrage du secret
    const clePeer = await genererCleSecrete(clePublique, opts)

    // Chiffrer le secret avec la nouvelle cle peer
    const clePubliquePeer = clePeer.peerPublicBytes,
          nonceHache = await (await hachage.hacher(clePubliquePeer, {hashingCode: 'blake2s-256', encoding: 'bytes'})).slice(0, 12)

    console.debug("Cle publique peer : %O\nnonce: %O\nCle intermediaire derivee : %O", clePubliquePeer, nonceHache, clePeer.cle)
    const cipher = crypto.createCipheriv('chacha20-poly1305', clePeer.cle, nonceHache, { authTagLength: 16 });
    const ciphertext = cipher.update(cleSecrete)
    console.debug("Ciphertext : %O", new Uint8Array(ciphertext))
    cipher.final()
    const tag = cipher.getAuthTag()

    // Encoder la cle peer publique et le ciphertext dans un meme buffer
    const cleChiffreeBuffer = new Uint8Array(80)
    cleChiffreeBuffer.set(clePubliquePeer, 0)
    cleChiffreeBuffer.set(ciphertext, 32)
    cleChiffreeBuffer.set(tag, 64)
    console.debug("Cle chiffree buffer : %O", cleChiffreeBuffer)
    const cleChiffreeStr = base64.encode(cleChiffreeBuffer)

    console.debug("Resultat chiffrer cle : %O", cleChiffreeStr)

    return cleChiffreeStr
}

/**
 * Dechiffre une cle secrete chiffree
 * @param {*} cleSecreteChiffree Cle secrete en base64 (string) ou buffer
 * @param {*} clePrivee Buffer d'une cle privee Ed25519
 * @param {*} opts 
 */
export async function dechiffrerCle(cleSecreteChiffree, clePrivee, opts) {

    let cleSecreteBuffer
    if(typeof(cleSecreteChiffree) === 'string') {
        cleSecreteBuffer = multibase.decode(cleSecreteChiffree)
    } else if( cleSecreteChiffree instanceof ArrayBuffer || ArrayBuffer.isView(cleSecreteChiffree) ) {
        cleSecreteBuffer = cleSecreteChiffree
    } else {
        throw new Error("chiffrage.ed25519 dechiffrerCle Param cleSecreteChiffree a un format non supporte")
    }

    let cleDechiffree
    if(cleSecreteBuffer.length === 32) {
        // On assume que c'est une cle de millegrille. Rederiver la valeur.
        const clePubliquePeer = cleSecreteBuffer.slice(0, 32)
        cleDechiffree = await deriverCleSecrete(clePrivee, clePubliquePeer, opts)
    } else if(cleSecreteBuffer.length === 80) {
        // Cle chiffree avec peer public
        const clePubliquePeer = cleSecreteBuffer.slice(0, 32),
              cleChiffree = cleSecreteBuffer.slice(32, 64),
              tag = cleSecreteBuffer.slice(64, 80),
              nonce = await (await hachage.hacher(clePubliquePeer, {hashingCode: 'blake2s-256', encoding: 'bytes'})).slice(0, 12)
        
        const cleSecreteDerivee = await deriverCleSecrete(clePrivee, clePubliquePeer, opts)
        console.debug("Cle dechiffrage nonce : %O\nCle intermediaire rederivee : %O", nonce, cleSecreteDerivee)

        const decipher = crypto.createDecipheriv('chacha20-poly1305', cleSecreteDerivee, nonce, { authTagLength: 16 })
        cleDechiffree = decipher.update(cleChiffree)
        console.debug("Cle dechiffree : %O", new Uint8Array(cleDechiffree))
        decipher.setAuthTag(tag)
        decipher.final()
    } else {
        throw new Error("chiffrage.ed25519 dechiffrerCle Param cleSecreteChiffree n'a pas une taille supportee (32 bytes ou 80 bytes)")
    }

    return cleDechiffree
}

async function _deriverCleSecrete(clePrivee, clePublique) {
    // Deriver la cle secrete a partir de la cle publique et peer prive
    const cleSecreteDerivee = curve25519.sharedKey(clePrivee, clePublique)
    const cleSecreteHachee = await hachage.hacher(cleSecreteDerivee, {hashingCode: 'blake2s-256', encoding: 'bytes'})
    return cleSecreteHachee
}

function convertirPublicEd25519VersX25519(clePublique, opts) {
    // Charger la cle publique, s'assurer d'avoir le format X25519
    let cleX25519
    if(!clePublique) {
        throw new Error("utiljs chiffrage.ed25519 Cle publique null/undefined")
    } else if(typeof(clePublique) === 'string') {
        // Certificat PEM
        const cert = pki.certificateFromPem(clePublique)
        const publicKey = cert.publicKey.publicKeyBytes
        cleX25519 = convertPublicKey(publicKey)
    } else if(clePublique.publicKeyBytes) {
        // Cle publique Ed25519
        const publicKey = clePublique.publicKeyBytes
        cleX25519 = convertPublicKey(publicKey)
    } else if(clePublique instanceof ArrayBuffer || ArrayBuffer.isView(clePublique)) {
        if(opts.ed25519 === true) {
            // Cle publique Ed25519
            cleX25519 = convertPublicKey(clePublique)
        } else {
            // Cle publique X25519, rien a faire.
            cleX25519 = clePublique
        }
    } else {
        throw new Error("utiljs chiffrage.ed25519 Format de cle publique inconnu")
    }

    return cleX25519
}

function convertirPriveEd25519VersX25519(clePrivee, opts) {
    opts = opts || {}

    let cleX25519
    if(!clePrivee) {
        throw new Error("utiljs chiffrage.ed25519 Cle privee null/undefined")
    } else if(typeof(clePrivee) === 'string') {
        // Certificat PEM
        const cert = pki.privateKeyFromPem(clePrivee)
        const privateKey = cert.publicKey.privateKeyBytes.slice(0, 32)
        cleX25519 = convertSecretKey(privateKey)
    } else if(clePrivee.privateKeyBytes) {
        // Cle publique Ed25519
        const privateKey = clePrivee.privateKeyBytes.slice(0, 32)
        cleX25519 = convertSecretKey(privateKey)
    } else if(clePrivee instanceof ArrayBuffer || ArrayBuffer.isView(clePrivee)) {
        if(opts.x25519 === true) {
            // Cle privee X25519, rien a faire
            cleX25519 = clePrivee
        } else {
            // Cle publique Ed25519.
            cleX25519 = convertSecretKey(clePrivee).slice(0, 32)
        }
    } else {
        throw new Error("utiljs chiffrage.ed25519 Format de cle privee inconnu")
    }

    return cleX25519
}
