// Utilitaires pour le maitre des cles
const multibase = require('multibase')
const { ed25519 } = require('@dugrema/node-forge')
const { calculerDigest } = require('./hachage')
const { publicKeyFromPrivateKey } = require('./certificats')
const { genererCleSecrete: genererCleSecreteEd25519, chiffrerCle, dechiffrerCle, deriverCleSecrete } = require('./chiffrage.ed25519')

const SIGNATURE_DOMAINES_V1 = 1

/**
 * Signature utilisee par la commande ajouterCleDomaines du maitre des cles. Permet de
 * garantir que l'originateur de la commande avait en sa possession la cle secrete.
 */
class SignatureDomaines {

    constructor(domaines, opts) {
        opts = opts || {}

        /** Liste des domaines supportes pour la cle. */
        this.domaines = domaines

        /** Version de la signature */
        this.version = opts.version || SIGNATURE_DOMAINES_V1

        /** 
         * Peer public, represente la cle chiffree pour le CA, format X25519.
         * Deriver le secret en utilisant la cle privee du CA + blake2s.
         */
        this.peer_ca = null

        /**
         * Signature des domaines en utilisant la cle secrete
         * Encodage : string base64 nopad
         */
        this.signature = null
    }

    /**
     * Genere une nouvelle signature de domaines a utiliser avec une commande de sauvegarde de cle.
     * 
     * @param {*} peerPublic String/Buffer d'une cle publique X25519 utilisee pour un exchange avec le CA.
     * @param {Uint8Array} cleSecrete Bytes d'une cle secrete
     */
    async signerEd25519(peerPublic, cleSecrete) {
        // Effectuer la signature en utilisant la cle secrete
        this.signature = await signerDomaines(this.domaines, cleSecrete)
        
        if(typeof(peerPublic) === 'string') {
            this.peer_ca = peerPublic
        } else if(ArrayBuffer.isView(peerPublic)) {
            // Conserver le peerPublic en base64 no pad.
            this.peer_ca = String.fromCharCode
                .apply(null, multibase.encode('base64', peerPublic))
                .slice(1)  // Retirer le 'm' d'encodage multibase
        } else {
            throw new Error("Mauvais format pour peerPublic, doit etre Uint8Array ou string en base64 no pad")
        }
    }

    /**
     * Utilise la cle secrete pour verifier la signature des domaines. Si la signature est valide,
     * implique que la cle secrete est correcte et que les domaines sont valides pour cette cle.
     * @param {Uint8Array} cleSecrete 
     */
    async verifierSecrete(cleSecrete) {
        // Convertir la cle secrete Ed25519 en cle publique.
        const clePublique = publicKeyFromPrivateKey(cleSecrete)
        // Verifier la signature des domaines
        const resultat = await verifierDomaines(this.domaines, this.signature, clePublique)

        if(!resultat) throw new Error("Signature invalide")
    }

    /**
     * Valeur unique qui peut etre utilisee comme identite pour cette cle.
     * @returns {string} Hachage de la signature en blake2s.
     */
    async getCleRef() {
        if(!this.signature) throw new Error("Signature absente")
        const hachageBytes = multibase.decode('m'+this.signature)
        const hachageSignatureByteString = await calculerDigest(hachageBytes, 'blake2s-256')
        const hachageSignature = Buffer.from(hachageSignatureByteString, 'binary')
        
        // Convertir en base58 btc
        const signatureBase58 = String.fromCharCode.apply(null, multibase.encode('base58btc', hachageSignature))
        return signatureBase58
    }

    async getCleDechiffreeCa(clePriveeCa) {
        const cleChiffreeX25519Bytes = multibase.decode('m'+this.peer_ca)
        const clePeerCaPublicX25519 = await deriverCleSecrete(clePriveeCa, cleChiffreeX25519Bytes)
        return clePeerCaPublicX25519
    }

}

/**
 * Genere une nouvelle signature de domaines a utiliser avec une commande de sauvegarde de cle.
 * 
 * @param {string} domaines Liste des domaines
 * @param {Uint8Array} clePriveeEd25519 Bytes d'une cle privee utilisee pour un exchange x25519 avec le CA.
 * @returns {string} Signature base64
 */
async function signerDomaines(domaines, clePriveeEd25519) {
    // Hacher les domaines
    const domainesBytes = new TextEncoder().encode(JSON.stringify(domaines))
    const domainesHachage = await calculerDigest(domainesBytes, 'blake2s-256')

    // Signer
    const signatureByteString = ed25519.sign({message: domainesHachage, privateKey: clePriveeEd25519})
    const signature = Buffer.from(signatureByteString, 'binary')

    // Convertir en base64 nopad (retirer premier char 'm')
    const signatureBase64 = String.fromCharCode
        .apply(null, multibase.encode('base64', signature))
        .slice(1)  // Retirer premier char multibase ('m')

    return signatureBase64
}

/**
 * Verifie la signature des domaines en utilisant une cle publique.
 * @param {array} domaines 
 * @param {string} signatureString 
 * @param {Object} clePublique 
 * @returns 
 */
async function verifierDomaines(domaines, signatureString, clePublique) {
    const domainesBytes = new TextEncoder().encode(JSON.stringify(domaines))
    const domainesHachage = await calculerDigest(domainesBytes, 'blake2s-256')

    const signatureBytes = multibase.decode('m'+signatureString)

    const params = {
        message: domainesHachage, 
        signature: signatureBytes, 
        publicKey: clePublique
    }

    // Verifier
    return ed25519.verify(params)
}

class DechiffrageInterMillegrilles {
    constructor(cles) {
        this.cles = cles
        this.format = null
        this.nonce = null
        this.verification = null

        this.cle_id = undefined

        // Deprecated, header -> nonce, hachage -> verification
        this.header = undefined
        this.hachage = undefined
    }

    async dechiffrer(fingerprint, clePriveeEd25519) {
        const cleChiffree = this.cles[fingerprint]
        if(!cleChiffree) throw new Error(`Cle manquante pour certificat ${fingerprint}`)
        
        // La cle chiffree est encodee en base64 nopad, utiliser format 'm'+cle pour decoder en multibase
        return await dechiffrerCle('m'+cleChiffree, clePriveeEd25519)
    }
}

class CommandeAjouterCleDomaines {

    /**
     * 
     * @param {Object} cles 
     * @param {SignatureDomaines} signature 
     */
    constructor(cles, signature) {
        this.cles = cles
        this.signature = signature
    }

}

async function creerCommandeAjouterCle(signature, cleSecrete, clesPubliques) {
    if(!signature) throw new Error("Aucune signature")
    if(!cleSecrete) throw new Error("Aucunes cle secrete")
    if(!clesPubliques || clesPubliques.length === 0) throw new Error("Aucunes cles publiques")

    // Chiffrer la cle secrete pour chaque cle publique
    const clesChiffrees = {}
    for(const clePublique of clesPubliques) {
        const clePubliqueBytes = Buffer.from(clePublique, 'hex')
        const cleChiffree = await chiffrerCle(cleSecrete, clePubliqueBytes, {ed25519: true})
        clesChiffrees[clePublique] = cleChiffree.slice(1)  // Retirer le 'm' (format mulitbase)
    }

    return new CommandeAjouterCleDomaines(clesChiffrees, signature)
}

async function genererCleSecrete(clePublique, opts) {
    opts = opts || {}
    let resultat = await genererCleSecreteEd25519(clePublique, opts)
    const { cle, peer } = resultat

    const peerBase64NoPad = peer.slice(1)  // Retirer le 'm' multibase

    resultat = {cle}

    if(opts.domaines) {
        const signature = new SignatureDomaines(opts.domaines)
        await signature.signerEd25519(peerBase64NoPad, cle)
        resultat.signature = signature
    } else {
        resultat.peer = peer
    }

    return resultat
}

module.exports = {
    SignatureDomaines, CommandeAjouterCleDomaines, DechiffrageInterMillegrilles,
    creerCommandeAjouterCle, genererCleSecrete
}
