// Utilitaires pour le maitre des cles
const multibase = require('multibase')
const { ed25519 } = require('@dugrema/node-forge')
const { calculerDigest } = require('./hachage')

const SIGNATURE_DOMAINES_V1 = 1

/**
 * Signature utilisee par la commande ajouterCleDomaines du maitre des cles. Permet de
 * garantir que l'originateur de la commande avait en sa possession la cle secrete.
 */
class SignatureDomaines {

    constructor(domaines, opts) {
        opts = opts || {}

        /** @field Liste des domaines supportes pour la cle. */
        this.domaines = domaines

        // Version de la signature
        this.version = opts.version || SIGNATURE_DOMAINES_V1
        
        // Signature des domaines pour la cle CA en utilisant la cle peer privee
        // Cette signature existe uniquement pour une cle derivee a partir du CA.
        // Encodage : string base64
        this.signature_ca = null

        // Signature des domaines en utilisant la cle secrete
        // Encodage : string base64
        this.signature_secrete = null
    }

    /**
     * Genere une nouvelle signature de domaines a utiliser avec une commande de sauvegarde de cle.
     * 
     * @param {Uint8Array} peerPrive Bytes d'une cle privee utilisee pour un exchange x25519 avec le CA.
     * @param {Uint8Array} cleSecrete Bytes d'une cle secrete
     */
    async signerEd25519(peerPrive, cleSecrete) {
        this.signature_ca = await signerDomaines(this.domaines, peerPrive)
        this.signature_secrete = await signerDomaines(this.domaines, cleSecrete)
    }

    async getCleRef() {
        if(!this.signature_secrete) throw new Error("Signature absente")
        const hachageBytes = multibase.decode('m'+this.signature_secrete)
        const hachageSignatureByteString = await calculerDigest(hachageBytes, 'blake2s-256')
        const hachageSignature = Buffer.from(hachageSignatureByteString, 'binary')
        
        // Convertir en base58 btc
        const signatureBase58 = String.fromCharCode.apply(null, multibase.encode('base58btc', hachageSignature))
        return signatureBase58
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

module.exports = {
    SignatureDomaines
}
