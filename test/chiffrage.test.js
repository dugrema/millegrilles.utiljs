/* Tests de chiffrage asymmetrique avec cles EdDSA25519 (-> X25519) */
const { ed25519 } = require('@dugrema/node-forge')
const { base64 } = require('multiformats/bases/base64')

require('./chiffrage.config')
const { deriverCleSecrete } = require('../src/chiffrage.ed25519')
const { genererClePrivee, genererCertificatMilleGrille } = require('../src/certificats')

const { 
    chiffrer, chiffrerDocument, 
    chiffrerChampsV2, dechiffrerChampsV2, preparerCommandeAjouterCleDomaines 
} = require('../src/chiffrage')
const { DechiffrageInterMillegrilles } = require('../src/maitredescles')

// const { ed25519 } = nodeforge

async function genererCert() {
    const clePrivee = genererClePrivee()
    console.debug("Cle privee pem : %O", clePrivee)
    const certInfo = await genererCertificatMilleGrille(clePrivee.pem)
    console.debug("certInfo: %O", certInfo)
    return {...certInfo, clePrivee}
}

// test('chiffrage/dechiffrage message secret', async () =>  {
//     const messageStr = "Allo, message secret"
//     const encoder = new TextEncoder()
//     const messageBuffer = encoder.encode(messageStr)
//     console.debug("Message buffer : %O", messageBuffer)

//     // Generer cle dummy
//     const { publicKey, privateKey } = ed25519.generateKeyPair()
//     const publicKeyBytes = publicKey.publicKeyBytes

//     const resultatChiffrage = await chiffrer(messageBuffer, {clePubliqueEd25519: publicKeyBytes})
//     console.debug("Resultat chiffrage : %O", resultatChiffrage)

//     // Dechiffrer avec cle secrete
//     const { iv, tag } = resultatChiffrage.meta
//     const resultatDechiffrage = await dechiffrer(resultatChiffrage.ciphertext, resultatChiffrage.secretKey, iv, tag)
//     console.debug("Resultat dechiffrage : %O", resultatDechiffrage)

//     const decoder = new TextDecoder()
//     const messageDechiffre = decoder.decode(resultatDechiffrage)
//     console.debug("Message dechiffre : %O", messageDechiffre)

//     expect.assertions(1)
//     expect(messageDechiffre).toBe(messageStr)
// })

test('chiffrage/dechiffrage cle secrete', async () =>  {
    // Generer cle dummy
    const { publicKey, privateKey } = ed25519.generateKeyPair()
    const publicKeyBytes = publicKey.publicKeyBytes,
          privateKeyBytes = privateKey.privateKeyBytes

    console.debug("Public key : %O\nPrivate key : %O", publicKeyBytes, privateKeyBytes)

    const nonce = new Uint8Array(12)
    const resultatChiffrage = await chiffrer(new Uint8Array(1), {clePubliqueEd25519: publicKeyBytes, cipherAlgo: 'chacha20-poly1305', nonce})
    console.debug("Resultat chiffrage : %O", resultatChiffrage)

    // Verifier cle secrete
    const cleRederivee = await deriverCleSecrete(privateKeyBytes, base64.decode(resultatChiffrage.secretChiffre))
    console.debug("Cle rederivee : %O", cleRederivee)

    expect.assertions(1)
    expect(resultatChiffrage.secretKey).toEqual(cleRederivee)
})

test('chiffrage/dechiffrage document', async () => {
    
    // Preparer data, cert
    const docTest = {value: 'Document de test', nombre: 42}
    const certDummy = await genererCert()
    const clePrivee = certDummy.clePrivee.privateKey.privateKeyBytes

    // Chiffrer le document
    const nonce = new Uint8Array(12)
    const docChiffre = await chiffrerDocument(
        docTest, 'DomaineTest', certDummy.pem, 
        {idDoc: 'mondoc'},
        {cipherAlgo: 'chacha20-poly1305', nonce, DEBUG: true}
    )
    console.debug("Document chiffre: %O", docChiffre)

    // Dechiffrer le document
    const { cles, iv, tag, format } = docChiffre.commandeMaitrecles
    const cleChiffree = cles[Object.keys(cles)[0]]
    const messageCle = {
        iv, tag, format,
        cle: cleChiffree
    }

    // const docDechiffre = await dechiffrerDocument(docChiffre.ciphertext, messageCle, clePrivee, {DEBUG: true})
    // console.debug("Document dechiffre : %O", docDechiffre)

    // expect.assertions(1)
    // expect(docDechiffre).toEqual(docTest)
})

test('chiffrage/dechiffrage document V2', async () => {
    
    // Preparer data, cert
    const docTest = {value: 'Document de test', nombre: 42}
    const certDummy = await genererCert()
    const clePrivee = certDummy.clePrivee.privateKey.privateKeyBytes
    const clePubliqueCa = certDummy.cert.publicKey.publicKeyBytes

    // Chiffrer le document
    const nonce = new Uint8Array(12)
    const docChiffre = await chiffrerChampsV2(
        docTest, 'DomaineTest', clePubliqueCa, certDummy.pem, 
        {cipherAlgo: 'chacha20-poly1305', nonce, DEBUG: true}
    )
    console.debug("test Document chiffre V2: %O", docChiffre)

    // Dechiffrer le document
    const { cles, signature } = docChiffre.commandeMaitrecles
    const dechiffrage = new DechiffrageInterMillegrilles(cles)
    let cleSecrete = null
    for(const fingerprint of Object.keys(cles)) {
        cleSecrete = new Uint8Array(await dechiffrage.dechiffrer(fingerprint, clePrivee))
    }
    console.debug("Cle dechiffree : %O", cleSecrete)

    const message = docChiffre.doc
    const docDechiffre = await dechiffrerChampsV2(message, cleSecrete, {DEBUG: true})
    console.debug("Doc dechiffre\n%O", docDechiffre)
    expect(docDechiffre).toEqual(docTest)
})


test('creer commande ajouter cle domaines', async () => {
    const certDummy = await genererCert()
    console.debug("CertyDummy ", certDummy)
    const certificatsChiffrage = [certDummy.pem]

    const peerCa = "PEERCA"
    const cleSecrete = new Uint8Array(32)
    const domaine = 'MonDomaine1'
    const opts = {}

    const commandeMaitreDesCles = await preparerCommandeAjouterCleDomaines(
        certificatsChiffrage, peerCa, cleSecrete, domaine, opts)
    const signature = commandeMaitreDesCles.signature

    console.debug("Commande maitre des cles\n%O\n\n%s", commandeMaitreDesCles, JSON.stringify(commandeMaitreDesCles))
    expect(signature.peer_ca).toEqual(peerCa)
    expect(signature.domaines).toEqual([domaine])
    expect(signature.version).toEqual(1)

    // Note : on ne test pas le dechiffrage du peer (valeur est dummy)
})
