/* Tests de chiffrage asymmetrique avec cles EdDSA25519 (-> X25519) */
const { ed25519 } = require('@dugrema/node-forge')
// console.debug("Nodeforge : %O", Object.keys(nodeforge))
const { base64 } = require('multiformats/bases/base64')

require('./chiffrage.config')

const { chiffrer, dechiffrer, chiffrerDocument, dechiffrerDocument } = require('../src/chiffrage')
const { deriverCleSecrete } = require('../src/chiffrage.ed25519')

const { genererClePrivee, genererCertificatMilleGrille } = require('../src/certificats')

//console.debug("!!!3 NODEFORGE : %O", Object.keys(nodeforge))

// const { ed25519 } = nodeforge

async function genererCert() {
    const clePrivee = genererClePrivee()
    console.debug("Cle privee pem : %O", clePrivee)
    const certInfo = await genererCertificatMilleGrille(clePrivee.pem)
    console.debug("certInfo: %O", certInfo)
    return {...certInfo, clePrivee}
}

test('chiffrage/dechiffrage message secret', async () =>  {
    const messageStr = "Allo, message secret"
    const encoder = new TextEncoder()
    const messageBuffer = encoder.encode(messageStr)
    console.debug("Message buffer : %O", messageBuffer)

    // Generer cle dummy
    const { publicKey, privateKey } = ed25519.generateKeyPair()
    const publicKeyBytes = publicKey.publicKeyBytes

    const resultatChiffrage = await chiffrer(messageBuffer, {clePubliqueEd25519: publicKeyBytes})
    console.debug("Resultat chiffrage : %O", resultatChiffrage)

    // Dechiffrer avec cle secrete
    const { iv, tag } = resultatChiffrage.meta
    const resultatDechiffrage = await dechiffrer(resultatChiffrage.ciphertext, resultatChiffrage.secretKey, iv, tag)
    console.debug("Resultat dechiffrage : %O", resultatDechiffrage)

    const decoder = new TextDecoder()
    const messageDechiffre = decoder.decode(resultatDechiffrage)
    console.debug("Message dechiffre : %O", messageDechiffre)

    expect.assertions(1)
    expect(messageDechiffre).toBe(messageStr)
})

test('chiffrage/dechiffrage cle secrete', async () =>  {
    // Generer cle dummy
    const { publicKey, privateKey } = ed25519.generateKeyPair()
    const publicKeyBytes = publicKey.publicKeyBytes,
          privateKeyBytes = privateKey.privateKeyBytes

    console.debug("Public key : %O\nPrivate key : %O", publicKeyBytes, privateKeyBytes)

    const resultatChiffrage = await chiffrer(new Uint8Array(1), {clePubliqueEd25519: publicKeyBytes})
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
    const docChiffre = await chiffrerDocument(docTest, 'DomaineTest', certDummy.pem, {idDoc: 'mondoc'}, {DEBUG: true})
    console.debug("Document chiffre: %O", docChiffre)

    // Dechiffrer le document
    const { cles, iv, tag, format } = docChiffre.commandeMaitrecles
    const cleChiffree = cles[Object.keys(cles)[0]]
    const messageCle = {
        iv, tag, format,
        cle: cleChiffree
    }

    const docDechiffre = await dechiffrerDocument(docChiffre.ciphertext, messageCle, clePrivee, {DEBUG: true})
    console.debug("Document dechiffre : %O", docDechiffre)

    expect.assertions(1)
    expect(docDechiffre).toEqual(docTest)
})