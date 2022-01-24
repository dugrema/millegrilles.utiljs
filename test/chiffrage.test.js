/* Tests de chiffrage asymmetrique avec cles EdDSA25519 (-> X25519) */
import nodeforge from '@dugrema/node-forge'
import { base64 } from 'multiformats/bases/base64'

import { chiffrer, dechiffrer } from '../src/chiffrage'
import './hachage.config'
import './chiffrage.config'
import { deriverCleSecrete } from '../src/chiffrage.ed25519'

const { ed25519 } = nodeforge

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

test.only('chiffrage/dechiffrage cle secrete', async () =>  {
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