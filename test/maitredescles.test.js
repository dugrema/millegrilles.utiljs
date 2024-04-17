const multibase = require('multibase')
const { generateKeyPair, sharedKey } = require('curve25519-js')
const { convertSecretKey, convertPublicKey } = require('ed2curve')
const { ed25519 } = require('@dugrema/node-forge')

const { SignatureDomaines, creerCommandeAjouterCle, genererCleSecrete, DechiffrageInterMillegrilles } = require('../src/maitredescles')
const { publicKeyFromPrivateKey } = require('../src/certificats')

require('./hachage.config')
require('./chiffrage.config')

const CLE_1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1])
const CLE_2 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2])
const CLE_3 = new Uint8Array([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33])

test('test signature domaines', async () => {
    console.debug("Test signature domaines")
    const signature = new SignatureDomaines(["domaine1"])

    const cleSecrete = CLE_2
    await signature.signerEd25519("", cleSecrete)

    console.debug("Signature %O", signature)

    expect(signature.signature).toBe("LKo3GK4j4BJV6xWT4GNF2zJDrw4XklWXeaSSn7aU3GuZTYDPkN5p3xVyI25r77PKjKvQ7JqMNnNOhZrFeQkgDg")

    // Lance une erreur si la cle est invalide
    await signature.verifierSecrete(cleSecrete)
})

test('test get cle ref', async () => {
    console.debug("Test signature domaines")
    const signature = new SignatureDomaines(["domaine1"])

    const cleSecrete = CLE_2
    await signature.signerEd25519("", cleSecrete)

    const cleRef = await signature.getCleRef()
    console.debug("Cle ref : %s", cleRef)
    
    expect(cleRef).toBe("z82YFttyyjsYSbu4NTk5G56RBFaH71edAAqXyNxaMiFFC")
})

test('test creer commande maitre des cles', async () => {
    console.debug("Test signature domaines")
    const signature = new SignatureDomaines(["domaine1"])

    const cleSecrete = CLE_2
    await signature.signerEd25519("", cleSecrete)
  
    // Generer cle publique pour rechiffrage (simuler un certificat de maitre des cles)
    const clePrivee3Ed25519 = CLE_3,
          clePublique3Ed25519 = publicKeyFromPrivateKey(clePrivee3Ed25519)
    console.debug("ClePublique3 Ed25519 ", clePublique3Ed25519)
    const clePubliqueEd25519Hex = Buffer.from(clePublique3Ed25519.publicKeyBytes).toString('hex')
  
    const clesPubliques = [clePubliqueEd25519Hex]
    console.debug("ClesPubliques ", clesPubliques)
    const opts = {}

    const commande = await creerCommandeAjouterCle(signature, cleSecrete, clesPubliques, opts)
    console.debug("Commande maitre des cles %O", commande)

    const cleChiffree = commande.cles['Q83AI9ItX54QfRoGk0V9NdHRDrfSHHIRkvVvXeQGZdM']
    expect(cleChiffree).not.toBeNull()

    // Dechiffrer la cle
    const informationCles = new DechiffrageInterMillegrilles(commande.cles)
    const cleDechiffree = await informationCles.dechiffrer(clePubliqueEd25519Hex, clePrivee3Ed25519)
    console.debug("Cle dechiffree : %O\nCle secrete: %O", new Uint8Array(cleDechiffree), cleSecrete)
    expect(new Uint8Array(cleDechiffree)).toEqual(cleSecrete)
})

test('generer cle secrete avec domaines', async () => {
      const domaines = ['Domaine1']
  
      const { publicKey, privateKey } = ed25519.generateKeyPair()
      console.debug("KeyPair\nPublic: %O\nPrivate: %O", publicKey, privateKey)
  
      const cle = await genererCleSecrete(publicKey.publicKeyBytes, {domaines})
      console.debug("Cle secrete signee", cle)
  
      // Verifier la signature secrete
      await cle.signature.verifierSecrete(cle.cle)
  
      // Dechiffrer la cle CA
      const cleCaDechiffree = await cle.signature.getCleDechiffreeCa(privateKey)
      console.debug("Cle CA dechiffree\n%O", cleCaDechiffree)
      expect(cleCaDechiffree).toEqual(cle.cle)
  })
  