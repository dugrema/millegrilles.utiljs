const { SignatureDomaines } = require('../src/maitredescles')
const { publicKeyFromPrivateKey } = require('../src/certificats')

require('./hachage.config')

const CLE_1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1])
const CLE_2 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2])

test('test signature domaines', async () => {
    console.debug("Test signature domaines")
    const signature = new SignatureDomaines(["domaine1"])

    const peerPrive = CLE_1,
          cleSecrete = CLE_2
    await signature.signerEd25519(peerPrive, cleSecrete)

    console.debug("Signature\n%O", JSON.stringify(signature))

    expect(signature.signature_ca).toBe("Kpey17TDuXtwHH/1A+08ZS3xSTqYLXmFZPDT8KLqHyyLMQSyGYLGXWyyeLlchwwe59+P5+2kgzGFztz9usc/Cw")
    expect(signature.signature_secrete).toBe("LKo3GK4j4BJV6xWT4GNF2zJDrw4XklWXeaSSn7aU3GuZTYDPkN5p3xVyI25r77PKjKvQ7JqMNnNOhZrFeQkgDg")

    // Lance une erreur si la cle est invalide
    await signature.verifierSecrete(cleSecrete)

    const clePubliqueCa = publicKeyFromPrivateKey(CLE_1)
    await signature.verifierCa(clePubliqueCa)
})

test('test get cle ref', async () => {
    console.debug("Test signature domaines")
    const signature = new SignatureDomaines(["domaine1"])

    const peerPrive = CLE_1,
          cleSecrete = CLE_2
    await signature.signerEd25519(peerPrive, cleSecrete)

    const cleRef = await signature.getCleRef()
    console.debug("Cle ref : %s", cleRef)
    
    expect(cleRef).toBe("z82YFttyyjsYSbu4NTk5G56RBFaH71edAAqXyNxaMiFFC")
})

test