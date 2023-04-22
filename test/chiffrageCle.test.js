/* Tests de chiffrage asymmetrique avec cles EdDSA25519 (-> X25519) */
const { ed25519 } = require('@dugrema/node-forge')
// console.debug("Nodeforge : %O", Object.keys(nodeforge))
const { base64 } = require('multiformats/bases/base64')

require('./chiffrage.config')

const { signerIdentiteCle } = require('../src/chiffrage')
const { deriverCleSecrete } = require('../src/chiffrage.ed25519')

//const keyPair =  ed25519.generateKeyPair()
//console.debug("keyPair ", keyPair)
//const privateKeyMb = base64.encode(keyPair.privateKey.privateKeyBytes)
const privateKeyMb = 'mQmou4WevIdb9noBaHLm+eVwaKG7md8Gl7bZkIjD2oCq8is/DDnK8r5h0fJOPZ/3tMPKvnbjmxw8M28rjkn5t+g'
const privateKeyBytes = base64.decode(privateKeyMb)
console.debug('privateKeyMb %O\n%O', privateKeyMb, privateKeyBytes)
const keyPair2 = ed25519.generateKeyPair({seed: privateKeyBytes})
console.debug("Keypair 2 ", keyPair2)

test('signer identite cle', async () => {
    console.debug("Signer identite cle")

    const domaine = 'DummyDomaine', 
          identificateurs_document = {'type': 'Test'},
          hachage_bytes = 'zSEfXUEyon2ZEMdbCtfGmRSjo4Ni4FDiAGqkLce7MxGhtLgEUiPafkhWZoC4kz1oLXuCzcZN5QG4EwCB2YYdgBxSjYFnGU'

    const signature = await signerIdentiteCle(privateKeyBytes, domaine, identificateurs_document, hachage_bytes)
    console.debug("Signature cle ", signature)

    expect(signature).toBe('mAhNnp9baJmnf1jrhZyNyol3DDVsl3BB7jPhFDSp1gWT5HO7XaNDFlrq4pqUxdEn4w4WJXL2GYdy+r57Nm7zwgAY')
    // expect(messageFormatte.sig).toBeDefined()
    // expect(messageFormatte.estampille).toBeDefined()
    // expect(messageFormatte.kind).toBe(KIND_DOCUMENT)
    // expect(messageFormatte.contenu).toBe('{"texte":"Bonjour","valeur":1}')
    // expect(messageFormatte.routage).not.toBeDefined()
})