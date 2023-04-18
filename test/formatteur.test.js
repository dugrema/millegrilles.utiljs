require('./hachage.config')

const fs = require('fs')

const { FormatteurMessage } = require('../src/formatteurMessage')
const { verifierMessage } = require('../src/validateurMessage')
const forgecommon = require('../src/forgecommon')
const { pki } = require('@dugrema/node-forge')
const {KIND_DOCUMENT, KIND_REQUETE} = require('../src/constantes')

const certPem = new TextDecoder().decode(fs.readFileSync('/var/opt/millegrilles/secrets/pki.instance.cert')),
      clePem = new TextDecoder().decode(fs.readFileSync('/var/opt/millegrilles/secrets/pki.instance.key')),
      certCorePem = new TextDecoder().decode(fs.readFileSync('/var/opt/millegrilles/secrets/pki.core.cert'))

const chainePem = forgecommon.splitPEMCerts(certPem),
      certCore = pki.certificateFromPem(certCorePem)

test('formatter', async () => {
    console.debug("Formatter")

    const formatteur = new FormatteurMessage(chainePem, clePem, {})
    const ready = await formatteur.ready()

    console.debug("Formatteur ready : ", ready)
    
    const message = {texte: 'Bonjour', valeur: 1}

    const messageFormatte = await formatteur.formatterMessage(KIND_DOCUMENT, message, {ajouterCertificat: true})
    console.debug("Message formatte : ", messageFormatte)

    expect(messageFormatte.id).toBeDefined()
    expect(messageFormatte.sig).toBeDefined()
    expect(messageFormatte.estampille).toBeDefined()
    expect(messageFormatte.kind).toBe(KIND_DOCUMENT)
    expect(messageFormatte.contenu).toBe('{"texte":"Bonjour","valeur":1}')
    expect(messageFormatte.routage).not.toBeDefined()
})

test('formatterRoutage', async () => {
    console.debug("Formatter")

    const formatteur = new FormatteurMessage(chainePem, clePem, {})
    const ready = await formatteur.ready()

    console.debug("Formatteur ready : ", ready)
    
    const message = {texte: 'Bonsoir', valeur: 2}

    const messageFormatte = await formatteur.formatterMessage(
        KIND_REQUETE, message, {domaine: 'DomaineDummy', action: 'ActionDummy', ajouterCertificat: true})
    
    console.debug("Message formatte : ", messageFormatte)

    expect(messageFormatte.id).toBeDefined()
    expect(messageFormatte.sig).toBeDefined()
    expect(messageFormatte.estampille).toBeDefined()
    expect(messageFormatte.kind).toBe(KIND_REQUETE)
    expect(messageFormatte.contenu).toBe('{"texte":"Bonsoir","valeur":2}')
    expect(messageFormatte.routage).toEqual({domaine: 'DomaineDummy', action: 'ActionDummy'})
})

test('formatter kind manquant', async () => {
    const formatteur = new FormatteurMessage(chainePem, clePem, {})
    await formatteur.ready()
    const message = {texte: 'Bonjour', valeur: 1}
    await expect(formatteur.formatterMessage(message)).rejects.toThrow('kind doit etre un int')
})

test('verifier message', async () => {
    const formatteur = new FormatteurMessage(chainePem, clePem, {})
    await formatteur.ready()
    const message = {texte: 'Bonjour', valeur: 1}
    const messageFormatte = await formatteur.formatterMessage(KIND_DOCUMENT, message)
    
    const resultat = await verifierMessage(messageFormatte)
    console.debug("Resultat verification : ", resultat)
    await expect(resultat).toBe(true)
})

test('verifier message certificat', async () => {
    const formatteur = new FormatteurMessage(chainePem, clePem, {})
    await formatteur.ready()
    const message = {texte: 'Bonjour', valeur: 1}
    const messageFormatte = await formatteur.formatterMessage(KIND_DOCUMENT, message)
    const resultat = await verifierMessage(messageFormatte, {certificat: formatteur.cert})
    console.debug("Resultat verification : ", resultat)
    await expect(resultat).toBe(true)
})

test('verifier message sample1', async () => {
    const certificat = pki.certificateFromPem(certPem)
    const resultat = await verifierMessage(MESSAGE_SAMPLE1, {certificat})
    await expect(resultat).toBe(true)
})

test('verifier message id corrompu', async () => {
    // Corrompre
    const messageFormatte = {...MESSAGE_SAMPLE1, id: '7cae0bdd47f3e6a1a08a73eee76fc12d94846205eb70c457ae16e5a1ac408dd6'}
    await expect(verifierMessage(messageFormatte)).rejects.toThrow('signature')
})

test('verifier message sig corrompu', async () => {
    // Corrompre
    const messageFormatte = {...MESSAGE_SAMPLE1, sig: '18ef4f9767106478eb9fd7fb2edb59360d76037f19faba7ab9edebac4b6b69fc56d9b57410003f7545f411fe775a1c8efb2980bb25fbf359635412993530f509'}
    await expect(verifierMessage(messageFormatte)).rejects.toThrow('signature')
})

test('verifier message contenu corrompu', async () => {
    // Corrompre
    const messageFormatte = {...MESSAGE_SAMPLE1, estampille: 1681836713}
    await expect(verifierMessage(messageFormatte)).rejects.toThrow('Hachage')
})

test('verifier message certificat pubkey mismatch', async () => {
    await expect(verifierMessage(MESSAGE_SAMPLE1, {certificat: certCore})).rejects.toThrow('mismatch certificat')
})

const MESSAGE_SAMPLE1 = {
    pubkey: '7cae0bdd47f3e6a1a08a73eee76fc12d94846205eb70c457ae16e5a1ac408dd6',
    estampille: 1681837817,
    kind: 1,
    contenu: '{"texte":"Bonsoir","valeur":2}',
    routage: { action: 'ActionDummy', domaine: 'DomaineDummy' },
    id: '8da02266610cbc42ffd8b5638fb62048a6db40ecbc179ca86a63e8deda68740d',
    sig: '9f6fc2eb233cbbbaff2c2e852c146bf7b9227004ed0173d2a9057d4e567de850cdb1a51ce187f4e61001d4c1d29c2687183135be4f417aae583123efc6bdd806'
}
