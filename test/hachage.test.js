const hachage = require('../src/hachage')
require('./hachage.config')

test('hachage 1', async () => {
    console.debug("Hachage")

    const message = new TextEncoder().encode("Un message simple")
    const hachageResultat = await hachage.hacher(message)
    console.debug("Resultat hachage : %O", hachageResultat)

    await hachage.verifierHachage(hachageResultat, message)
})
