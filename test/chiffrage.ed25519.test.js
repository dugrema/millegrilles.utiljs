/* Tests de chiffrage asymmetrique avec cles EdDSA25519 (-> X25519) */
const chiffrage = require('../src/chiffrage.ed25519')
// require('./hachage.config')
require('./chiffrage.config')

const multibase = require('multibase')
const { ed25519 } = require('@dugrema/node-forge')
const { convertPublicKey } = require('ed2curve')
// const { ed25519 } = nodeforge,
//       { convertPublicKey } = ed2curve

test('test chiffrage cle secrete', () => {
    console.debug("Test chiffrage")

    expect.assertions(3)
    expect(()=>chiffrage.genererCleSecrete()).rejects.toThrow('utiljs chiffrage.ed25519 Cle publique null/undefined')
    expect(()=>chiffrage.genererCleSecrete(1)).rejects.toThrow('utiljs chiffrage.ed25519 Format de cle publique inconnu')
    expect(chiffrage.genererCleSecrete(CERT_PEM1)).resolves.not.toBeUndefined()
    
})

test('deriver cle secrete', async () => {
    expect.assertions(2)
    expect(await chiffrage.deriverCleSecrete(PEER_2_PRIVE, PEER_1_PUBLIC_X25519, {ed25519: false})).toEqual(CLE_SECRETE_1)
    expect(await chiffrage.deriverCleSecrete(PEER_1_PRIVE, PEER_2_PUBLIC_X25519, {ed25519: false})).toEqual(CLE_SECRETE_1)
})

test('rechiffrer cle secrete', async () => {
    expect.assertions(1)
    const cleChiffree = await chiffrage.chiffrerCle(CLE_SECRETE_2, multibase.decode(PEER_1_PUBLIC_X25519), {ed25519: false})
    console.debug("Cle chiffree : %O", cleChiffree)
    const cleDechiffree = await chiffrage.dechiffrerCle(multibase.decode(cleChiffree), PEER_1_PRIVE)
    console.debug("Cle originale\n%O\Cle dechiffree\n%O", CLE_SECRETE_2, cleDechiffree)
    expect(CLE_SECRETE_2).toEqual(new Uint8Array(cleDechiffree))
})

test('rederiver cle secrete millegrille', async () => {
    expect.assertions(1)
    const cleChiffree = await chiffrage.genererCleSecrete(multibase.decode(PEER_1_PUBLIC_X25519), {ed25519: false})
    const peerPublic = cleChiffree.peer
    const cleDechiffree = await chiffrage.dechiffrerCle(multibase.decode(peerPublic), PEER_1_PRIVE)

    console.debug("Cle originale\n%O\Cle dechiffree\n%O", cleChiffree.cle, cleDechiffree)
    expect(cleChiffree.cle).toEqual(new Uint8Array(cleDechiffree))
})

const CERT_PEM1 = `
-----BEGIN CERTIFICATE-----
MIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs
ZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV
BAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I
/TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G
A1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p
MJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI
-----END CERTIFICATE-----
`

const PEER_1_PUBLIC_X25519 = 'mPMbhxr+wKcmSyhUH4fqY1jxioTvKXvHAm2pnjvG6QSU'
const PEER_1_PRIVE = multibase.decode('mJVgu7/9r0u6U3FGxaTGhoRhyIoNb2eWabnFoMMkklyJwWT761HqBUDbOLQXxsLF0BqTrUnmkvGEnptgoj48vvg')
const PEER_2_PUBLIC_X25519 = 'mZkNn2EqdRLp+iOuiWhM7zRBTpoog89EJDlMB/uos5Ds'
const PEER_2_PRIVE = multibase.decode('mjs+Y266uF6nRinRlINqfVyedtpVr3EzydQdgOU/BBq0pAcsGar9BUdasq7QtubAyqc2iLSBEypThvrECajMY3g')
const CLE_SECRETE_1 = new Uint8Array(Buffer.from([161, 207, 216, 188, 200, 57, 144, 115, 103, 200, 227, 136, 69, 206, 50, 58, 248, 195, 23, 55, 227, 236, 208, 148, 0, 7, 153, 224, 14, 251, 18, 151]))
const CLE_SECRETE_2 = new Uint8Array(32)  // All zeros

function genererTestData() {
    const keyPair1 = ed25519.generateKeyPair()
    console.debug("Peer 1")
    printKey(keyPair1)

    const keyPair2 = ed25519.generateKeyPair()
    console.debug("Peer 2")
    printKey(keyPair2)
}

function printKey(keyPair) {
    const peerPublicX25519 = convertPublicKey(keyPair.publicKey.publicKeyBytes)
    const peerPublic = String.fromCharCode.apply(null, multibase.encode('base64', peerPublicX25519)),
          peerPrive = String.fromCharCode.apply(null, multibase.encode('base64', keyPair.privateKey.privateKeyBytes))
    console.debug("Public x25519: %s\ncle privee ed25519: %s", peerPublic, peerPrive)
}

// genererTestData()