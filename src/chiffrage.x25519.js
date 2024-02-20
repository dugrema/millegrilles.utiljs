const { generateKeyPair, sharedKey } = require('curve25519-js')
const { getRandom } = require('./random')

/**
 * 
 * @returns {private: Uint8Array, public: Uint8Array}
 */
function genererKeyPairX25519() {

    const seed = getRandom(32)

    // Generer private, public (Uint8Array)
    return generateKeyPair(seed)
}

async function calculerSharedKey(private, peer) {
    return sharedKey(private, peer)
}

module.exports = {
    genererKeyPairX25519, calculerSharedKey,
}
