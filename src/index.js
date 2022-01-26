// import * as validateurMessage from './validateurMessage'
// import * as formatteurMessage from './formatteurMessage'
// import * as forgecommon from './forgecommon'
// import * as constantes from './constantes'

// export { constantes, forgecommon, formatteurMessage, validateurMessage }

// export * from './certificats'
// export * from './chiffrage.ciphers'
// export * from './chiffrage'
// export * as ed25519 from './chiffrage.ed25519'
// export * from './hachage'
// export * from './idmg'

//

const validateurMessage = require('./validateurMessage')
const formatteurMessage = require('./formatteurMessage')
const forgecommon = require('./forgecommon')
const constantes = require('./constantes')

const certificats = require('./certificats')
const ciphers = require('./chiffrage.ciphers')
const chiffrage = require('./chiffrage')
const ed25519 = require('./chiffrage.ed25519')
const hachage = require('./hachage')
const idmg = require('./idmg')

const exportVals = {
    constantes, forgecommon, formatteurMessage, validateurMessage, ed25519,
    ...certificats,
    ...ciphers,
    ...chiffrage,
    ...hachage,
    ...idmg,
}

module.exports = exportVals

