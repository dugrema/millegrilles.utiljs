const MIMETYPE_EXT_MAP = require('../res/mimetype_ext.json')
const EXT_MIMETYPE_MAP = require('../res/ext_mimetype.json')

const CONST_COMMANDE_AUTH = 0x1,        // Authentification
      CONST_COMMANDE_SIGNER_CSR = 0x2   // Demande de signature d'un CSR

function getMimetypeExtMap() {
    return MIMETYPE_EXT_MAP
}

function getExtMimetypeMap() {
    return EXT_MIMETYPE_MAP
}

module.exports = {
  CONST_COMMANDE_AUTH, CONST_COMMANDE_SIGNER_CSR,
  getMimetypeExtMap, getExtMimetypeMap
}
