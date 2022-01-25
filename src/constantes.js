import MIMETYPE_EXT_MAP from '../res/mimetype_ext.json'
import EXT_MIMETYPE_MAP from '../res/ext_mimetype.json'

const CONST_COMMANDE_AUTH = 0x1,        // Authentification
      CONST_COMMANDE_SIGNER_CSR = 0x2   // Demande de signature d'un CSR

export function getMimetypeExtMap() {
    return MIMETYPE_EXT_MAP
}

export function getExtMimetypeMap() {
    return EXT_MIMETYPE_MAP
}

export default {
  CONST_COMMANDE_AUTH, CONST_COMMANDE_SIGNER_CSR,
  getMimetypeExtMap, getExtMimetypeMap
}
