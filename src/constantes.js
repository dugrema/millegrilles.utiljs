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

const KIND_DOCUMENT = 0,
      KIND_REQUETE = 1,
      KIND_COMMANDE = 2,
      KIND_TRANSACTION = 3,
      KIND_REPONSE = 4,
      KIND_EVENEMENT = 5,
      KIND_REPONSE_CHIFFREE = 6

const KINDS_ROUTAGE = [KIND_REQUETE, KIND_COMMANDE, KIND_TRANSACTION, KIND_EVENEMENT]

module.exports = {
  CONST_COMMANDE_AUTH, CONST_COMMANDE_SIGNER_CSR,
  getMimetypeExtMap, getExtMimetypeMap,
  KIND_DOCUMENT, KIND_REQUETE, KIND_COMMANDE, KIND_TRANSACTION, KIND_REPONSE, KIND_EVENEMENT, KIND_REPONSE_CHIFFREE,
  KINDS_ROUTAGE,
}
