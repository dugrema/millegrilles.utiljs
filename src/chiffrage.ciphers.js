// Conserve la liste des algorithmes de chiffrage optimises

// Section asymmetrique
/*
  Format
  { 
    _algo_: {

    }
  }
*/
// var _chiffrageAsymmetrique = {}
// export function setChiffrageAsymmetrique(chiffrageAsymmetrique, opts) {
//   opts = opts || {}
//   console.debug("Chiffrage asymmetrique : %O", chiffrageSymmetrique)
//   if(opts.update === true) {
//     _chiffrageAsymmetrique = {..._chiffrageAsymmetrique, ...chiffrageAsymmetrique}
//   } else {
//     _chiffrageAsymmetrique = chiffrageAsymmetrique
//   }
// }

// Section symmetrique
/*
Format cipher/decipher : 
  { 
    _algo_: {
      getCipher(key, nonce, opts) -> {update(data) -> ciphertext, finalize() -> {tag, hachage}}, 
      getDecipher(key, nonce, opts) -> {update(data) -> message, finalize(tag)}, 
      encrypt(key, nonce, data, opts) -> {ciphertext, tag, hachage}, 
      decrypt(key, nonce, data, tag, opts) -> message,
      nonceSize: int
    } 
  }
*/
var _chiffrageSymmetrique = {}

function setCiphers(chiffrageSymmetrique, opts) {
  opts = opts || {}
  console.debug("Chiffrage symmetrique : %O", chiffrageSymmetrique)
  if(opts.update === true) {
    _chiffrageSymmetrique = {..._chiffrageSymmetrique, ...chiffrageSymmetrique}
  } else {
    _chiffrageSymmetrique = chiffrageSymmetrique
  }
}

function getCipher(algo) {
  return _chiffrageSymmetrique[algo]
}

module.exports = { setCiphers, getCipher }
