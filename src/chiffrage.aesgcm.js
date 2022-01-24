// export async function chiffrerForge(contenu, opts) {
//   opts = opts || {}

//   const cipher = await creerCipher(opts)
//   const ciphertext = cipher.update(contenu)
//   const resultatChiffrage = await cipher.finish()
//   resultatChiffrage.ciphertext = ciphertext

//   return resultatChiffrage
// }

// export function dechiffrer(ciphertext, password, iv, tag) {
//   // Contenu doit etre : string multibase ou Buffer
//   // Les autres parametres doivent tous etre format multibase
//   if(_subtle) {
//     return dechiffrerSubtle(ciphertext, password, iv, tag)
//   } else {
//     return dechiffrerForge(ciphertext, password, iv, tag)
//   }

// }

// export function dechiffrerForge(ciphertext, password, iv, tag) {
//   const decipher = creerDecipher(password, iv, tag)
//   var output = decipher.update(ciphertext)
//   const outputFinishBlock = decipher.finish()
//   return Buffer.concat([output, outputFinishBlock])
// }

//   // Dechiffrer - note : lance une erreur si le contenu est invalide
//   var resultat = await _subtle.decrypt(
//     {name: 'AES-GCM', length: 256, iv: ivArray},
//     secretKey,
//     concatBuffer
//   )

//   if( ! Buffer.isBuffer(resultat) ) {
//     resultat = Buffer.from(resultat)
//   }
//   return new Uint8Array(resultat)
// }

// export async function creerCipher(opts) {
//   opts = opts || {}

//   // Generer IV et password random
//   var password = opts.password
//   if( ! password ) {
//     password = await forgeRandom.getBytes(32)
//   }
//   const iv = await forgeRandom.getBytes(12)

//   const cipher = forgeCipher.createCipher('AES-GCM', password)
//   const hacheur = new Hacheur({hash: 'sha2-512', encoding: 'base58btc'})
//   cipher.start({iv})

//   // Creer objet wrapper pour le cipher
//   const cipherWrapper = {
//     update: data => {

//       if(typeof(data) === 'string') {
//         data = forgeUtil.createBuffer(forgeUtil.encodeUtf8(data), 'utf8')
//       } else {
//         // Convertir AB vers byte string
//         data = forgeUtil.createBuffer(data, 'raw')
//       }

//       cipher.update(data)

//       const ciphertext = Buffer.from(cipher.output.getBytes(), 'binary')
//       // console.debug("Ciphertext : %O", ciphertext)
//       hacheur.update(ciphertext)

//       return ciphertext
//     },
//     finish: ()=>_fermerCipher(cipher, password, iv, hacheur)
//   }

//   return cipherWrapper
// }

// async function _fermerCipher(cipher, password, iv, hacheur) {
//   cipher.finish()

//   var ciphertext = cipher.output
//   const tag = cipher.mode.tag

//   // Convertir en buffer
//   ciphertext = Buffer.from(ciphertext.getBytes(), 'binary')
//   hacheur.update(ciphertext)

//   // const hachage_bytes = await hacher(ciphertext, {hashingCode: 'sha2-512', encoding: 'base64'})
//   const hachage_bytes = hacheur.finalize()

//   return {
//     ciphertextFinalBlock: ciphertext,
//     password: Buffer.from(password, 'binary'),
//     meta: {
//       iv: String.fromCharCode.apply(null, multibase.encode('base64', Buffer.from(iv, 'binary'))),
//       tag: String.fromCharCode.apply(null, multibase.encode('base64', Buffer.from(tag.getBytes(), 'binary'))),
//       hachage_bytes,
//     }
//   }
// }

// export function creerDecipher(password, iv, tag) {

//   // console.debug("Params IV: %O, TAG: %O", iv, tag)
//   const ivArray = multibase.decode(iv)
//   const tagArray = multibase.decode(tag)
//   // console.debug("Array IV: %O, TAG: %O", ivArray, tagArray)

//   const passwordBytes = String.fromCharCode.apply(null, password)
//   const ivBytes = String.fromCharCode.apply(null, ivArray)
//   const tagBytes = String.fromCharCode.apply(null, tagArray)

//   // console.debug("IV : %O, tag: %O", ivBytes, tagBytes)

//   var decipher = forgeCipher.createDecipher('AES-GCM', passwordBytes)
//   decipher.start({
//     iv: ivBytes,
//     tag: tagBytes,
//   })

//   const decipherWrapper = {
//     update: ciphertext => {
//       ciphertext = forgeUtil.createBuffer(ciphertext, 'raw')
//       decipher.update(ciphertext)
//       return Buffer.from(decipher.output.getBytes(), 'binary')
//     },
//     finish: () => {
//       var pass = decipher.finish()
//       if(pass) {
//         return Buffer.from(decipher.output.getBytes(), 'binary')
//       } else {
//         throw new Error("Erreur de dechiffrage - invalid tag")
//       }
//     }
//   }

//   return decipherWrapper
// }

// export function chiffrerCleSecreteForge(clePublique, cleSecrete, opts) {
//   opts = opts || {}
//   const DEBUG = opts.DEBUG
//   if(DEBUG) console.debug("Cle publique : %O, cle secrete : %O, opts: %O", clePublique, cleSecrete, opts)

//   const algorithm = opts.algorithm || 'RSA-OAEP',
//         hashFunction = opts.hashFunction || 'SHA-256'

//   cleSecrete = forgeUtil.createBuffer(cleSecrete, 'raw').getBytes()

//   var cleSecreteChiffree = clePublique.encrypt(cleSecrete, algorithm, {md: forgeMd.sha256.create()})
//   cleSecreteChiffre = Buffer.from(cleSecreteChiffree, 'binary')

//   if(DEBUG) console.debug("Cle secrete chiffree %O", cleSecreteChiffre)

//   return new Uint8Array(cleSecreteChiffre)
// }

// export function dechiffrerCleSecreteForge(clePrivee, cleSecreteChiffree, opts) {
//   opts = opts || {}
//   const algorithm = opts.algorithm || 'RSA-OAEP',
//         hashFunction = opts.hashFunction || 'SHA-256',
//         DEBUG = opts.DEBUG

//   if(DEBUG) console.debug("Cle secrete chiffree originale : %O", cleSecreteChiffree)

//   if(typeof(cleSecreteChiffree) === 'string') {
//     // Assumer format multibase
//     cleSecreteChiffree = multibase.decode(cleSecreteChiffree)
//     cleSecreteChiffree = Buffer.from(cleSecreteChiffree, 'binary')
//     if(DEBUG) console.debug("Cle secrete chiffree bytes : %s", cleSecreteChiffree)
//   }
//   cleSecreteChiffree = forgeUtil.createBuffer(cleSecreteChiffree, 'raw').getBytes()

//   if(DEBUG) console.debug("Cle privee : cle secrete chiffree : %O", cleSecreteChiffree)
//   var cleSecrete = clePrivee.decrypt(cleSecreteChiffree, algorithm, {md: forgeMd.sha256.create()})
//   cleSecrete = Buffer.from(cleSecrete, 'binary')

//   return new Uint8Array(cleSecrete)
// }

// export async function dechiffrerCleSecreteSubtle(clePrivee, cleSecreteChiffree, opts) {
//   opts = opts || {}
//   const algorithm = opts.algorithm || 'RSA-OAEP',
//         DEBUG = opts.DEBUG

//   if(typeof(cleSecreteChiffree) === 'string') {
//     // Assumer format multibase
//     cleSecreteChiffree = multibase.decode(cleSecreteChiffree)
//   }

//   if(typeof(clePrivee) === 'string') {
//     // Convertir PEM en cle subtle
//     clePrivee = await importerClePriveeSubtle(clePrivee, {})
//   }

//   if(DEBUG) console.debug("Cle privee : %O", clePrivee)
//   const cleSecreteDechiffree = await _subtle.decrypt(
//       {name: clePrivee.algorithm.name},
//       clePrivee,
//       cleSecreteChiffree
//     )

//   return new Uint8Array(cleSecreteDechiffree)
// }
