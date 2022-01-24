// // Charger subtle si disponible dans le navigateur
// export function detecterSubtle() {
//   var crypto
//   if( typeof(window) !== 'undefined' && window.crypto) {
//     // Navigateur / client
//     crypto = window.crypto
//   } else if( typeof(self) !== 'undefined' && self.crypto ) {
//     // Web worker
//     crypto = self.crypto
//   }

//   var subtle = null, getRandomValues = null
//   if(crypto) {
//     subtle = crypto.subtle
//     getRandomValues = buffer => {crypto.getRandomValues(buffer)}
//     // console.debug("Crypto trouve, subtle : %O, getRandomValues: %O", subtle, getRandomValues)
//   }

//   return {subtle, getRandomValues}
// }
// const { getRandomValues: _getRandomValues } = detecterSubtle()

// export async function chiffrerSubtle(contenu, opts) {
//   opts = opts || {}

//   // Generer IV, password au besoin
//   var tailleRandom = 12
//   // if( !opts.password ) { tailleRandom += 32 }
//   const randomBytes = new Uint8Array(tailleRandom);
//   if(opts.DEBUG) console.debug("_getRandomValues : %O", _getRandomValues)
//   await _getRandomValues(randomBytes)
//   const iv = randomBytes.slice(0, 12)
//   // const password = opts.password || randomBytes.slice(12)
//   // console.debug("Password : %O, IV: %O", password, iv)

//   if(typeof(contenu) === 'string') {
//     // Encoder utf-8 en bytes
//     contenu = new TextEncoder().encode(contenu)
//   }

//   const cleSecreteSubtle = await _subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt'])
//   const password = await _subtle.exportKey('raw', cleSecreteSubtle)

//   // console.debug("Cle secrete subtle : %O\npassword: %O", cleSecreteSubtle, password)

//   var resultatBuffer = await _subtle.encrypt({...cleSecreteSubtle.algorithm, iv}, cleSecreteSubtle, contenu)
//   // console.debug("Resultat chiffrage : %O", resultatBuffer)

//   const resultatView = new Uint8Array(resultatBuffer)
//   const longueurBuffer = resultatView.length
//   const computeTag = resultatView.slice(longueurBuffer-16)
//   resultatBuffer = resultatView.slice(0, longueurBuffer-16)

//   // console.debug("Compute tag : %O\nCiphertext : %O", computeTag, resultatBuffer)

//   const hachage_bytes = await hacher(resultatBuffer, {hashingCode: 'sha2-512', encoding: 'base58btc'})

//   return {
//     ciphertext: resultatBuffer,
//     password,
//     meta: {
//       iv: String.fromCharCode.apply(null, multibase.encode('base64', iv)),
//       tag: String.fromCharCode.apply(null, multibase.encode('base64', computeTag)),
//       hachage_bytes,
//     },
//   }
// }

// export async function dechiffrerSubtle(ciphertext, password, iv, tag) {
//   const ivArray = multibase.decode(iv)
//   const tagArray = multibase.decode(tag)

//   // Concatener le tag au ciphertext - c'est le format requis par subtle
//   const concatBuffer = new Uint8Array(tagArray.length + ciphertext.byteLength)
//   concatBuffer.set(new Uint8Array(ciphertext), 0)
//   concatBuffer.set(new Uint8Array(tagArray), ciphertext.byteLength)

//   let secretKey = password
//   // Voir si le secret est deja en format subtle dechiffre
//   if(!secretKey.algorithm) {
//     // console.debug("!!! !!! !!! Importer cle secrete %O", password)
//     secretKey = await _subtle.importKey(
//       'raw',
//       password,
//       {name: 'AES-GCM', length: 256, iv: ivArray},
//       false,
//       ['decrypt']
//     )
//   } else {
//     // console.debug("!!! Cle subtle deja importee %O", password)
//   }


// export async function preparerCleSecreteSubtle(cleSecreteChiffree, iv, clePriveeSubtle) {

//   // console.debug("Dechiffrer cle %O avec %O", cleSecreteChiffree, clePriveeSubtle)
//   const password = await dechiffrerCleSecreteSubtle(clePriveeSubtle, cleSecreteChiffree)

//   const ivArray = multibase.decode(iv)

//   // console.debug("!!! !!! !!! Importer cle secrete %O", password)
//   return _subtle.importKey(
//     'raw',
//     password,
//     {name: 'AES-GCM', length: 256, iv: ivArray},
//     false,
//     ['decrypt']
//   )
// }

// export async function chiffrerCleSecreteSubtle(clePublique, cleSecrete, opts) {
//   opts = opts || {}
//   const DEBUG = opts.DEBUG
//   if(DEBUG) console.debug("Cle publique : %O, cle secrete : %O, opts: %O", clePublique, cleSecrete, opts)

//   const algorithm = opts.algorithm || 'RSA-OAEP',
//         hashFunction = opts.hashFunction || 'SHA-256'

//   var clePubliqueString = clePublique
//   if( clePublique.verify ) {
//     // C'est probablement le format nodeforge, on extrait la cle publique en
//     // format PEM pour la reimporter avec Subtle
//     const clePubliquePem = forgePki.publicKeyToPem(clePublique)
//     const regEx = /\n?\-{5}[A-Z ]+\-{5}\n?/g
//     clePubliqueString = clePubliquePem.replaceAll(regEx, '')
//     if(DEBUG) console.debug("Cle public string extraite du format nodeforge : %s", clePubliqueString)
//   }

//   var clePubliqueImportee = clePublique
//   if(clePublique.algorithm) {
//     // Format subtle, ok
//   } else if(clePublique.verify || typeof(clePublique) === 'string') {
//     // C'est probablement le format nodeforge, on extrait la cle publique en
//     // format PEM pour la reimporter avec Subtle
//     // var clePubliquePem = clePublique
//     // if(clePublique.verify) {
//     //   clePubliquePem = forgePki.publicKeyToPem(clePublique)
//     // }
//     //
//     // const regEx = /\n?\-{5}[A-Z ]+\-{5}\n?/g
//     // clePubliqueString = clePubliquePem.replaceAll(regEx, '')
//     // if(DEBUG) console.debug("Cle public string extraite du format nodeforge : %s", clePubliqueString)
//     //
//     // const clePubliqueBuffer = Buffer.from(clePubliqueString, 'base64')
//     //
//     // Importer la cle PEM en format subtle
//     clePubliqueImportee = await importerClePubliqueSubtle(clePublique)
//     if(DEBUG) console.debug("Cle publique importee avec subtle : %O", clePubliqueImportee)
//   } else {
//     throw new Error("Format de cle publique inconnue")
//   }

//   // var clePubliqueBuffer = Buffer.from(clePubliqueString, 'base64')
//   // if(DEBUG) console.debug("Cle publique buffer : %O", clePubliqueBuffer)
//   //
//   // // Importer la cle PEM en format subtle
//   // const clePubliqueImportee = await _subtle.importKey(
//   //   'spki',
//   //   clePubliqueBuffer,
//   //   {name: algorithm, hash: hashFunction},
//   //   false,  // export
//   //   ["encrypt"]
//   // )
//   if(DEBUG) console.debug("Cle publique importee avec subtle : %O", clePubliqueImportee)

//   // Chiffrer la cle secrete en utilisant la cle publique
//   const cleChiffree = await _subtle.encrypt(
//       {name: algorithm},
//       clePubliqueImportee,
//       cleSecrete
//     )
//   if(DEBUG) console.debug("Cle secrete chiffree %O", cleChiffree)

//   return new Uint8Array(cleChiffree)
// }

// export function importerClePriveeSubtle(clePrivee, opts) {
//   opts = opts || {},
//          usage = opts.usage || ['decrypt']
//   const algorithm = opts.algorithm || 'RSA-OAEP',
//         hashFunction = opts.hash || 'SHA-256'

//   // Note: pour signature : usage = ['sign'], algorithm = 'RSA-PSS', hash = 'SHA-512'

//   if(typeof(clePrivee) === 'string') {
//     // Assumer PEM, on importe directement
//     const regEx = /\n?\-{5}[A-Z ]+\-{5}\n?/g
//     clePrivee = clePrivee.replaceAll(regEx, '')

//     const clePriveeBuffer = Buffer.from(clePrivee, 'base64')

//     return _subtle.importKey(
//       'pkcs8',
//       clePriveeBuffer,
//       {name: algorithm, hash: hashFunction},
//       false,
//       usage
//     )
//   }

//   throw new Error("Format cle privee inconnu")
// }

// export function importerClePubliqueSubtle(clePublique, opts) {
//   opts = opts || {}
//   const usage = opts.usage || ['encrypt'],
//         DEBUG = opts.DEBUG

//   const algorithm = opts.algorithm || 'RSA-OAEP',
//         hashFunction = opts.hashFunction || 'SHA-256'

//   var clePubliquePem = clePublique
//   if(clePublique.verify) {
//     clePubliquePem = forgePki.publicKeyToPem(clePublique)
//   }

//   const regEx = /\n?\-{5}[A-Z ]+\-{5}\n?/g
//   const clePubliqueString = clePubliquePem.replaceAll(regEx, '')
//   if(DEBUG) console.debug("Cle public string extraite du format nodeforge : %s", clePubliqueString)

//   const clePubliqueBuffer = Buffer.from(clePubliqueString, 'base64')

//   // Importer la cle PEM en format subtle
//   return _subtle.importKey(
//     'spki',
//     clePubliqueBuffer,
//     {name: algorithm, hash: hashFunction},
//     false,  // export
//     ["encrypt"]
//   )
// }