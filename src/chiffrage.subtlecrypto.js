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