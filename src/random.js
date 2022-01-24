import nodeforge from '@dugrema/node-forge'

export function getRandom(nbBytes) {
    var crypto
    if( typeof(window) !== 'undefined' && window.crypto) {
      // Navigateur / client
      crypto = window.crypto
    } else if( typeof(self) !== 'undefined' && self.crypto ) {
      // Web worker
      crypto = self.crypto
    }

    let abView
    if( crypto ) {
        // Navigateur main
        const aleatAB = new ArrayBuffer(nbBytes);
        abView = new Uint8Array(aleatAB)
        crypto.getRandomValues(abView)
    } else {
        // Forge default
        let rndForgeBuffer = nodeforge.random.getBytesSync(nbBytes)
        console.debug("!!! forge buffer? %O", rndForgeBuffer)
        // Convertir en TypedArray
        abView = new Uint8Array(Buffer.from(rndForgeBuffer, 'binary'))
    }
    return abView
}
