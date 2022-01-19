export function getRandom(nbBytes) {
    let abView
    if(window.crypto) {
        // Navigateur
        const aleatAB = new ArrayBuffer(nbBytes);
        abView = new Uint8Array(aleatAB)
        window.crypto.getRandomValues(abView)
    } else {
        // Forge default
        let rndForgeBuffer = forge.random.getBytesSync(nbBytes).getBytes()
        // Convertir en TypedArray
        abView = new Uint8Array(String.fromCharCode.apply(null, rndForgeBuffer))
    }
    return abView
}
