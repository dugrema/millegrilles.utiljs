import {setHacheurs} from '../src/hachage'
import blake2 from 'blake2'
import { createHash as cryptoCreateHash } from 'crypto'

// Injecte les methodes de hachage natives avec setHacheurs pour la librairie utiljs

const blake2HachageConstructor = algo => {
    const hacheur = blake2.createHash(algo)
    return {
        update: buffer => hacheur.update(buffer),
        finalize: () => hacheur.digest(),
        digest: async buffer => { await hacheur.update(buffer); return await hacheur.digest() }
    }
}

const cryptoHachageConstructor = algo => {
    const hacheur = cryptoCreateHash(algo)
    return {
        update: buffer => hacheur.update(buffer),
        finalize: () => hacheur.digest(),
        digest: async buffer => { await hacheur.update(buffer); return await hacheur.digest() }
    }
}

const hacheurs = {
    // Nodejs Crypto
    'sha256': () => cryptoHachageConstructor('sha256'),
    'sha2-256': () => cryptoHachageConstructor('sha256'),
    'sha512': () => cryptoHachageConstructor('sha512'),
    'sha2-512': () => cryptoHachageConstructor('sha512'),

    // Blake2
    'blake2s256': () => blake2HachageConstructor('blake2s'),
    'blake2s-256': () => blake2HachageConstructor('blake2s'),
    'blake2b512': () => blake2HachageConstructor('blake2b'),
    'blake2b-512': () => blake2HachageConstructor('blake2b'),
}

setHacheurs(hacheurs)

// export { hacheurs }