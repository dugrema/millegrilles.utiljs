/* Facade pour crypto de nodejs. */
import crypto from 'crypto'
import {setCiphers} from '../src/chiffrage'

console.info("Ciphers disponibles : %s", crypto.getCiphers().reduce((liste, item)=>{
    return liste + '\n' + item
}, ''))


function creerCipherXchacha20Poly1305(key, nonce) {
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
    let tag = null
    return {
        update: data => cipher.update(data),
        final: () => {
            cipher.final();
            tag = cipher.getAuthTag()
            return tag
        },
        tag: () => tag
    }
}

function creerDecipherXchacha20Poly1305(key, nonce) {
    const cipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
    let tag = null
    return {
        update: data => cipher.update(data),
        final: () => {
            cipher.final();
            tag = cipher.getAuthTag()
            return tag
        },
        tag: () => tag
    }
}

const ciphers = {
    // Nodejs Crypto
    'xchacha20poly1305': (key, nonce) => creerCipherXchacha20Poly1305(key, nonce),
}

const deciphers = {
    // Nodejs Crypto
    'xchacha20poly1305': (key, nonce) => creerDecipherXchacha20Poly1305(key, nonce),
}

setCiphers(ciphers, deciphers)