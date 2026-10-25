import {
    blindSignaturesSetup,
    blindSignaturesPack
} from './blind-signatures.mjs'

const { privateKey, publicKeyG1, publicKeyG2 } =
    blindSignaturesSetup()

const message = 'Hello World'
const encodedMessage = new TextEncoder().encode(message)

const { blindPoint, randomScalar } =
    blindSignaturesPack(encodedMessage)

console.log('Blinded message:', blindPoint)
console.log('Random scalar:', randomScalar)

console.log('Private key:', privateKey)
console.log('Public key in G1:', publicKeyG1)
console.log('Public key in G2:', publicKeyG2)