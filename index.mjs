import { blindSignaturesSetup } from './blind-signatures.mjs'

const { privateKey, publicKeyG1, publicKeyG2 } =
    blindSignaturesSetup()

console.log('Private key:', privateKey)
console.log('Public key in G1:', publicKeyG1)
console.log('Public key in G2:', publicKeyG2)