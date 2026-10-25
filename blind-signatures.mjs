import { bls12_381 } from '@noble/curves/bls12-381.js'
import { bytesToNumberBE } from '@noble/curves/utils.js'

export function blindSignaturesSetup() {
    // Generate the signer's private key as bytes
    const privateKey = bls12_381.utils.randomSecretKey()

    // Convert to BigInt for point multiplication
    const privateScalar = bytesToNumberBE(privateKey)

    // Public key in G1: xS * G
    const publicKeyG1 =
        bls12_381.longSignatures.getPublicKey(privateKey)

    // Public key in G2: xS * P
    const publicKeyG2 =
        bls12_381.G2.Point.BASE.multiply(privateScalar)

    return { privateKey, publicKeyG1, publicKeyG2 }
}