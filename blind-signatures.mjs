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

export function blindSignaturesPack(encodedMessage) {
    // Hash the message to a point in G2: H(m)
    const hashedMessage =
        bls12_381.longSignatures.hash(encodedMessage)

    // Generate a fresh random scalar r
    const randomScalar =
        bytesToNumberBE(bls12_381.utils.randomSecretKey())

    // Calculate rP, where P is the generator of G2
    const blindingPoint =
        bls12_381.G2.Point.BASE.multiply(randomScalar)

    // Blind the message: H(m) + rP
    const blindPoint = hashedMessage.add(blindingPoint)

    return { blindPoint, randomScalar }
}

export function blindSignaturesSign(privateKey, blindPoint) {
    // Sign the blinded point: xS * [H(m) + rP]
    return bls12_381.longSignatures.sign(blindPoint, privateKey)
}