import {
    blindSignaturesSetup,
    blindSignaturesPack,
    blindSignaturesSign,
    blindSignaturesUnpack
} from './blind-signatures.mjs'
import { bls12_381 } from '@noble/curves/bls12-381.js'

const { privateKey, publicKeyG1, publicKeyG2 } =
    blindSignaturesSetup()

const message = 'Hello World'
const encodedMessage = new TextEncoder().encode(message)

const { blindPoint, randomScalar } =
    blindSignaturesPack(encodedMessage)

// Recalculate H(m)
const hashedMessage = 
    bls12_381.longSignatures.hash(encodedMessage)

// Remove rP from the blinded point
const recoveredPoint = blindPoint.subtract(
    bls12_381.G2.Point.BASE.multiply(randomScalar)
)

console.log(
    'Removing the blinding recovers H(m)?',
    recoveredPoint.equals(hashedMessage)
)

const blindSignature =
    blindSignaturesSign(privateKey, blindPoint)

console.log('Blinded signature:', blindSignature)

// Check that the signer correctly signed the blinded point
const verified = bls12_381.longSignatures.verify(
    blindSignature,
    blindPoint,
    publicKeyG1
)

console.log('Blinded signature verified?', verified)

// Producer: unblind using the signer's G2 public key
const signature = blindSignaturesUnpack(
    publicKeyG2,
    randomScalar,
    blindSignature
)

// Verify against the ORIGINAL message hash using the G1 public key
const finalVerified = bls12_381.longSignatures.verify(
    signature,
    hashedMessage,
    publicKeyG1
)

console.log('Unblinded signature verified?', finalVerified)