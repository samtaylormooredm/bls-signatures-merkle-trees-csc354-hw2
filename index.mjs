import { ed25519 } from '@noble/curves/ed25519.js'
import {
    blindSignaturesPack,
    blindSignaturesUnpack
} from './blind-signatures.mjs'
import {
    registerVote,
    getProof,
    getVoterProof,
    authorizeVote,
    submitVote,
    calculateOutcome,
    publicKeyG2
} from './voting.mjs'

// Register three voters with their intended choices.
const voters = []

for (const vote of ['Y', 'N', 'Y']) {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)

    registerVote(publicKey)
    voters.push({ publicKey, vote })
}

// Close registration and establish the AP's trusted root.
const root = getProof()
console.log('Registration root:', root.toString('hex'))

for (const voter of voters) {
    // Obtain proof that the voter is registered.
    const merklePath = getVoterProof(voter.publicKey)

    // Blind the vote.
    const encodedVote = new TextEncoder().encode(voter.vote)
    const { blindPoint, randomScalar } =
        blindSignaturesPack(encodedVote)

    // AP verifies membership and signs the blinded vote.
    const blindSignature = authorizeVote(blindPoint, merklePath)

    // Voter unblinds the signature.
    const signature = blindSignaturesUnpack(
        publicKeyG2,
        randomScalar,
        blindSignature
    )

    // Submit the signed choice without voter identity.
    submitVote({ vote: voter.vote, signature })
}

// Verify submitted signatures and count valid votes.
console.log('Final outcome:', calculateOutcome())