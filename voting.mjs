import { createHash } from 'node:crypto'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { MerkleTree } from './merkle_tree.mjs'
import {
    blindSignaturesSetup,
    blindSignaturesSign
} from './blind-signatures.mjs'

const hasher = (data) =>
    createHash('sha256').update(data).digest()

// Registration Provider (RP)
const bottomLevel = 3
const registrationTree = new MerkleTree(bottomLevel, hasher)
let registrationClosed = false

// Authorization Provider (AP)
const signer = blindSignaturesSetup()

export const publicKeyG1 = signer.publicKeyG1
export const publicKeyG2 = signer.publicKeyG2

let authorizedRoot = null
const authorizedVoters = new Set()

// Tally Provider (TP)
const submittedVotes = []

export function registerVote(publicKey) {
    if (registrationClosed) {
        throw new Error('Registration is closed')
    }

    const encodedPublicKey = Buffer.from(publicKey)

    if (registrationTree.getBottomIndex(encodedPublicKey) !== -1) {
        throw new Error('Voter is already registered')
    }

    const index = registrationTree.leaves.length
    registrationTree.append(encodedPublicKey)

    return index
}

export function getProof() {
    // Close registration and give the AP a fixed root.
    if (!registrationClosed) {
        authorizedRoot = Buffer.from(registrationTree.getRoot())
        registrationClosed = true
    }

    return Buffer.from(authorizedRoot)
}

// Extra helper: the RP supplies an individual voter's membership proof.
export function getVoterProof(publicKey) {
    if (!registrationClosed) {
        throw new Error('Close registration with getProof() first')
    }

    const encodedPublicKey = Buffer.from(publicKey)
    const index = registrationTree.getBottomIndex(encodedPublicKey)

    if (index === -1) {
        throw new Error('Voter is not registered')
    }

    const [, siblings, isLeft] = registrationTree.getProof(index)

    return {
        leafHash: hasher(encodedPublicKey),
        siblings: siblings.map(hash => Buffer.from(hash)),
        isLeft: [...isLeft]
    }
}

export function authorizeVote(blindedVote, merklePath) {
    if (!registrationClosed) {
        throw new Error('Registration is still open')
    }

    const { leafHash, siblings, isLeft } = merklePath

    if (
        siblings.length !== bottomLevel ||
        isLeft.length !== bottomLevel ||
        !isLeft.every(position => typeof position === 'boolean')
    ) {
        throw new Error('Invalid Merkle proof')
    }

    // Reconstruct the root using the supplied leaf hash and path.
    let currentHash = Buffer.from(leafHash)

    for (let i = 0; i < siblings.length; i++) {
        const sibling = Buffer.from(siblings[i])

        const left = isLeft[i] ? sibling : currentHash
        const right = isLeft[i] ? currentHash : sibling

        currentHash = hasher(Buffer.concat([left, right]))
    }

    // The AP uses only its saved root, not the RP's tree.
    if (!currentHash.equals(authorizedRoot)) {
        throw new Error('Invalid Merkle proof')
    }

    // Identify the registered voter by their leaf hash.
    const voterID = Buffer.from(leafHash).toString('hex')

    if (authorizedVoters.has(voterID)) {
        throw new Error('Voter has already received authorization')
    }

    const blindSignature = blindSignaturesSign(
        signer.privateKey,
        blindedVote
    )

    // Mark authorization only after signing succeeds.
    authorizedVoters.add(voterID)

    return blindSignature
}

export function submitVote(unblindedVote) {
    const { vote, signature } = unblindedVote

    if (vote !== 'Y' && vote !== 'N') {
        throw new Error('Vote must be Y or N')
    }

    // Store no voter identity.
    submittedVotes.push({ vote, signature })
}

export function calculateOutcome() {
    const outcome = { Y: 0, N: 0 }

    for (const { vote, signature } of submittedVotes) {
        const encodedVote = new TextEncoder().encode(vote)
        const hashedVote =
            bls12_381.longSignatures.hash(encodedVote)

        // Count only signatures verified with the AP's public key.
        try {
            const verified = bls12_381.longSignatures.verify(
                signature,
                hashedVote,
                publicKeyG1
            )

            if (verified) {
                outcome[vote]++
            }
        } catch {
            // Malformed signatures are not counted.
        }
    }

    return outcome
}