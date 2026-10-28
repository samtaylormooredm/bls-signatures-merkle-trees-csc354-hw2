import { createHash } from 'node:crypto'
import { MerkleTree } from './merkle_tree.mjs'

const hasher = (data) =>
    createHash('sha256').update(data).digest()

// Registration Provider state: room for 8 voters
const registrationTree = new MerkleTree(3, hasher)
let registrationClosed = false

export function registerVote(publicKey) {
    if (registrationClosed) {
        throw new Error('Registration is closed')
    }

    // Expect the public key as bytes
    const encodedPublicKey = Buffer.from(publicKey)

    if (registrationTree.getBottomIndex(encodedPublicKey) !== -1) {
        throw new Error('Voter is already registered')
    }

    const index = registrationTree.leaves.length
    registrationTree.append(encodedPublicKey)

    return index
}