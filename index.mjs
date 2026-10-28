import {
    blindSignaturesSetup,
    blindSignaturesPack,
    blindSignaturesSign,
    blindSignaturesUnpack
} from './blind-signatures.mjs'
import { MerkleTree } from './merkle_tree.mjs'
import { createHash } from 'node:crypto'
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
    '---- Blind signatures testing: ----\n',
    'Removing the blinding recovers H(m)?',
    recoveredPoint.equals(hashedMessage)
)

const blindSignature =
    blindSignaturesSign(privateKey, blindPoint)

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

// Takes bytes and returns the hash as a Buffer
const hasher = (data) =>
    createHash('sha256').update(data).digest()

const tree = new MerkleTree(3, hasher)

console.log(
    '---- Merkle tree testing: ----\n',
    'Leaf capacity:', tree.capacity
)
console.log('Current leaf count:', tree.leaves.length)

tree.append(Buffer.from('Alice'))
tree.append(Buffer.from('Bob'))
tree.append(Buffer.from('Charlie'))

console.log('Current leaf count:', tree.leaves.length)

console.log('Alice index:', tree.getBottomIndex(Buffer.from('Alice')))
console.log('Bob index:', tree.getBottomIndex(Buffer.from('Bob')))
console.log('Charlie index:', tree.getBottomIndex(Buffer.from('Charlie')))
console.log('Unknown index:', tree.getBottomIndex(Buffer.from('Unknown')))

// A depth-1 tree has exactly two leaf positions
const smallTree = new MerkleTree(1, hasher)

smallTree.append(Buffer.from('Alice'))
smallTree.append(Buffer.from('Bob'), true)

// Calculate the expected root directly
const expectedRoot = hasher(Buffer.concat([
    hasher(Buffer.from('Alice')),
    hasher(Buffer.from('Bob'))
]))

console.log(
    'Root matches expected hash?',
    smallTree.getRoot().equals(expectedRoot)
)

const aliceIndex = tree.getBottomIndex(Buffer.from('Alice'))
const [root, siblings, isLeft] = tree.getProof(aliceIndex)

// Start with Alice's leaf hash
let currentHash = hasher(Buffer.from('Alice'))

// Rebuild the root using only Alice and her proof
for (let i = 0; i < siblings.length; i++) {
    const left = isLeft[i] ? siblings[i] : currentHash
    const right = isLeft[i] ? currentHash : siblings[i]

    currentHash = hasher(Buffer.concat([left, right]))
}

console.log('Proof reaches the root?', currentHash.equals(root))
console.log('Number of sibling hashes:', siblings.length)