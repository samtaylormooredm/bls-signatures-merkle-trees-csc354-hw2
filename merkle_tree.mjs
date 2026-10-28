export class MerkleTree {
	constructor(bottomLevel, hasher) {
		if (!Number.isInteger(bottomLevel) || bottomLevel < 0) {
            throw new Error('bottomLevel must be a nonnegative integer')
        }

		this.bottomLevel = bottomLevel
		this.hasher = hasher

		// Maximum number of leaves at this depth
        this.capacity = 2 ** bottomLevel

        // Stores hashes of the appended elements
        this.leaves = []

        // Caches calculated node hashes by their tree position
        this.positionMap = new Map()
	}

	append(element, updateInternalState = false) {
		if (this.leaves.length >= this.capacity) {
			throw new Error('Merkle tree is full')
		}

		// Hash the element before storing it
		const leafHash = this.hasher(element)
		const bottomIndex = this.leaves.length

		this.leaves.push(leafHash)

		// Cache the leaf hash using "level:index" as its position
		this.positionMap.set(
			`${this.bottomLevel}:${bottomIndex}`,
			leafHash
		)

		// Only this leaf's ancestors need to be recalculated
		let index = bottomIndex

		for (let level = this.bottomLevel - 1; level >= 0; level--) {
			index = Math.floor(index / 2)
			this.positionMap.delete(`${level}:${index}`)
		}

		// Recalculate now if requested; otherwise wait until getRoot()
		if (updateInternalState) {
			this.getRoot()
		}
	}

	appendAll(elements) {
		for(let element of elements) {
			this.append(element);
		}
	}

	getBottomIndex(element) {
		const elementHash = this.hasher(element)

		return this.leaves.findIndex(
			leafHash => leafHash.equals(elementHash)
		)
	}

	getNodeHash(level, index) {
		const key = `${level}:${index}`

		// Reuse the hash if it has already been calculated
		if (this.positionMap.has(key)) {
			return this.positionMap.get(key)
		}

		let hash

		if (level === this.bottomLevel) {
			// An unused leaf position
			hash = this.hasher(Buffer.alloc(0))
		} else {
			// Calculate the left and right children's hashes
			const left = this.getNodeHash(level + 1, index * 2)
			const right = this.getNodeHash(level + 1, index * 2 + 1)

			// Parent = hash(left hash || right hash)
			hash = this.hasher(Buffer.concat([left, right]))
		}

		this.positionMap.set(key, hash)
		return hash
	}

	getRoot() {
		// The root is at level 0, index 0
		return this.getNodeHash(0, 0)
	}

	getProof(bottomIndex) {
		if (!Number.isInteger(bottomIndex) ||
			bottomIndex < 0 ||
			bottomIndex >= this.leaves.length) {
			throw new Error('Invalid leaf index')
		}

		// Calculate and cache any missing hashes
		const root = this.getRoot()

		const siblings = []
		const isLeft = []

		let index = bottomIndex

		for (let level = this.bottomLevel; level > 0; level--) {
			// Even indices are left children; odd indices are right children
			const siblingIsLeft = index % 2 === 1
			const siblingIndex = siblingIsLeft ? index - 1 : index + 1

			siblings.push(this.getNodeHash(level, siblingIndex))
			isLeft.push(siblingIsLeft)

			// Move to the parent
			index = Math.floor(index / 2)
		}

		return [root, siblings, isLeft]
	}
}
