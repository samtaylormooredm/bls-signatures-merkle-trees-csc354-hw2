export class MerkleTree {
	constructor(bottomLevel, hasher) {
	}

	append(element, updateInternalState = false)
	}

	appendAll(elements) {
		for(let element of elements) {
			this.append(element);
		}
	}

	getBottomIndex(element) {
	}

	getRoot() {
	}

	getProof(bottomIndex) {
		let siblings = [];
		let isLeft = [];

		// Call getRoot() to lazily evaluate all elements in the positionMap

		// Start from bottomLevel at bottomIndex, and backward-calculate siblings and isLeft

		// If the tree has bottomLevel == 3, your siblings should have:
		// neighbor at level 3, at position 2
		// neighbor at level 2, at position 1
		// neighbor at level 1, at position 0

		return [root, siblings, isLeft];
	}
}
