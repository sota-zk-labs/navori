module verifier_addr::merkle_verifier {
    use std::signer::address_of;
    use std::vector;
    use std::vector::borrow;
    use aptos_std::aptos_hash::keccak256;
    use aptos_framework::event;

    use lib_addr::bytes::{bytes32_to_u256, u256_to_bytes32};
    use verifier_addr::fri::{get_fri, update_fri};

    // This line is used for generating constants DO NOT REMOVE!
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    // 1
    const COMMITMENT_SIZE: u256 = 0x1;
    // 2
    const EINVALID_MERKLE_PROOF: u64 = 0x2;
    // 1
    const ETOO_MANY_MERKLE_QUERIES: u64 = 0x1;
    // 1
    const INDEX_SIZE: u64 = 0x1;
    // 128
    const MAX_N_MERKLE_VERIFIER_QUERIES: u64 = 0x80;
    // 2
    const MERKLE_SLOT_SIZE: u64 = 0x2;
    // 2
    const TWO_COMMITMENTS_SIZE: u256 = 0x2;
    // End of generating constants!

    #[event]
    struct Hash has store, drop {
        hash: vector<u8>
    }

    public entry fun verify_merkle(
        s: &signer,
        channel_ptr: u64,
        queue_ptr: u64,
        root: u256,
        n: u64
    ) {
        let fri = &mut get_fri(address_of(s));

        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, ETOO_MANY_MERKLE_QUERIES);
        // queuePtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th index in the queue.
        // hashesPtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th hash in the queue.
        let hashes_ptr = queue_ptr + INDEX_SIZE;
        let queue_size = n * MERKLE_SLOT_SIZE;

        // The items are in slots [0, n-1].
        let rd_idx = 0;
        let wr_idx = 0;

        // Iterate the queue until we hit the root.
        let index = *borrow(fri, queue_ptr + rd_idx);
        let proof_ptr = *borrow(fri, channel_ptr);

        while (index > 1) {
            let sibling_index = index ^ 1;
            // sibblingOffset := COMMITMENT_SIZE_IN_BYTES * lsb(siblingIndex).
            let sibling_offset = (sibling_index * COMMITMENT_SIZE) % TWO_COMMITMENTS_SIZE;
            // Store the hash corresponding to index in the correct slot.
            // 0 if index is even and 0x20 if index is odd.
            // The hash of the sibling will be written to the other slot.
            let hash = *vector::borrow(fri, hashes_ptr + rd_idx);
            *vector::borrow_mut(fri, (sibling_offset ^ 1 as u64)) = hash;

            rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

            // Inline channel operation:
            // Assume we are going to read a new hash from the proof.
            // If this is not the case add(proofPtr, COMMITMENT_SIZE_IN_BYTES) will be reverted.

            let new_hash_ptr = proof_ptr;
            proof_ptr = proof_ptr + COMMITMENT_SIZE;

            // Push index/2 into the queue, before reading the next index.
            // The order is important, as otherwise we may try to read from an empty queue (in
            // the case where we are working on one item).
            // wrIdx will be updated after writing the relevant hash to the queue.

            *vector::borrow_mut(fri, wr_idx + queue_ptr) = index / 2 ;

            // Load the next index from the queue and check if it is our sibling.
            index = *borrow(fri, queue_ptr + rd_idx);
            if (index == sibling_index) {
                // Take sibling from queue rather than from proof.
                new_hash_ptr = (rd_idx + hashes_ptr as u256);
                // Revert reading from proof.
                proof_ptr = proof_ptr - COMMITMENT_SIZE;
                rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

                // Index was consumed, read the next one.
                // Note that the queue can't be empty at this point.
                // The index of the parent of the current node was already pushed into the
                // queue, and the parent is never the sibling.

                index = *borrow(fri, queue_ptr + rd_idx);
            };

            let new_hash = *vector::borrow(fri, (new_hash_ptr as u64));
            *vector::borrow_mut(fri, (sibling_offset as u64)) = new_hash;

            let hash = u256_to_bytes32(borrow(fri, 0));
            vector::append(&mut hash, u256_to_bytes32(borrow(fri, 1)));

            let pre_hash = keccak256(hash);

            *vector::borrow_mut(fri, wr_idx + hashes_ptr) = COMMITMENT_MASK & bytes32_to_u256(pre_hash);
            wr_idx = (wr_idx + MERKLE_SLOT_SIZE) % queue_size;
        };

        let hash = *vector::borrow(fri, hashes_ptr + rd_idx);
        assert!(hash == root, EINVALID_MERKLE_PROOF);
        event::emit<Hash>(Hash { hash: u256_to_bytes32(&hash) });
        *vector::borrow_mut(fri, channel_ptr) = proof_ptr;
        update_fri(s, *fri);
    }
}