module verifier_addr::merkle_verifier {
    use std::vector::borrow;
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_le};
    use lib_addr::vector::set_el;

    // This line is used for generating constants DO NOT REMOVE!
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    // 1
    const COMMITMENT_SIZE: u64 = 0x1;
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
    const TWO_COMMITMENTS_SIZE: u64 = 0x2;
    // End of generating constants!

    public fun verify_merkle(
        channel_ptr: &mut u64,
        merkle_view: &vector<u256>,
        initial_merkle_queue: &mut vector<u256>,
        root: u256,
        n: u64
    ): u256 {
        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, ETOO_MANY_MERKLE_QUERIES);
        // queuePtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th index in the queue.
        // hashesPtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th hash in the queue.
        let hashes_ptr = INDEX_SIZE;
        let queue_size = n * MERKLE_SLOT_SIZE;

        // The items are in slots [0, n-1].
        let rd_idx = 0;
        let wr_idx = 0;

        // Iterate the queue until we hit the root.
        let index = *borrow(initial_merkle_queue, 0) as u64;
        let proof_ptr = *channel_ptr;

        let nodes_to_hash: vector<u256> = vector[0, 0];
        while (index > 1) {
            let sibling_index = (index ^ 1);
            // sibblingOffset := COMMITMENT_SIZE_IN_BYTES * lsb(siblingIndex).
            let sibling_offset = (sibling_index * COMMITMENT_SIZE) % TWO_COMMITMENTS_SIZE;
            // Store the hash corresponding to index in the correct slot.
            // 0 if index is even and 0x20 if index is odd.
            // The hash of the sibling will be written to the other slot.
            set_el(&mut nodes_to_hash, sibling_offset ^ 1, *borrow(initial_merkle_queue, hashes_ptr + rd_idx));
            rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

            // Inline channel operation:
            // Assume we are going to read a new hash from the proof.
            // If this is not the case add(proofPtr, COMMITMENT_SIZE_IN_BYTES) will be reverted.
            let hash_in_proof = true;
            let new_hash_ptr = proof_ptr;
            proof_ptr = proof_ptr + COMMITMENT_SIZE;

            // Push index/2 into the queue, before reading the next index.
            // The order is important, as otherwise we may try to read from an empty queue (in
            // the case where we are working on one item).
            // wrIdx will be updated after writing the relevant hash to the queue.
            set_el(initial_merkle_queue, wr_idx, (index >> 1) as u256);

            // Load the next index from the queue and check if it is our sibling.
            index = (*borrow(initial_merkle_queue, rd_idx) as u64);
            if (index == sibling_index) {
                // Take sibling from queue rather than from proof.
                new_hash_ptr = rd_idx + hashes_ptr;
                hash_in_proof = false;
                // Revert reading from proof.
                proof_ptr = proof_ptr - COMMITMENT_SIZE;
                rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

                // Index was consumed, read the next one.
                // Note that the queue can't be empty at this point.
                // The index of the parent of the current node was already pushed into the
                // queue, and the parent is never the sibling.

                index = (*borrow(initial_merkle_queue, rd_idx) as u64);
            };

            if (hash_in_proof) {
                set_el(&mut nodes_to_hash, sibling_offset, *borrow(merkle_view, new_hash_ptr));
            } else {
                set_el(&mut nodes_to_hash, sibling_offset, *borrow(initial_merkle_queue, new_hash_ptr));
            };

            // Push the new hash to the end of the queue.
            set_el(
                initial_merkle_queue,
                wr_idx + hashes_ptr,
                COMMITMENT_MASK & bytes32_to_u256(keccak256(vec_to_bytes_le(&nodes_to_hash)))
            );
            wr_idx = (wr_idx + MERKLE_SLOT_SIZE) % queue_size;
        };

        let hash = *borrow(initial_merkle_queue, hashes_ptr + rd_idx);
        assert!(hash == root, EINVALID_MERKLE_PROOF);
        *channel_ptr = proof_ptr;
        hash
    }
}