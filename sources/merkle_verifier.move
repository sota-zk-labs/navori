module verifier_addr::merkle_verifier {
    use std::vector::borrow;
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{u256_from_bytes_be, vec_to_bytes_be};
    use lib_addr::vector::{assign, set_el};

    // This line is used for generating constants DO NOT REMOVE!
	// 128
	const MAX_N_MERKLE_VERIFIER_QUERIES: u64 = 0x80;
	// 0x40
	const MERKLE_SLOT_SIZE_IN_BYTES: u64 = 0x40;
	// 0x20
	const INDEX_SIZE_IN_BYTES: u64 = 0x20;
	// 0x20
	const COMMITMENT_SIZE_IN_BYTES: u64 = 0x20;
	// 0x40
	const TWO_COMMITMENTS_SIZE_IN_BYTES: u64 = 0x40;
	// 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
	const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    // End of generating constants!

    // The size of a SLOT in the verifyMerkle queue.
    // Every slot holds a (index, hash) pair.
    // Commitments are masked to 160bit using the following mask to save gas costs.
    // The size of a commitment. We use 32 bytes (rather than 20 bytes) per commitment as it
    // simplifies the code.
    // The size of two commitments.
    // The size of and index in the verifyMerkle queue.
    /*
      Verifies a Merkle tree decommitment for n leaves in a Merkle tree with N leaves.

      The inputs data sits in the queue at queue_ptr.
      Each slot in the queue contains a 32 bytes leaf index and a 32 byte leaf value.
      The indices need to be in the range [N..2*N-1] and strictly incrementing.
      Decommitments are read from the channel in the ctx.

      The input data is destroyed during verification.
    */
    public fun verify_merkle(
        ctx: &mut vector<u256>,
        channel_ptr: u64,
        queue_ptr: u64,
        root: u256,
        n: u64,
    ): u256 {
        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, TOO_MANY_MERKLE_QUERIES);
        let hash = 0;

        // queue_ptr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th index in the queue.
        // hashes_ptr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th hash in the queue.
        let hashes_ptr = queue_ptr + INDEX_SIZE_IN_BYTES / 32;
        let queue_size = n * MERKLE_SLOT_SIZE_IN_BYTES / 32;

        // The items are in slots [0, n-1].
        let rd_idx = 0;
        let wr_idx = 0; // = n % n.

        // Iterate the queue until we hit the root.
        let index = (*borrow(ctx, rd_idx + queue_ptr) as u64);
        let proof_ptr = (*borrow(ctx, channel_ptr) as u64);

        let mem_to_hash = assign(0u256, 2);

        // while(index > 1).
        while (index > 1) {
            let sibling_index = index ^ 1;
            // sibbling_offset = COMMITMENT_SIZE_IN_BYTES * lsb(sibling_index).
            let sibbling_offset = (sibling_index * COMMITMENT_SIZE_IN_BYTES % TWO_COMMITMENTS_SIZE_IN_BYTES) / 32;

            // Store the hash corresponding to index in the correct slot.
            // 0 if index is even and 0x20 if index is odd.
            // The hash of the sibling will be written to the other slot.
            set_el(&mut mem_to_hash, sibbling_offset ^ 1, *borrow(ctx, rd_idx + hashes_ptr));
            rd_idx = (rd_idx + MERKLE_SLOT_SIZE_IN_BYTES / 32) % queue_size;

            // Inline channel operation:
            // Assume we are going to read a new hash from the proof.
            // If this is not the case add(proof_ptr, COMMITMENT_SIZE_IN_BYTES) will be reverted.
            let new_hash_ptr = proof_ptr;
            proof_ptr = proof_ptr + COMMITMENT_SIZE_IN_BYTES / 32;

            // Push index/2 into the queue, before reading the next index.
            // The order is important, as otherwise we may try to read from an empty queue (in
            // the case where we are working on one item).
            // wr_idx will be updated after writing the relevant hash to the queue.
            set_el(ctx, wr_idx + queue_ptr, (index / 2 as u256));

            // Load the next index from the queue and check if it is our sibling.
            index = (*borrow(ctx, rd_idx + queue_ptr) as u64);
            if (index == sibling_index) {
                // Take sibling from queue rather than from proof.

                new_hash_ptr = rd_idx + hashes_ptr;
                // Revert reading from proof.
                proof_ptr = proof_ptr - COMMITMENT_SIZE_IN_BYTES / 32;
                rd_idx = (rd_idx + MERKLE_SLOT_SIZE_IN_BYTES / 32) % queue_size;

                // Index was consumed, read the next one.
                // Note that the queue can't be empty at this point.
                // The index of the parent of the current node was already pushed into the
                // queue, and the parent is never the sibling.
                index = (*borrow(ctx, rd_idx + queue_ptr) as u64);
            };

            set_el(&mut mem_to_hash, sibbling_offset, *borrow(ctx, new_hash_ptr));

            // Push the new hash to the end of the queue.
            set_el(
                ctx,
                wr_idx + hashes_ptr,
                COMMITMENT_MASK & u256_from_bytes_be(&keccak256(vec_to_bytes_be(&mem_to_hash)))
            );
            wr_idx = (wr_idx + MERKLE_SLOT_SIZE_IN_BYTES / 32) % queue_size;
        };
        hash = *borrow(ctx, rd_idx + hashes_ptr);

        // Update the proof pointer in the context.
        set_el(ctx, channel_ptr, (proof_ptr as u256));
        // emit LogBool(hash == root);
        assert!(hash == root, INVALID_MERKLE_PROOF);

        hash
    }

    const TOO_MANY_MERKLE_QUERIES: u64 = 1;
    const INVALID_MERKLE_PROOF: u64 = 2;
}