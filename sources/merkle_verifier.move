module verifier_addr::merkle_verifier {
    use std::bcs::to_bytes;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::debug::print;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::table::{Table, borrow, upsert, borrow_with_default};
    use verifier_addr::U256ToByte32::{u256_to_bytes32, bytes32_to_u256};
    use verifier_addr::append_vector::append_vector;
    #[test_only]
    use aptos_std::string_utils::to_string;

    const MAX_N_MERKLE_VERIFIER_QUERIES : u256 = 128;
    const MERKLE_SLOT_SIZE : u256 = 2;
    const COMMITMENT_MASK :u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    const COMMITMENT_SIZE : u256 = 1;
    const TWO_COMMITMENTS_SIZE : u256 = 2;
    const INDEX_SIZE :  u256 = 1;


    //error
    const TOO_MANY_MERKLE_QUERIES : u64=  1;
    const INVALID_MARKLE_PROOF : u64 = 2;

    public fun verify_merkle(
        fri : &mut Table<u256,u256>,
        channel_ptr : u256,
        queue_ptr : u256,
        root : u256,
        n : u256
    ) : vector<u8> {

        // print(&bytes32_to_u256(root));
        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, TOO_MANY_MERKLE_QUERIES );

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

        while (index > 1 ) {
            let sibling_index = index ^ 1;
            // sibblingOffset := COMMITMENT_SIZE_IN_BYTES * lsb(siblingIndex).
            let sibling_offset = (sibling_index * COMMITMENT_SIZE) % TWO_COMMITMENTS_SIZE;
            // Store the hash corresponding to index in the correct slot.
            // 0 if index is even and 0x20 if index is odd.
            // The hash of the sibling will be written to the other slot.
            let hash = *borrow(fri, hashes_ptr + rd_idx);
            upsert(fri, sibling_offset ^ 1, hash);

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

            upsert(fri, wr_idx + queue_ptr, index / 2);

            // Load the next index from the queue and check if it is our sibling.
            index = *borrow(fri, queue_ptr + rd_idx);
            if (index == sibling_index) {
                // Take sibling from queue rather than from proof.
                new_hash_ptr = rd_idx + hashes_ptr;
                // Revert reading from proof.
                proof_ptr = proof_ptr - COMMITMENT_SIZE;
                rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

                // Index was consumed, read the next one.
                // Note that the queue can't be empty at this point.
                // The index of the parent of the current node was already pushed into the
                // queue, and the parent is never the sibling.

                index = *borrow(fri, queue_ptr + rd_idx);
            };

            let new_hash = *borrow(fri, new_hash_ptr);
            upsert(fri,sibling_offset,new_hash);

            let f0 = u256_to_bytes32(*borrow(fri, 0)) ;
            let f1 = u256_to_bytes32(*borrow(fri, 1)) ;

            let pre_hash =  keccak256(append_vector(f0,f1));
            upsert(fri, wr_idx + hashes_ptr, COMMITMENT_MASK & bytes32_to_u256(pre_hash));
            wr_idx = (wr_idx + MERKLE_SLOT_SIZE) % queue_size;
        };
        let hash = *borrow(fri, hashes_ptr + rd_idx);
        upsert(fri,channel_ptr,proof_ptr);

        assert!(hash == root,INVALID_MARKLE_PROOF);
        u256_to_bytes32(hash)

    }
}


