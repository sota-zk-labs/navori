module verifier_addr::merkle_verifier {
    use std::bcs::to_bytes;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::debug::print;
    use aptos_std::from_bcs::{to_u8, to_u256};
    use lib_addr::EndianConversion::to_big_endian;
    use lib_addr::memory::{mload, Memory, mstore, mloadrange};
    use lib_addr::memory;
    use lib_addr::math_mod;
    use verifier_addr::error::{err_too_many_merkle_queries, err_invalid_merkle_proof};

    const MAX_N_MERKLE_VERIFIER_QUERIES: u256 = 128;

    // The size of a SLOT in the verifyMerkle queue.
    // Every slot holds a (index, hash) pair.
    const MERKLE_SLOT_SIZE_IN_BYTES: u256 = 0x40;

    // Commitments are masked to 160bit using the following mask to save gas costs.
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;

    // The size of a commitment. We use 32 bytes (rather than 20 bytes) per commitment as it
    // simplifies the code.
    const COMMITMENT_SIZE_IN_BYTES: u256 = 0x20;

    // The size of two commitments.
    const TWO_COMMITMENTS_SIZE_IN_BYTES: u256 = 0x40;

    // The size of and index in the verifyMerkle queue.
    const INDEX_SIZE_IN_BYTES: u256 = 0x20;


    /*
      Verifies a Merkle tree decommitment for n leaves in a Merkle tree with N leaves.

      The inputs data sits in the queue at queuePtr.
      Each slot in the queue contains a 32 bytes leaf index and a 32 byte leaf value.
      The indices need to be in the range [N..2*N-1] and strictly incrementing.
      Decommitments are read from the channel in the ctx.

      The input data is destroyed during verification.
    */
    public fun verify_merkle(
        memory: &mut Memory,
        channel_ptr: u256,
        queue_ptr: u256,
        root: u256,
        n: u256,
    ): u256 {
        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, err_too_many_merkle_queries());
        let hash: u256 = 0;

        // queuePtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th index in the queue.
        // hashesPtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th hash in the queue.
        let hashes_ptr = queue_ptr + INDEX_SIZE_IN_BYTES;
        let queue_size = n * MERKLE_SLOT_SIZE_IN_BYTES;

        // The items are in slots [0, n-1].
        let rd_idx = 0;
        let wr_idx = 0; // = n % n

        let index = mload(memory, rd_idx + queue_ptr);
        let proof_ptr = mload(memory, channel_ptr);

        // while(index > 1).
        while (index > 1) {
            let sibling_index = index ^ 1;
            // sibblingOffset := COMMITMENT_SIZE_IN_BYTES * lsb(siblingIndex).
            let sibling_offset = math_mod::mod_mul(
                sibling_index,
                COMMITMENT_SIZE_IN_BYTES,
                TWO_COMMITMENTS_SIZE_IN_BYTES
            );

            // Store the hash corresponding to index in the correct slot.
            // 0 if index is even and 0x20 if index is odd.
            // The hash of the sibling will be written to the other slot.
            let value = mload(memory, rd_idx + hashes_ptr);
            mstore(memory, 0x20u256 ^ sibling_offset, value);
            rd_idx = math_mod::mod_add(rd_idx, MERKLE_SLOT_SIZE_IN_BYTES, queue_size);

            // Inline channel operation:
            // Assume we are going to read a new hash from the proof.
            // If this is not the case add(proofPtr, COMMITMENT_SIZE_IN_BYTES) will be reverted.
            let new_hash_ptr: u256 = proof_ptr;
            proof_ptr = proof_ptr + COMMITMENT_SIZE_IN_BYTES;

            // Push index/2 into the queue, before reading the next index.
            // The order is important, as otherwise we may try to read from an empty queue (in
            // the case where we are working on one item).
            // wrIdx will be updated after writing the relevant hash to the queue.
            mstore(memory, wr_idx + queue_ptr, index / 2);

            // Load the next index from the queue and check if it is our sibling.
            index = mload(memory, rd_idx + queue_ptr);
            if (index == sibling_index) {
                // Take sibling from queue rather than from proof.
                new_hash_ptr = rd_idx + hashes_ptr;
                // Revert reading from proof.
                proof_ptr = proof_ptr - COMMITMENT_SIZE_IN_BYTES;
                rd_idx = math_mod::mod_add(rd_idx, MERKLE_SLOT_SIZE_IN_BYTES, queue_size);

                // Index was consumed, read the next one.
                // Note that the queue can't be empty at this point.
                // The index of the parent of the current node was already pushed into the
                // queue, and the parent is never the sibling.
                index = mload(memory, rd_idx + queue_ptr);
            };


            // Push the new hash to the end of the queue.
            let keccak_input = mloadrange(memory, 0x00u256, (TWO_COMMITMENTS_SIZE_IN_BYTES as u64));
            mstore(memory, wr_idx + hashes_ptr, COMMITMENT_MASK & to_u256(keccak256(keccak_input)));
            wr_idx = math_mod::mod_add(wr_idx, MERKLE_SLOT_SIZE_IN_BYTES, queue_size);
        };
        hash = mload(memory, rd_idx + hashes_ptr);

        // Update the proof pointer in the context.
        mstore(memory, channel_ptr, proof_ptr);

        assert!(hash != root, err_invalid_merkle_proof());
        return hash
    }
}
