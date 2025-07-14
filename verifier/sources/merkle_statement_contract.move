module verifier_addr::merkle_statement_contract {
    use std::vector;
    use std::vector::{length, push_back};
    use aptos_std::aptos_hash::keccak256;
    use verifier_addr::merkle_verifier;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_le};
    use verifier_addr::fact_registry::{register_fact};

    // This line is used for generating constants DO NOT REMOVE!
    // 1
    const EHEIGHT_MUST_BE_LESS_THAN_200: u64 = 0x1;
    // 2
    const EINVALID_MERKLE_INDICES: u64 = 0x2;
    // 6
    const EODD_MERKLE_QUEUE_SIZE: u64 = 0x6;
    // 1
    const ETOO_MANY_MERKLE_QUERIES: u64 = 0x1;
    // 128
    const MAX_N_MERKLE_VERIFIER_QUERIES: u64 = 0x80;
    // 2
    const MERKLE_SLOT_SIZE: u64 = 0x2;
    // End of generating constants!

    public entry fun verify_merkle(
        s: &signer,
        merkle_view: vector<u256>,
        initial_merkle_queue: vector<u256>,
        height: u8,
        expected_root: u256
    ) {
        assert!(height < 200, EHEIGHT_MUST_BE_LESS_THAN_200);
        assert!(length(&initial_merkle_queue) <= MAX_N_MERKLE_VERIFIER_QUERIES * 2, ETOO_MANY_MERKLE_QUERIES);
        assert!(length(&initial_merkle_queue) % 2 == 0, EODD_MERKLE_QUEUE_SIZE);

        let merkle_queue_ptr = 0;
        // Get number of queries.
        let n_queries = length(&initial_merkle_queue) / 2;
        // Get a pointer to the end of initialMerkleQueue.
        let initial_merkle_queue_end_ptr = n_queries * MERKLE_SLOT_SIZE;
        // Let dataToHashPtr point to a free memory.
        let data_to_hash = vector[];

        // Copy initialMerkleQueue to dataToHashPtr and validaite the indices.
        // The indices need to be in the range [2**height..2*(height+1)-1] and
        // strictly incrementing.

        // First index needs to be >= 2**height.
        let idx_lower_limit = 1 << height;

        // Basically just copying all initial_merkle_queue into other memory slot
        // Then the sanity check that the indices are sorted and the overflow check
        while (merkle_queue_ptr < initial_merkle_queue_end_ptr) {
            let cur_idx = *vector::borrow(&initial_merkle_queue, merkle_queue_ptr);

            // Sanity check that the indices are sorted.
            assert!(cur_idx >= idx_lower_limit, EINVALID_MERKLE_INDICES);

            // The next idx must be at least curIdx + 1. Ensure it doesn't overflow.
            idx_lower_limit = cur_idx + 1;
            assert!(idx_lower_limit != 0, EINVALID_MERKLE_INDICES);

            // Copy the pair (idx, hash) to the dataToHash array.
            push_back(&mut data_to_hash, cur_idx);
            push_back(&mut data_to_hash, *vector::borrow(&initial_merkle_queue, merkle_queue_ptr + 1));

            merkle_queue_ptr = merkle_queue_ptr + MERKLE_SLOT_SIZE;
        };

        // We need to enforce that lastIdx < 2**(height+1)
        // => fail if lastIdx >= 2**(height+1)
        // => fail if (lastIdx + 1) > 2**(height+1)
        // => fail if idxLowerLimit > 2**(height+1).
        assert!(idx_lower_limit <= (2 << height), EINVALID_MERKLE_INDICES);

        let res_root = merkle_verifier::verify_merkle(&mut 0, &merkle_view, &mut initial_merkle_queue, expected_root, n_queries);
        push_back(&mut data_to_hash, res_root);

        register_fact(s, bytes32_to_u256(keccak256(vec_to_bytes_le(&data_to_hash))));
    }
}
