module verifier_addr::fri_statement_contract {
    use std::vector::{borrow, length, push_back, slice};
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_le,
    };
    use lib_addr::vector::{assign, set_el};
    use verifier_addr::fact_registry::register_fact;
    use verifier_addr::fri_layer;
    use verifier_addr::merkle_verifier;

    // This line is used for generating constants DO NOT REMOVE!
    // 3
    const EFRI_QUEUE_MUST_BE_COMPOSED_OF_TRIPLETS_PLUS_ONE_DELIMITER_CELL: u64 = 0x3;
    // 1
    const EFRI_STEP_SIZE_TOO_LARGE: u64 = 0x1;
    // 2
    const EINVALID_EVAL_POINT: u64 = 0x2;
    // 8
    const EINVALID_FRI_INVERSE_POINT: u64 = 0x8;
    // 7
    const EINVALID_FRI_VALUE: u64 = 0x7;
    // 5
    const EINVALID_QUERIES_RANGE: u64 = 0x5;
    // 6
    const EINVALID_QUERY_VALUE: u64 = 0x6;
    // 4
    const ENO_QUERY_TO_PROCESS: u64 = 0x4;
    // FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET + (FRI_GROUP_SIZE / 2)
    const FRI_CTX_SIZE: u64 = 0x28;
    // 4
    const FRI_MAX_STEP_SIZE: u8 = 0x4;
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // End of generating constants!

    public entry fun verify_fri(
        signer: &signer,
        proof: vector<u256>,
        fri_queue: vector<u256>,
        evaluation_point: u256,
        fri_step_size: u8,
        expected_root: u256
    ) {
        // must <= FRI_MAX_STEPS_SIZE
        assert!(fri_step_size <= FRI_MAX_STEP_SIZE, EFRI_STEP_SIZE_TOO_LARGE);
        assert!(evaluation_point < K_MODULUS, EINVALID_EVAL_POINT);

        validate_fri_queue(&mut fri_queue);

        let n_queries = length(&fri_queue) / 3;
        let fri_ctx = assign(0u256, FRI_CTX_SIZE);
        let merkle_queue = assign(0u256, n_queries * 2);
        let channel_ptr = 0;

        let data_to_hash = vector[evaluation_point, fri_step_size as u256];
        push_back(&mut data_to_hash, bytes32_to_u256(keccak256(vec_to_bytes_le(&slice(&fri_queue, 0, n_queries * 3)))));

        fri_layer::init_fri_group(&mut fri_ctx);

        n_queries = fri_layer::compute_next_layer(
            &mut channel_ptr,
            &proof,
            &mut fri_queue,
            &mut merkle_queue,
            n_queries,
            &mut fri_ctx,
            evaluation_point,
            1 << fri_step_size
        );

        merkle_verifier::verify_merkle(&mut channel_ptr, &proof, &mut merkle_queue, expected_root, n_queries);

        push_back(&mut data_to_hash, bytes32_to_u256(keccak256(vec_to_bytes_le(&slice(&fri_queue, 0, n_queries * 3)))));
        push_back(&mut data_to_hash, expected_root);
        let fact_hash = bytes32_to_u256(keccak256(vec_to_bytes_le(&data_to_hash)));
        register_fact(signer, fact_hash);
    }

    fun validate_fri_queue(fri_queue: &mut vector<u256>) {
        let fri_queue_length = length(fri_queue);
        assert!(fri_queue_length % 3 == 1, EFRI_QUEUE_MUST_BE_COMPOSED_OF_TRIPLETS_PLUS_ONE_DELIMITER_CELL);
        assert!(fri_queue_length >= 4, ENO_QUERY_TO_PROCESS);

        // Force delimiter cell to 0, this is cheaper then asserting it.
        set_el(fri_queue, fri_queue_length - 1, 0);

        // We need to check that Qi+1 > Qi for each i,
        // Given that the queries are sorted the height range requirement can be validated by
        // checking that (Q1 ^ Qn) < Q1.
        // This check affirms that all queries are within the same logarithmic step.

        // NOLINT: divide-before-multiply.
        let n_queries = fri_queue_length / 3;
        let prev_query = 0;
        for (i in 0..n_queries) {
            assert!(*borrow(fri_queue, 3 * i) > prev_query, EINVALID_QUERY_VALUE);
            assert!(*borrow(fri_queue, 3 * i + 1) < K_MODULUS, EINVALID_FRI_VALUE);
            assert!(*borrow(fri_queue, 3 * i + 2) < K_MODULUS, EINVALID_FRI_INVERSE_POINT);
            prev_query = *borrow(fri_queue, 3 * i);
        };
        // Verify all queries are on the same logarithmic step.
        // NOLINTNEXTLINE: divide-before-multiply.
        assert!(
            *borrow(fri_queue, 0) ^ *borrow(fri_queue, 3 * n_queries - 3) < *borrow(
                fri_queue,
                0
            ),
            EINVALID_QUERIES_RANGE
        );
    }
}
