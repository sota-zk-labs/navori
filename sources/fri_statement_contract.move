module verifier_addr::fri_statement_contract {
    use std::vector;
    use std::vector::for_each;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::math128::pow;

    use err_addr::fri_error::err_fri_step_size_too_large;
    use lib_addr::bytes::u256_from_bytes_be;
    use lib_addr::endia_encode::to_big_endian;
    use lib_addr::memory;
    use lib_addr::memory::{allocate, get_next, mloadrange, mstore};
    use verifier_addr::fact_registry::register_fact;
    use verifier_addr::fri_layer::{compute_next_layer, init_fri_group};

    #[test_only]
    use aptos_std::debug::print;
    #[test_only]
    use verifier_addr::fact_registry::{init_fact_registry, is_valid};
    #[test_only]
    use verifier_addr::fri_test::{
        get_evaluation_point_2,
        get_evaluation_point_3,
        get_expected_root_2,
        get_expected_root_3,
        get_fri_queue_2,
        get_fri_queue_3,
        get_fri_step_size_2,
        get_fri_step_size_3,
        get_proof_2,
        get_proof_3
    };

    // This line is used for generating constants DO NOT REMOVE!
    // 0x800000000000011000000000000000000000000000000000000000000000001
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // FRI_CTX_TO_FRI_GROUP_OFFSET + FRI_GROUP_SIZE
    const FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET: u256 = 0x400;
    // 0x20 * MAX_COSET_SIZE
    const FRI_GROUP_SIZE: u256 = 0x200;
    // FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET + (FRI_GROUP_SIZE / 2)
    const FRI_CTX_SIZE: u256 = 0x500;
    // End of generating constants!

    public fun verify_fri(
        signer: &signer,
        proof: vector<u256>,
        fri_queue: vector<u256>,
        evaluation_point: u256,
        fri_step_size: u256,
        expected_root: u256
    ) {
        let memory = memory::new();

        // load input to memory
        let proof_ptr = allocate(&mut memory, (vector::length(&proof) as u256));
        for_each(proof, |p| {
            allocate(&mut memory, p);
        });

        let fri_queue_ptr = allocate(&mut memory, (vector::length(&fri_queue) as u256));
        for_each(fri_queue, |f| {
            allocate(&mut memory, f);
        });

        assert!(fri_step_size <= 4, err_fri_step_size_too_large());

        // Verify evaluation point within valid range.
        assert!(evaluation_point < K_MODULUS, 1);

        // Validate the FRI queue.
        validate_fri_queue(fri_queue);

        let mm_fri_ctx_size = FRI_CTX_SIZE;
        let n_queries = (vector::length(&fri_queue) / 3 as u256); // expected eq 13 (40 /3)
        let merkle_queue_ptr: u256;
        let channel_ptr: u256;
        let fri_ctx: u256;
        let data_to_hash: u256;

        let fri_queue_ptr = fri_queue_ptr + 0x20;

        channel_ptr = get_next(&memory);

        mstore(&mut memory, channel_ptr, proof_ptr + 0x20);
        merkle_queue_ptr = channel_ptr + 0x20;
        fri_ctx = merkle_queue_ptr + 0x40 * n_queries;

        data_to_hash = fri_ctx + mm_fri_ctx_size;

        mstore(&mut memory, data_to_hash, evaluation_point);
        mstore(&mut memory, data_to_hash + 0x20, fri_step_size);
        mstore(&mut memory, data_to_hash + 0x80, expected_root);

        // Hash FRI inputs and add to dataToHash.

        let keccak_input = mloadrange(&mut memory, fri_queue_ptr, 0x60 * n_queries);
        mstore(
            &mut memory,
            data_to_hash + 0x40,
            to_u256(to_big_endian(keccak256(keccak_input)))
        );
        init_fri_group(&mut memory, fri_ctx);

        let fri_coset_size = (pow(2, (fri_step_size as u128)) as u256);

        n_queries = compute_next_layer(
            &mut memory,
            channel_ptr,
            fri_queue_ptr,
            merkle_queue_ptr,
            n_queries,
            fri_ctx,
            evaluation_point,
            fri_coset_size,
        );

        // Todo
        // verify_merkle(&mut memory, channel_ptr, merkle_queue_ptr, to_big_endian(to_bytes(&expected_root)), n_queries);

        let keccak_input = mloadrange(&mut memory, fri_queue_ptr, 0x60 * n_queries);
        mstore(&mut memory, data_to_hash + 0x60, to_u256(to_big_endian(keccak256(keccak_input))));

        let keccak_input = mloadrange(&mut memory, data_to_hash, 0xa0);
        let fact_hash = u256_from_bytes_be(&keccak256(keccak_input));
        register_fact(signer, fact_hash);
    }

    fun validate_fri_queue(fri_queue: vector<u256>) {
        let fri_queue_length = vector::length(&fri_queue);
        assert!(fri_queue_length % 3 == 1, 1);
        assert!(fri_queue_length >= 4, 1);

        // Force delimiter cell to 0, this is cheaper then asserting it.
        vector::insert(&mut fri_queue, fri_queue_length - 1, 0);

        // We need to check that Qi+1 > Qi for each i,
        // Given that the queries are sorted the height range requirement can be validated by
        // checking that (Q1 ^ Qn) < Q1.
        // This check affirms that all queries are within the same logarithmic step.

        // NOLINT: divide-before-multiply.
        let n_queries = fri_queue_length / 3;
        let prev_query = 0;
        for (i in 0..n_queries) {
            assert!(*vector::borrow(&fri_queue, 3 * i) > prev_query, 1);
            assert!(*vector::borrow(&fri_queue, 3 * i + 1) < K_MODULUS, 1);
            assert!(*vector::borrow(&fri_queue, 3 * i + 2) < K_MODULUS, 1);
            prev_query = *vector::borrow(&fri_queue, 3 * i);
        };

        // Verify all queries are on the same logarithmic step.
        // NOLINTNEXTLINE: divide-before-multiply.
        assert!(
            *vector::borrow(&fri_queue, 0) ^ *vector::borrow(&fri_queue, 3 * n_queries - 3) < *vector::borrow(
                &fri_queue,
                0
            ),
            1
        );
    }

    #[test()]
    fun test_validate_fri_queue() {
        validate_fri_queue(get_fri_queue_3());
    }

    #[test(signer = @verifier_addr)]
    fun test_verify_fri_3(signer: &signer) {
        init_fact_registry(signer);
        verify_fri(
            signer,
            get_proof_3(),
            get_fri_queue_3(),
            get_evaluation_point_3(),
            get_fri_step_size_3(),
            get_expected_root_3()
        );
        let fact_hash: u256 = 0x81b6de7f72176840720dbf7460352c0a18342fd155c307bee6e384302b472179;
        assert!(is_valid(signer, fact_hash), 1);
    }

    #[test(signer = @verifier_addr)]
    fun test_verify_fri_2(signer: &signer) {
        init_fact_registry(signer);
        verify_fri(
            signer,
            get_proof_2(),
            get_fri_queue_2(),
            get_evaluation_point_2(),
            get_fri_step_size_2(),
            get_expected_root_2()
        );
        let fact_hash: u256 = 0xbc348fdab2b2e1f3564918265f0c0371e70078a8195897eb9a76687bbda53558;
        assert!(is_valid(signer, fact_hash), 1);
    }

    #[test]
    fun test_hash() {
        let memory = memory::new();
        allocate(&mut memory, 4);
        allocate(&mut memory, 5);
        let keccak_input = mloadrange(&mut memory, 0x80, 0x40);
        print(&(keccak_input));
        let keccak_hash = keccak256(keccak_input);
        print(&keccak_hash);
        print(&to_big_endian(keccak_hash));
    }

    #[test]
    fun test_hash1() {
        let data: vector<u8> = vector[4, 5];
        print(&(data));
        let keccak_hash = keccak256(data);
        print(&keccak_hash);
        print(&to_big_endian(keccak_hash));
    }
}