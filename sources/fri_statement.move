module verifier_addr::fri_statement {
    use std::bcs;
    use std::bcs::to_bytes;
    use std::features::cryptography_algebra_enabled;
    use std::signer::address_of;
    use std::vector;
    use std::vector::{length, for_each};
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::table::{Table, new, upsert};
    use verifier_addr::fri_layer::{fri_ctx_size, init_fri_group, compute_next_layer};
    use verifier_addr::prime_field_element_0::k_modulus;
    use verifier_addr::fri_layer;
    use aptos_std::debug::print;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::math128::pow;
    use lib_addr::memory;
    use lib_addr::endia_encode::to_big_endian;
    use verifier_addr::fact_registry::register_fact;
    use lib_addr::memory::{mloadrange, mload, mstore, allocate, get_next, set_next, Memory};
    use verifier_addr::merkle_verifier::verify_merkle;
    use verifier_addr::vector::append_vector;
    use err_addr::fri_error::err_fri_step_size_too_large;
    #[test_only]
    use aptos_std::debug::print_stack_trace;
    #[test_only]
    use verifier_addr::fri_test::{
        get_proof_3, get_fri_queue_3, get_evaluation_point_3, get_fri_step_size_3, get_expected_root_3, get_proof_2,
        get_evaluation_point_2, get_fri_queue_2, get_fri_step_size_2, get_expected_root_2
    };


    public fun verify_fri(
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

        allocate(&mut memory, evaluation_point);
        allocate(&mut memory, fri_step_size);
        allocate(&mut memory, expected_root);

        // init_fri(&signer);
        // must <= FRI_MAX_STEPS_SIZE
        // let fri = &mut borrow_global_mut<Fri>(address_of(&signer)).fri;
        assert!(fri_step_size <= 4, err_fri_step_size_too_large());

        // Verify evaluation point within valid range.
        assert!(evaluation_point < k_modulus(), 1);

        // Validate the FRI queue.
        validate_fri_queue(fri_queue);

        let mm_fri_ctx_size = fri_ctx_size();
        let n_queries = (vector::length(&fri_queue) / 3 as u256); // expected eq 13 (40 /3)
        let merkle_queue_ptr: u256;
        let channel_ptr: u256;
        let fri_ctx: u256;
        let data_to_hash: u256;

        let fri_queue_ptr = fri_queue_ptr + 0x20;
        let channel_ptr = fri_queue_ptr + (length(&fri_queue) as u256);

        channel_ptr = get_next(&mut memory);
        mstore(&mut memory, channel_ptr, proof_ptr + 0x20);
        merkle_queue_ptr = channel_ptr + 0x20;
        fri_ctx = merkle_queue_ptr + 0x40 * n_queries;
        data_to_hash = fri_ctx + mm_fri_ctx_size;
        set_next(&mut memory, 0xa0);

        mstore(&mut memory, data_to_hash, evaluation_point);
        mstore(&mut memory, data_to_hash + 0x20, fri_step_size);
        mstore(&mut memory, data_to_hash + 0x80, expected_root);

        // Hash FRI inputs and add to dataToHash.
        // TODO: check keccak
        mstore(
            &mut memory,
            data_to_hash + 0x40,
            to_u256(keccak256(append_vector(to_bytes(&fri_queue_ptr), to_bytes(&(n_queries * 3)))))
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

        // TODO: check the keccak
        verify_merkle(&mut memory, channel_ptr, merkle_queue_ptr, to_big_endian(to_bytes(&expected_root)), n_queries);

        let keccak_input = mloadrange(&mut memory, fri_queue_ptr, 0x60 * n_queries);
        mstore(&mut memory, data_to_hash + 0x60, to_u256(keccak256(keccak_input)));

        let keccak_input = mloadrange(&mut memory, data_to_hash, 0xa0);
        let fact_hash = keccak256(keccak_input);

        register_fact(fact_hash)
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
            assert!(*vector::borrow(&fri_queue, 3 * i + 1) < k_modulus(), 1);
            assert!(*vector::borrow(&fri_queue, 3 * i + 2) < k_modulus(), 1);
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

    #[test]
    fun test_verify_fri_3() {
        verify_fri(
            get_proof_3(),
            get_fri_queue_3(),
            get_evaluation_point_3(),
            get_fri_step_size_3(),
            get_expected_root_3()
        );
        let i = 0;
        // while(i < 500) {
        //     let val = table::borrow_with_default(fri, i,&0);
        //     print(&i);
        //     print(val);
        //     i = i + 1;
        // }
    }

    #[test]
    fun test_verify_fri_2() {
        verify_fri(
            get_proof_2(),
            get_fri_queue_2(),
            get_evaluation_point_2(),
            get_fri_step_size_2(),
            get_expected_root_2()
        );
    }
}
