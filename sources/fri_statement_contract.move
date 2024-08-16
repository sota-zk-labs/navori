module verifier_addr::fri_statement_contract {
    use std::signer::address_of;
    use std::vector;
    use std::vector::length;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::math128::pow;
    use aptos_framework::event::emit;

    use verifier_addr::convert_memory::from_vector;
    use verifier_addr::fact_registry::register_fact;
    use verifier_addr::fri::{get_fri, new_fri, update_fri};
    use verifier_addr::u256_to_byte32::{bytes32_to_u256, u256_to_bytes32};

    // This line is used for generating constants DO NOT REMOVE!
    // FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET + (FRI_GROUP_SIZE / 2)
    const FRI_CTX_SIZE: u64 = 0x28;
    // 4
    const FRI_MAX_STEP_SIZE: u256 = 0x4;
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // End of generating constants!

    //log-event
    #[event]
    struct FriCtx has store, drop {
        fri_ctx: u256
    }

    #[event]
    struct ComputeNextLayer has store, drop {
        channel_ptr: u256,
        fri_queue_ptr: u256,
        merkle_queue_ptr: u256,
        n_queries: u256,
        fri_ctx: u256,
        evaluation_point: u256,
        fri_coset_size: u256,
    }

    #[event]
    struct RegisterFactVerifyFri has store, drop {
        data_to_hash: u256,
        fri_queue_ptr: u256,
    }


    public entry fun verify_fri(
        signer: &signer,
        proof: vector<u256>,
        fri_queue: vector<u256>,
        evaluation_point: u256,
        fri_step_size: u256,
        expected_root: u256
    ) {
        let fri = &mut new_fri();

        // must <= FRI_MAX_STEPS_SIZE
        assert!(fri_step_size <= FRI_MAX_STEP_SIZE, 1);
        assert!(evaluation_point < K_MODULUS, 1);

        validate_fri_queue(fri_queue);

        let mm_fri_ctx_size = FRI_CTX_SIZE;
        let n_queries = vector::length(&fri_queue) / 3;

        let fri_queue_ptr = vector::length(&proof) + 6 ;
        let channel_ptr = fri_queue_ptr + length(&fri_queue);
        *vector::borrow_mut(fri, channel_ptr) = 5u256;
        let merkle_queue_ptr = channel_ptr + 1;
        let fri_ctx = merkle_queue_ptr + n_queries * 2;
        *vector::borrow_mut(fri, 4) = (vector::length(&proof) as u256);
        from_vector(proof, fri, 5);

        *vector::borrow_mut(fri, 4 + vector::length(&proof) + 1) = (vector::length(&fri_queue) as u256);

        from_vector(fri_queue, fri, fri_queue_ptr);

        let data_to_hash = fri_ctx + mm_fri_ctx_size;

        *vector::borrow_mut(fri, data_to_hash) = evaluation_point;
        *vector::borrow_mut(fri, data_to_hash + 1) = fri_step_size;
        *vector::borrow_mut(fri, data_to_hash + 4) = expected_root;

        let hash = vector::empty();
        let idx_hash = 0;

        while (idx_hash < n_queries * 3) {
            vector::append(&mut hash, u256_to_bytes32(vector::borrow(fri, fri_queue_ptr + idx_hash)));
            idx_hash = idx_hash + 1;
        };

        *vector::borrow_mut(fri, data_to_hash + 2) = bytes32_to_u256(keccak256(hash));
        let fri_coset_size = (pow(2, (fri_step_size as u128)) as u256);
        update_fri(signer, *fri);

        emit(FriCtx { fri_ctx: (fri_ctx as u256) });

        emit(ComputeNextLayer {
            channel_ptr: (channel_ptr as u256),
            fri_queue_ptr: (fri_queue_ptr as u256),
            merkle_queue_ptr: (merkle_queue_ptr as u256),
            n_queries: (n_queries as u256),
            fri_ctx: (fri_ctx as u256),
            evaluation_point,
            fri_coset_size,
        });

        emit(RegisterFactVerifyFri {
            data_to_hash: (data_to_hash as u256),
            fri_queue_ptr: (data_to_hash as u256),
        });
    }

    public entry fun register_fact_verify_fri(s: &signer, data_to_hash: u256, fri_queue_ptr: u256, n_queries: u256) {
        let data_to_hash = (data_to_hash as u64);
        let fri_queue_ptr = (fri_queue_ptr as u64);
        let n_queries = (n_queries as u64);

        let ffri = get_fri(address_of(s));
        let fri = &mut ffri;

        let input_hash = vector::empty();
        let idx_hash: u64 = 0;


        //input_hash has range from friQueuePtr to n_queries * 3.
        while (idx_hash < n_queries * 3) {
            vector::append(
                &mut input_hash,
                u256_to_bytes32(vector::borrow(fri, fri_queue_ptr + idx_hash))
            );
            idx_hash = idx_hash + 1;
        };

        *vector::borrow_mut(
            fri,
            data_to_hash + 3
        ) = bytes32_to_u256(keccak256(input_hash));


        input_hash = vector::empty();
        let idx_hash = 0;

        //input_hash has range from friQueuePtr to n_queries * 3.
        while (idx_hash < 5) {
            vector::append(
                &mut input_hash,
                u256_to_bytes32(vector::borrow(fri, data_to_hash + idx_hash))
            );
            idx_hash = idx_hash + 1;
        };
        register_fact(s, keccak256(input_hash));
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
}
