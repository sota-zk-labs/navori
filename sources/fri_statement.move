module verifier_addr::fri_statement {
    use std::signer::address_of;
    use std::vector;
    use std::vector::length;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::math128::pow;
    use aptos_std::simple_map::{borrow, upsert};
    use aptos_framework::account;
    use aptos_framework::event::{destroy_handle, emit_event};

    use verifier_addr::u256_to_byte32::{bytes32_to_u256, u256_to_bytes32};
    use verifier_addr::convert_memory::from_vector;
    use verifier_addr::fri::{get_fri, init_fri, update_fri};
    use verifier_addr::fri_layer::fri_ctx_size;
    use verifier_addr::prime_field_element_0::k_modulus;

    //log-event
    #[event]
    struct FriCtx has store, drop {
        fri_ctx: u256
    }

    struct ComputeNextLayer has drop, store {
        channel_ptr: u256,
        fri_queue_ptr: u256,
        merkle_queue_ptr: u256,
        n_queries: u256,
        fri_ctx: u256,
        evaluation_point: u256,
        fri_coset_size: u256,
    }


    public entry fun verify_fri(
        signer: &signer,
        proof: vector<u256>,
        fri_queue: vector<u256>,
        evaluation_point: u256,
        fri_step_size: u256,
        expected_root: u256
    ) {
        init_fri(signer);
        // must <= FRI_MAX_STEPS_SIZE
        let fri = &mut get_fri(address_of(signer));
        // let fri = fri_storage;
        assert!(fri_step_size <= 4, 1);
        assert!(evaluation_point < k_modulus(), 1);

        validate_fri_queue(fri_queue);

        let mm_fri_ctx_size = fri_ctx_size();
        let n_queries = (vector::length(&fri_queue) / 3 as u256); // expected eq 13 (40 /3)
        let fri_queue_ptr = (vector::length(&proof) + 6 as u256);
        let channel_ptr = fri_queue_ptr + (length(&fri_queue) as u256);
        upsert(fri, channel_ptr, 5);
        let merkle_queue_ptr = channel_ptr + 1;
        let fri_ctx = merkle_queue_ptr + n_queries * 2;
        upsert(fri, 4, (vector::length(&proof) as u256));
        from_vector(proof, fri, 5);
        upsert(fri, 4 + (vector::length(&proof) as u256) + 1, (vector::length(&fri_queue) as u256));
        from_vector(fri_queue, fri, fri_queue_ptr);

        let data_to_hash = fri_ctx + mm_fri_ctx_size;

        upsert(fri, data_to_hash, evaluation_point);
        upsert(fri, data_to_hash + 1, fri_step_size);
        upsert(fri, data_to_hash + 4, expected_root);

        let hash = *borrow(fri, &fri_queue_ptr);

        let hash = u256_to_bytes32(hash);
        for (i in (fri_queue_ptr + 1)..(fri_queue_ptr + n_queries * 3)) {
            vector::append(&mut hash, u256_to_bytes32(*borrow(fri, &i)));
        };
        upsert(fri, data_to_hash + 2, bytes32_to_u256(keccak256(hash)));
        let fri_coset_size = (pow(2, (fri_step_size as u128)) as u256);
        update_fri(signer, *freeze(fri));


        //Log fri_ctx
        let fri_ctx_handler = account::new_event_handle<FriCtx>(signer);
        emit_event<FriCtx>(&mut fri_ctx_handler, FriCtx { fri_ctx });
        destroy_handle<FriCtx>(fri_ctx_handler);


        let compute_next_next_layer_handler = account::new_event_handle<ComputeNextLayer>(signer);
        emit_event<ComputeNextLayer>(&mut compute_next_next_layer_handler, ComputeNextLayer {
            channel_ptr,
            fri_queue_ptr,
            merkle_queue_ptr,
            n_queries,
            fri_ctx,
            evaluation_point,
            fri_coset_size,
        });
        destroy_handle<ComputeNextLayer>(compute_next_next_layer_handler);
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
}
