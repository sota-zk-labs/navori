module verifier_addr::fri_7 {
    /*
      Verifies FRI layers.

      See FriLayer for the descriptions of the FRI context and FRI queue.
    */
    use std::vector::{borrow, borrow_mut, length};
    use verifier_addr::horner_evaluator::horner_eval;
    use verifier_addr::memory_access_utils_7::get_fri_step_sizes;
    use verifier_addr::prime_field_element_0::{fmul, k_montgomery_r, fpow};
    use verifier_addr::fri_layer::{FRI_QUEUE_SLOT_SIZE};
    use verifier_addr::vector::set_el;
    use verifier_addr::fri_transform::FRI_MAX_STEP_SIZE;
    use verifier_addr::memory_map_7::{MM_FRI_CTX, MAX_SUPPORTED_FRI_STEP_SIZE, MM_CHANNEL, MM_MERKLE_QUEUE,
        MM_N_UNIQUE_QUERIES, MM_FRI_QUERIES_DELIMITER, MM_FRI_QUEUE, MM_FRI_LAST_LAYER_DEG_BOUND, MM_BLOW_UP_FACTOR,
        MM_FRI_LAST_LAYER_PTR
    };

    fun verify_last_layer(ctx: &mut vector<u256>, proof: &vector<u256>, n_points: u64) {
        let fri_last_layer_deg_bound = *borrow(ctx, MM_FRI_LAST_LAYER_DEG_BOUND());
        let group_order_minus_one = fri_last_layer_deg_bound * (*borrow(ctx, MM_BLOW_UP_FACTOR())) - 1;
        let coefs_start = *borrow(ctx, MM_FRI_LAST_LAYER_PTR());

        for (i in 0..n_points) {
            let point = *borrow(ctx, MM_FRI_QUEUE() + FRI_QUEUE_SLOT_SIZE() * i + 2);
            // Invert point using inverse(point) == fpow(point, ord(point) - 1).

            point = fpow(point, group_order_minus_one);
            assert!(
                horner_eval(proof, (coefs_start as u64), point, (fri_last_layer_deg_bound as u64)) ==
                *borrow(ctx, MM_FRI_QUEUE() + FRI_QUEUE_SLOT_SIZE() * i + 1),
                BAD_LAST_LAYER_VALUE
            );
        }    
    }
    
    public fun fri_verify_layers(signer: &signer, ctx: &mut vector<u256>, proof: &vector<u256>, proof_params: &vector<u256>) {
        let fri_ctx = MM_FRI_CTX();
        assert!(
            MAX_SUPPORTED_FRI_STEP_SIZE() == (FRI_MAX_STEP_SIZE() as u64),
            MAX_STEP_SIZE_IS_INCONSISTENT
        );
        // Todo
        // initFriGroups(fri_ctx);
        // emit LogGas("FRI offset precomputation", gasleft());
        let channel_ptr = MM_CHANNEL();
        let merkle_queue_ptr = MM_MERKLE_QUEUE();

        let fri_step = 1;
        let n_live_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES()) as u64);

        // Add 0 at the end of the queries array to avoid empty array check when reading the next
        // queueItemIdx in `gatherCosetInputs`.
        set_el(ctx, MM_FRI_QUERIES_DELIMITER(), 0);

        // Rather than converting all the values from Montgomery to standard form,
        // we can just pretend that the values are in standard form but all
        // the committed polynomials are multiplied by MontgomeryR.
        //
        // The values in the proof are already multiplied by MontgomeryR,
        // but the inputs from the OODS oracle need to be fixed.
        for (i in 0..n_live_queries) {
            let tmp = borrow_mut(ctx, MM_FRI_QUEUE() + FRI_QUEUE_SLOT_SIZE() * i + 1);
            *tmp = fmul(*tmp, k_montgomery_r());
        };

        let fri_queue = MM_FRI_QUEUE();

        let fri_step_sizes = get_fri_step_sizes(signer, proof_params);
        let n_fri_steps = length(&fri_step_sizes);
        while (fri_step < n_fri_steps) {
            let fri_coset_size = (1 << (*borrow(&fri_step_sizes, fri_step) as u8));

            // Todo
            // n_live_queries = compute_next_layer(
            //     channelPtr,
            //     friQueue,
            //     merkleQueuePtr,
            //     n_live_queries,
            //     friCtx,
            //     ctx[MM_FRI_EVAL_POINTS + fri_step],
            //     fri_coset_size
            // );

            // emit LogGas(
            //     string(abi.encodePacked("FRI layer ", bytes1(uint8(48 + fri_step)))), gasleft());

            // Layer is done, verify the current layer and move to next layer.
            // ctx[mmMerkleQueue: merkleQueueIdx) holds the indices
            // and values of the merkle leaves that need verification.
            // Todo
            // verify_merkle(
            //     channelPtr,
            //     merkleQueuePtr,
            //     bytes32(ctx[MM_FRI_COMMITMENTS + fri_step - 1]),
            //     n_live_queries
            // );

            // emit LogGas(
            //     string(abi.encodePacked("Merkle of FRI layer ", bytes1(uint8(48 + fri_step)))),
            //     gasleft());
            fri_step = fri_step + 1;
        };

        verify_last_layer(ctx, proof, n_live_queries);
        // emit LogGas("last FRI layer", gasleft());
    }
    
    // assertion codes
    const MAX_STEP_SIZE_IS_INCONSISTENT: u64 = 1;
    const BAD_LAST_LAYER_VALUE: u64 = 2;
}
