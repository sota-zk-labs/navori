module verifier_addr::fri_7 {
    use std::vector::{borrow, borrow_mut, length};

    use verifier_addr::horner_evaluator::horner_eval;
    use verifier_addr::memory_access_utils_7::get_fri_step_sizes;
    use verifier_addr::prime_field_element_0::{fmul, fpow};
    use lib_addr::vector::set_el;

    // This line is used for generating constants DO NOT REMOVE!
	// 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1
	const K_MONTGOMERY_R: u256 = 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1;
	// 3
	const FRI_QUEUE_SLOT_SIZE: u64 = 0x3;
	// 4
	const FRI_MAX_STEP_SIZE: u256 = 0x4;
	// 0xfe
	const MM_FRI_CTX: u64 = 0xfe;
	// 4
	const MAX_SUPPORTED_FRI_STEP_SIZE: u64 = 0x4;
	// 0xa
	const MM_CHANNEL: u64 = 0xa;
	// 0xd
	const MM_MERKLE_QUEUE: u64 = 0xd;
	// 0x9
	const MM_N_UNIQUE_QUERIES: u64 = 0x9;
	// 0xfd
	const MM_FRI_QUERIES_DELIMITER: u64 = 0xfd;
	// 0x6d
	const MM_FRI_QUEUE: u64 = 0x6d;
	// 0x13b
	const MM_FRI_LAST_LAYER_DEG_BOUND: u64 = 0x13b;
	// 0x1
	const MM_BLOW_UP_FACTOR: u64 = 0x1;
	// 0x13c
	const MM_FRI_LAST_LAYER_PTR: u64 = 0x13c;
	// 0x127
	const MM_FRI_EVAL_POINTS: u64 = 0x127;
	// 0x131
	const MM_FRI_COMMITMENTS: u64 = 0x131;
    // End of generating constants!

    /*
      Verifies FRI layers.

      See FriLayer for the descriptions of the FRI context and FRI queue.
    */
    fun verify_last_layer(ctx: &mut vector<u256>, proof: &vector<u256>, n_points: u64) {
        let fri_last_layer_deg_bound = *borrow(ctx, MM_FRI_LAST_LAYER_DEG_BOUND);
        let group_order_minus_one = fri_last_layer_deg_bound * (*borrow(ctx, MM_BLOW_UP_FACTOR)) - 1;
        let coefs_start = *borrow(ctx, MM_FRI_LAST_LAYER_PTR);

        for (i in 0..n_points) {
            let point = *borrow(ctx, MM_FRI_QUEUE + FRI_QUEUE_SLOT_SIZE * i + 2);
            // Invert point using inverse(point) == fpow(point, ord(point) - 1).

            point = fpow(point, group_order_minus_one);
            assert!(
                horner_eval(proof, (coefs_start as u64), point, (fri_last_layer_deg_bound as u64)) ==
                    *borrow(ctx, MM_FRI_QUEUE + FRI_QUEUE_SLOT_SIZE * i + 1),
                BAD_LAST_LAYER_VALUE
            );
        }
    }

    public fun fri_verify_layers(
        ctx: &mut vector<u256>,
        proof: &vector<u256>,
        proof_params: &vector<u256>
    ) {
        let fri_ctx = MM_FRI_CTX;
        assert!(
            MAX_SUPPORTED_FRI_STEP_SIZE == (FRI_MAX_STEP_SIZE as u64),
            MAX_STEP_SIZE_IS_INCONSISTENT
        );
        // Todo
        // initFriGroups(fri_ctx);
        // emit LogGas("FRI offset precomputation", gasleft());
        let channel_ptr = MM_CHANNEL;
        let merkle_queue_ptr = MM_MERKLE_QUEUE;

        let fri_step = 1;
        let n_live_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);

        // Add 0 at the end of the queries array to avoid empty array check when reading the next
        // queueItemIdx in `gatherCosetInputs`.
        set_el(ctx, MM_FRI_QUERIES_DELIMITER, 0);

        // Rather than converting all the values from Montgomery to standard form,
        // we can just pretend that the values are in standard form but all
        // the committed polynomials are multiplied by MontgomeryR.
        //
        // The values in the proof are already multiplied by MontgomeryR,
        // but the inputs from the OODS oracle need to be fixed.
        for (i in 0..n_live_queries) {
            let tmp = borrow_mut(ctx, MM_FRI_QUEUE + FRI_QUEUE_SLOT_SIZE * i + 1);
            *tmp = fmul(*tmp, K_MONTGOMERY_R);
        };

        let fri_queue = MM_FRI_QUEUE;

        let fri_step_sizes = get_fri_step_sizes(proof_params);
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