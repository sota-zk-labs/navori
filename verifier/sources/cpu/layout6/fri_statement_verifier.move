module verifier_addr::fri_statement_verifier_6 {
    #[test_only]
    use std::vector::push_back;
    use std::signer::address_of;
    use std::vector::{borrow, borrow_mut, length, slice};
    use aptos_std::aptos_hash::keccak256;

    use cpu_addr::memory_access_utils_6::get_fri_step_sizes;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_le};
    use lib_addr::prime_field_element_0::{fmul, fpow};
    use lib_addr::vector::{assign, set_el};
    use verifier_addr::fact_registry::is_valid;
    use verifier_addr::horner_evaluator::horner_eval;
    use verifier_addr::verifier_channel::read_bytes;

    friend verifier_addr::stark_verifier_6;

    // This line is used for generating constants DO NOT REMOVE!
    // 1
    const EINVALIDATED_FRI_STATEMENT: u64 = 0x1;
    // 3618502788666127798953978732740734578953660990361066340291730267701097005025
    const K_MONTGOMERY_R: u256 = 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1;
    // 1
    const MM_BLOW_UP_FACTOR: u64 = 0x1;
    // 10
    const MM_CHANNEL: u64 = 0xa;
    // 305
    const MM_FRI_COMMITMENTS: u64 = 0x131;
    // 295
    const MM_FRI_EVAL_POINTS: u64 = 0x127;
    // 315
    const MM_FRI_LAST_LAYER_DEG_BOUND: u64 = 0x13b;
    // 316
    const MM_FRI_LAST_LAYER_PTR: u64 = 0x13c;
    // 109
    const MM_FRI_QUEUE: u64 = 0x6d;
    // 9
    const MM_N_UNIQUE_QUERIES: u64 = 0x9;
    // End of generating constants!

    // Fast-forwards the queries and invPoints of the friQueue from before the first layer to after
    // the last layer, computes the last FRI layer using horner evaluations, then returns the hash
    // of the final FriQueue.
    fun compute_last_layer_hash(
        ctx: &mut vector<u256>,
        proof: &vector<u256>,
        n_points: u64,
        sum_of_step_sizes: u8
    ): u256 {
        let fri_last_layer_deg_bound = (*borrow(ctx, MM_FRI_LAST_LAYER_DEG_BOUND) as u64);
        let group_order_minus_one = (fri_last_layer_deg_bound as u256) * (*borrow(ctx, MM_BLOW_UP_FACTOR)) - 1;
        let exponent = 1 << sum_of_step_sizes;
        let cur_point_index = 0;
        let prev_query = 0;
        let coefs_start = *borrow(ctx, MM_FRI_LAST_LAYER_PTR);
        let mm_fri_queue = MM_FRI_QUEUE;

        for (i in 0..n_points) {
            let query = *borrow(ctx, mm_fri_queue + 3 * i) >> sum_of_step_sizes;
            if (query == prev_query) {
                continue
            };
            set_el(ctx, mm_fri_queue + 3 * cur_point_index, query);
            prev_query = query;

            let point = fpow(*borrow(ctx, mm_fri_queue + 3 * i + 2), exponent);
            set_el(ctx, mm_fri_queue + 3 * cur_point_index + 2, point);
            // Invert point using inverse(point) == fpow(point, ord(point) - 1).

            point = fpow(point, group_order_minus_one);
            let tmp = horner_eval(
                proof,
                (coefs_start as u64),
                point,
                fri_last_layer_deg_bound
            );
            set_el(ctx, mm_fri_queue + 3 * cur_point_index + 1, tmp);

            cur_point_index = cur_point_index + 1;
        };

        let fri_queue = mm_fri_queue;
        // print(&slice(ctx, fri_queue, fri_queue + cur_point_index * 3));
        bytes32_to_u256(keccak256(vec_to_bytes_le(&slice(ctx, fri_queue, fri_queue + cur_point_index * 3))))
    }

    // Tested: OK
    public(friend) fun fri_verify_layers(
        signer: &signer,
        ctx: &mut vector<u256>,
        proof: &vector<u256>,
        proof_params: &vector<u256>
    ) {
        let signer_addr = address_of(signer);
        let channel_ptr = MM_CHANNEL;
        let n_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);

        // Rather than converting all the values from Montgomery to standard form,
        // we can just pretend that the values are in standard form but all
        // the committed polynomials are multiplied by MontgomeryR.
        //
        // The values in the proof are already multiplied by MontgomeryR,
        // but the inputs from the OODS oracle need to be fixed.
        for (i in 0..n_queries) {
            let tmp = borrow_mut(ctx, MM_FRI_QUEUE + 3 * i + 1);
            *tmp = fmul(*tmp, K_MONTGOMERY_R);
        };

        let fri_queue = MM_FRI_QUEUE;
        let input_layer_hash = bytes32_to_u256(
            keccak256(vec_to_bytes_le(&slice(ctx, fri_queue, fri_queue + n_queries * 3)))
        );

        let fri_step_sizes = get_fri_step_sizes(proof_params);
        let n_fri_inner_layers = length(&fri_step_sizes) - 1;
        let fri_step = 1;
        let sum_of_step_sizes = *borrow(&fri_step_sizes, 1);
        let data_to_hash = assign(0u256, 5);
        while (fri_step < n_fri_inner_layers) {
            let output_layer_hash = read_bytes(ctx, proof, channel_ptr, true, true);
            set_el(&mut data_to_hash, 0, *borrow(ctx, MM_FRI_EVAL_POINTS + fri_step));
            set_el(&mut data_to_hash, 1, *borrow(&fri_step_sizes, fri_step));
            set_el(&mut data_to_hash, 2, input_layer_hash);
            set_el(&mut data_to_hash, 3, output_layer_hash);
            set_el(&mut data_to_hash, 4, *borrow(ctx, MM_FRI_COMMITMENTS + fri_step - 1));

            // Verify statement is registered.
            assert!(// NOLINT: calls-loop.
                is_valid(signer_addr, bytes32_to_u256(keccak256(vec_to_bytes_le(&data_to_hash)))),
                EINVALIDATED_FRI_STATEMENT
            );

            input_layer_hash = output_layer_hash;

            fri_step = fri_step + 1;
            sum_of_step_sizes = sum_of_step_sizes + *borrow(&fri_step_sizes, fri_step);
        };

        set_el(&mut data_to_hash, 0, *borrow(ctx, MM_FRI_EVAL_POINTS + fri_step));
        set_el(&mut data_to_hash, 1, *borrow(&fri_step_sizes, fri_step));
        set_el(&mut data_to_hash, 2, input_layer_hash);
        set_el(&mut data_to_hash, 3, compute_last_layer_hash(ctx, proof, n_queries, (sum_of_step_sizes as u8)));
        set_el(&mut data_to_hash, 4, *borrow(ctx, MM_FRI_COMMITMENTS + fri_step - 1));

        assert!(
            is_valid(signer_addr, bytes32_to_u256(keccak256(vec_to_bytes_le(&data_to_hash)))),
            EINVALIDATED_FRI_STATEMENT
        );
    }
}