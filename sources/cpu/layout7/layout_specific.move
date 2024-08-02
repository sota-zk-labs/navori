module verifier_addr::layout_specific_7 {
    use std::vector::borrow;

    use verifier_addr::pedersen_hash_points_x_column;
    use verifier_addr::pedersen_hash_points_y_column;
    use verifier_addr::poseidon_poseidon_full_round_key_0_column_7;
    use verifier_addr::poseidon_poseidon_full_round_key_1_column_7;
    use verifier_addr::poseidon_poseidon_full_round_key_2_column_7;
    use verifier_addr::poseidon_poseidon_partial_round_key_0_column_7;
    use verifier_addr::poseidon_poseidon_partial_round_key_1_column_7;
    use verifier_addr::prime_field_element_0::{fadd, fmul, fpow};
    use verifier_addr::vector::set_el;

    // This line is used for generating constants DO NOT REMOVE!
	// 128
	const PEDERSEN_BUILTIN_RATIO: u256 = 0x80;
	// 8
	const RANGE_CHECK_BUILTIN_RATIO: u256 = 0x8;
	// 8
	const BITWISE__RATIO: u256 = 0x8;
	// 8
	const POSEIDON__RATIO: u256 = 0x8;
	// 1
	const PEDERSEN_BUILTIN_REPETITIONS: u256 = 0x1;
	// 4
	const DILUTED_SPACING: u8 = 0x4;
	// 16
	const DILUTED_N_BITS: u256 = 0x10;
	// 0x4fa
	const MM_LOG_N_STEPS: u64 = 0x4fa;
	// 0x15a
	const MM_INITIAL_PEDERSEN_ADDR: u64 = 0x15a;
	// 0x158
	const MM_PEDERSEN__SHIFT_POINT_X: u64 = 0x158;
	// 0x159
	const MM_PEDERSEN__SHIFT_POINT_Y: u64 = 0x159;
	// 0x15b
	const MM_INITIAL_RANGE_CHECK_ADDR: u64 = 0x15b;
	// 0x14f
	const MM_RANGE_CHECK16__PERM__PUBLIC_MEMORY_PROD: u64 = 0x14f;
	// 0x15c
	const MM_INITIAL_BITWISE_ADDR: u64 = 0x15c;
	// 0x153
	const MM_DILUTED_CHECK__PERMUTATION__PUBLIC_MEMORY_PROD: u64 = 0x153;
	// 0x154
	const MM_DILUTED_CHECK__FIRST_ELM: u64 = 0x154;
	// 0x15d
	const MM_INITIAL_POSEIDON_ADDR: u64 = 0x15d;
	// 0x15f
	const MM_OODS_POINT: u64 = 0x15f;
	// 0x13d
	const MM_PERIODIC_COLUMN__PEDERSEN__POINTS__X: u64 = 0x13d;
	// 0x13e
	const MM_PERIODIC_COLUMN__PEDERSEN__POINTS__Y: u64 = 0x13e;
	// 0x160
	const MM_INTERACTION_ELEMENTS: u64 = 0x160;
	// 0x152
	const MM_DILUTED_CHECK__PERMUTATION__INTERACTION_ELM: u64 = 0x152;
	// 0x155
	const MM_DILUTED_CHECK__INTERACTION_Z: u64 = 0x155;
	// 0x156
	const MM_DILUTED_CHECK__INTERACTION_ALPHA: u64 = 0x156;
	// 0x157
	const MM_DILUTED_CHECK__FINAL_CUM_VAL: u64 = 0x157;
	// 0x13f
	const MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY0: u64 = 0x13f;
	// 0x140
	const MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY1: u64 = 0x140;
	// 0x141
	const MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY2: u64 = 0x141;
	// 0x142
	const MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__PARTIAL_ROUND_KEY0: u64 = 0x142;
	// 0x143
	const MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__PARTIAL_ROUND_KEY1: u64 = 0x143;
	// 8
	const OFFSET_OUTPUT_BEGIN_ADDR: u64 = 0x8;
	// 9
	const OFFSET_OUTPUT_STOP_PTR: u64 = 0x9;
	// 10
	const OFFSET_PEDERSEN_BEGIN_ADDR: u64 = 0xa;
	// 11
	const OFFSET_PEDERSEN_STOP_PTR: u64 = 0xb;
	// 12
	const OFFSET_RANGE_CHECK_BEGIN_ADDR: u64 = 0xc;
	// 13
	const OFFSET_RANGE_CHECK_STOP_PTR: u64 = 0xd;
	// 20
	const OFFSET_N_PUBLIC_MEMORY_PAGES: u64 = 0x14;
	// 14
	const OFFSET_BITWISE_BEGIN_ADDR: u64 = 0xe;
	// 15
	const OFFSET_BITWISE_STOP_ADDR: u64 = 0xf;
	// 16
	const OFFSET_POSEIDON_BEGIN_ADDR: u64 = 0x10;
	// 17
	const OFFSET_POSEIDON_STOP_PTR: u64 = 0x11;
	// 0
	const OUTPUT_BUILTIN_BIT: u256 = 0x0;
	// 1
	const PEDERSEN_BUILTIN_BIT: u256 = 0x1;
	// 2
	const RANGE_CHECK_BUILTIN_BIT: u256 = 0x2;
	// 4
	const BITWISE_BUILTIN_BIT: u256 = 0x4;
	// 7
	const POSEIDON_BUILTIN_BIT: u256 = 0x7;
    // End of generating constants!

    #[view]
    public fun get_layout_info(): (u256, u256) {
        let public_memory_offset = OFFSET_N_PUBLIC_MEMORY_PAGES;
        let selected_builtins = (1u256 << (OUTPUT_BUILTIN_BIT as u8)) |
            (1 << (PEDERSEN_BUILTIN_BIT as u8)) |
            (1 << (RANGE_CHECK_BUILTIN_BIT as u8)) |
            (1 << (BITWISE_BUILTIN_BIT as u8)) |
            (1 << (POSEIDON_BUILTIN_BIT as u8));
        ((public_memory_offset as u256), selected_builtins)
    }

    #[view]
    public fun safe_div(numerator: u256, denominator: u256): u256 {
        assert!(denominator > 0, DENOMINATOR_MUST_NOT_BE_ZERO);
        assert!(numerator % denominator == 0, NUMERATOR_NOT_DIVISIBLE_BY_DENOMINATOR);
        numerator / denominator
    }

    // Note: This function needs no `builtinName` as in original version
    fun validate_builtin_pointers(
        initial_address: u256,
        stop_address: u256,
        builtin_ratio: u256,
        cells_per_instance: u256,
        n_steps: u256
    ) {
        assert!(
            initial_address < (1 << 64), OUT_OF_RANGE_BEGIN_ADDR);
        let max_stop_ptr = initial_address + cells_per_instance * safe_div(n_steps, builtin_ratio);
        assert!(
            initial_address <= stop_address && stop_address <= max_stop_ptr,
            INVALID_STOP_PTR
        );
    }

    public fun layout_specific_init(ctx: &mut vector<u256>, public_input: &vector<u256>) {
        // "output" memory segment.
        let output_begin_addr = *borrow(public_input, OFFSET_OUTPUT_BEGIN_ADDR);
        let output_stop_ptr = *borrow(public_input, OFFSET_OUTPUT_STOP_PTR);
        assert!(output_begin_addr <= output_stop_ptr, OUTPUT_BEGIN_ADDR_MUST_BE_LESS_THAN_OR_EQUAL_TO_STOP_PTR);
        assert!(output_stop_ptr < (1 << 64), OUT_OF_RANGE_OUTPUT_STOP_PTR);
        let n_steps = 1u256 << ((*borrow(ctx, MM_LOG_N_STEPS)) as u8);

        // "pedersen" memory segment.
        set_el(ctx, MM_INITIAL_PEDERSEN_ADDR, *borrow(public_input, OFFSET_PEDERSEN_BEGIN_ADDR));
        validate_builtin_pointers(
            *borrow(ctx, MM_INITIAL_PEDERSEN_ADDR),
            *borrow(public_input, OFFSET_PEDERSEN_STOP_PTR),
            PEDERSEN_BUILTIN_RATIO,
            3,
            n_steps
        );

        // Pedersen's shiftPoint values.
        set_el(ctx, MM_PEDERSEN__SHIFT_POINT_X, 0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804);
        set_el(ctx, MM_PEDERSEN__SHIFT_POINT_Y, 0x3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a);

        // "range_check" memory segment.
        set_el(ctx, MM_INITIAL_RANGE_CHECK_ADDR, *borrow(public_input, OFFSET_RANGE_CHECK_BEGIN_ADDR));
        validate_builtin_pointers(
            *borrow(ctx, MM_INITIAL_RANGE_CHECK_ADDR), *borrow(public_input, OFFSET_RANGE_CHECK_STOP_PTR),
            RANGE_CHECK_BUILTIN_RATIO, 1, n_steps);
        set_el(ctx, MM_RANGE_CHECK16__PERM__PUBLIC_MEMORY_PROD, 1);

        // "bitwise" memory segment.
        set_el(ctx, MM_INITIAL_BITWISE_ADDR, *borrow(public_input, OFFSET_BITWISE_BEGIN_ADDR));
        validate_builtin_pointers(
            *borrow(ctx, MM_INITIAL_BITWISE_ADDR), *borrow(public_input, OFFSET_BITWISE_STOP_ADDR),
            BITWISE__RATIO, 5, n_steps);

        set_el(ctx, MM_DILUTED_CHECK__PERMUTATION__PUBLIC_MEMORY_PROD, 1);
        set_el(ctx, MM_DILUTED_CHECK__FIRST_ELM, 0);

        // "poseidon" memory segment.
        set_el(ctx, MM_INITIAL_POSEIDON_ADDR, *borrow(public_input, OFFSET_POSEIDON_BEGIN_ADDR));
        validate_builtin_pointers(
            *borrow(ctx, MM_INITIAL_POSEIDON_ADDR), *borrow(public_input, OFFSET_POSEIDON_STOP_PTR),
            POSEIDON__RATIO, 6, n_steps);
    }

    public fun prepare_for_oods_check(ctx: &mut vector<u256>) {
        let mm_interaction_elements = MM_INTERACTION_ELEMENTS;
        let oods_point = *borrow(ctx, MM_OODS_POINT);
        let n_steps = 1 << (*borrow(ctx, MM_LOG_N_STEPS) as u8);

        // The number of copies in the pedersen hash periodic columns is
        // nSteps / PEDERSEN_BUILTIN_RATIO / PEDERSEN_BUILTIN_REPETITIONS.
        let n_pedersen_hash_copies = safe_div(
            n_steps,
            PEDERSEN_BUILTIN_RATIO * PEDERSEN_BUILTIN_REPETITIONS);
        let z_point_pow_pedersen = fpow(oods_point, n_pedersen_hash_copies);
        set_el(
            ctx,
            MM_PERIODIC_COLUMN__PEDERSEN__POINTS__X,
            pedersen_hash_points_x_column::compute(z_point_pow_pedersen)
        );

        set_el(
            ctx,
            MM_PERIODIC_COLUMN__PEDERSEN__POINTS__Y,
            pedersen_hash_points_y_column::compute(z_point_pow_pedersen)
        );

        let tmp = *borrow(ctx, mm_interaction_elements + 3);
        set_el(
            ctx,
            MM_DILUTED_CHECK__PERMUTATION__INTERACTION_ELM,
            tmp
        );

        let tmp = *borrow(ctx, mm_interaction_elements + 4);
        set_el(
            ctx,
            MM_DILUTED_CHECK__INTERACTION_Z,
            tmp
        );

        let tmp = *borrow(ctx, mm_interaction_elements + 5);
        set_el(
            ctx,
            MM_DILUTED_CHECK__INTERACTION_ALPHA,
            tmp
        );

        let tmp = compute_diluted_cumulative_value(ctx);
        set_el(
            ctx,
            MM_DILUTED_CHECK__FINAL_CUM_VAL,
            tmp
        );

        // The number of copies in the Poseidon hash periodic columns is
        // nSteps / POSEIDON__RATIO.
        let n_poseidon_hash_copies = safe_div(
            1 << ((*borrow(ctx, MM_LOG_N_STEPS)) as u8),
            POSEIDON__RATIO);
        let z_point_pow_poseidon = fpow(oods_point, n_poseidon_hash_copies);

        set_el(
            ctx,
            MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY0,
            poseidon_poseidon_full_round_key_0_column_7::compute(z_point_pow_poseidon)
        );
        set_el(
            ctx,
            MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY1,
            poseidon_poseidon_full_round_key_1_column_7::compute(z_point_pow_poseidon)
        );
        set_el(
            ctx,
            MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY2,
            poseidon_poseidon_full_round_key_2_column_7::compute(z_point_pow_poseidon)
        );
        set_el(
            ctx,
            MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__PARTIAL_ROUND_KEY0,
            poseidon_poseidon_partial_round_key_0_column_7::compute(z_point_pow_poseidon)
        );
        set_el(
            ctx,
            MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__PARTIAL_ROUND_KEY1,
            poseidon_poseidon_partial_round_key_1_column_7::compute(z_point_pow_poseidon)
        );
    }
    /*
      Computes the final cumulative value of the diluted pool.
    */
    fun compute_diluted_cumulative_value(ctx: &mut vector<u256>): u256 {
        // The cumulative value is defined using the following recursive formula:
        //   r_1 = 1, r_{j+1} = r_j * (1 + z * u_j) + alpha * u_j^2 (for j >= 1)
        // where u_j = Dilute(j, spacing, n_bits) - Dilute(j-1, spacing, n_bits)
        // and we want to compute the final value r_{2^n_bits}.
        // Note that u_j depends only on the number of trailing zeros in the binary representation
        // of j. Specifically,
        //   u_{(1 + 2k) * 2^i} = u_{2^i} =
        //   u_{2^{i - 1}} + 2^{i * spacing} - 2^{(i - 1) * spacing + 1}.
        //
        // The recursive formula can be reduced to a nonrecursive form:
        //   r_j = prod_{n=1..j-1}(1 + z*u_n) +
        //     alpha * sum_{n=1..j-1}(u_n^2 * prod_{m=n + 1..j - 1}(1 + z * u_m))
        //
        // We rewrite this equation to generate a recursive formula that converges in log(j) steps:
        // Denote:
        //   p_i = prod_{n=1..2^i - 1}(1 + z * u_n)
        //   q_i = sum_{n=1..2^i - 1}(u_n^2 * prod_{m=n + 1..2^i-1}(1 + z * u_m))
        //   x_i = u_{2^i}.
        //
        // Clearly
        //   r_{2^i} = p_i + alpha * q_i.
        // Moreover, due to the symmetry of the sequence u_j,
        //   p_i = p_{i - 1} * (1 + z * x_{i - 1}) * p_{i - 1}
        //   q_i = q_{i - 1} * (1 + z * x_{i - 1}) * p_{i - 1} + x_{i - 1}^2 * p_{i - 1} + q_{i - 1}
        //
        // Now we can compute p_{n_bits} and q_{n_bits} in 'n_bits' steps and we are done.
        let z = *borrow(ctx, MM_DILUTED_CHECK__INTERACTION_Z);
        let alpha = *borrow(ctx, MM_DILUTED_CHECK__INTERACTION_ALPHA);
        let diffMultiplier = 1 << DILUTED_SPACING;
        let diffX = diffMultiplier - 2;
        // Initialize p, q and x to p_1, q_1 and x_0 respectively.
        let p = 1 + z;
        let q = 1;
        let x = 1;
        let res = 0;
        for (i in 1..DILUTED_N_BITS) {
            x = fadd(x, diffX);
            diffX = fmul(diffX, diffMultiplier);
            // To save multiplications, store intermediate values.
            let x_p = fmul(x, p);
            let y = p + fmul(z, x_p);
            q = fadd(
                fmul(q, y) + fmul(x, x_p),
                q,
            );
            p = fmul(p, y);
        };
        res = fadd(p, fmul(q, alpha));

        res
    }
    // assertion codes
    const OUTPUT_BEGIN_ADDR_MUST_BE_LESS_THAN_OR_EQUAL_TO_STOP_PTR: u64 = 1;
    const OUT_OF_RANGE_OUTPUT_STOP_PTR: u64 = 2;
    const OUT_OF_RANGE_BEGIN_ADDR: u64 = 3;
    const INVALID_STOP_PTR: u64 = 4;
    const DENOMINATOR_MUST_NOT_BE_ZERO: u64 = 5;
    const NUMERATOR_NOT_DIVISIBLE_BY_DENOMINATOR: u64 = 6;
}