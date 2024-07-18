module verifier_addr::layout_specific_7 {
    use std::vector::borrow;
    use verifier_addr::prime_field_element_0::fpow;
    use verifier_addr::stark_parameters_7::{PEDERSEN_BUILTIN_RATIO, RANGE_CHECK_BUILTIN_RATIO, BITWISE__RATIO,
        POSEIDON__RATIO, PEDERSEN_BUILTIN_REPETITIONS
    };
    use verifier_addr::vector::set_el;
    use verifier_addr::memory_map_7::{MM_LOG_N_STEPS, MM_INITIAL_PEDERSEN_ADDR, MM_PEDERSEN__SHIFT_POINT_X,
        MM_PEDERSEN__SHIFT_POINT_Y, MM_INITIAL_RANGE_CHECK_ADDR, MM_RANGE_CHECK16__PERM__PUBLIC_MEMORY_PROD,
        MM_INITIAL_BITWISE_ADDR, MM_DILUTED_CHECK__PERMUTATION__PUBLIC_MEMORY_PROD, MM_DILUTED_CHECK__FIRST_ELM,
        MM_INITIAL_POSEIDON_ADDR, MM_OODS_POINT
    };
    use verifier_addr::cpu_public_input_offset_base::{OFFSET_OUTPUT_BEGIN_ADDR, OFFSET_OUTPUT_STOP_PTR,
        OFFSET_PEDERSEN_BEGIN_ADDR, OFFSET_PEDERSEN_STOP_PTR, OFFSET_RANGE_CHECK_BEGIN_ADDR, OFFSET_RANGE_CHECK_STOP_PTR
    };
    use verifier_addr::cpu_public_input_offsets_7::{OFFSET_N_PUBLIC_MEMORY_PAGES, OFFSET_BITWISE_BEGIN_ADDR,
        OFFSET_BITWISE_STOP_ADDR, OFFSET_POSEIDON_BEGIN_ADDR, OFFSET_POSEIDON_STOP_PTR
    };

    public fun get_layout_info(): (u256, u256) {
        let public_memory_offset = OFFSET_N_PUBLIC_MEMORY_PAGES();
        let selected_builtins = (1u256 << (OUTPUT_BUILTIN_BIT() as u8)) |
            (1 << (PEDERSEN_BUILTIN_BIT() as u8)) |
            (1 << (RANGE_CHECK_BUILTIN_BIT() as u8)) |
            (1 << (BITWISE_BUILTIN_BIT() as u8)) |
            (1 << (POSEIDON_BUILTIN_BIT() as u8));
        ((public_memory_offset as u256), selected_builtins)
    }

    public fun layout_specific_init(ctx: &mut vector<u256>, public_input: &vector<u256>) {
        // "output" memory segment.
        let output_begin_addr = *borrow(public_input, OFFSET_OUTPUT_BEGIN_ADDR());
        let output_stop_ptr = *borrow(public_input, OFFSET_OUTPUT_STOP_PTR());
        assert!(output_begin_addr <= output_stop_ptr, OUTPUT_BEGIN_ADDR_MUST_BE_LESS_THAN_OR_EQUAL_TO_STOP_PTR);
        assert!(output_stop_ptr < (1 << 64), OUT_OF_RANGE_OUTPUT_STOP_PTR);
        let n_steps = 1u256 << ((*borrow(ctx, MM_LOG_N_STEPS())) as u8);

        // "pedersen" memory segment.
        set_el(ctx, MM_INITIAL_PEDERSEN_ADDR(), *borrow(public_input, OFFSET_PEDERSEN_BEGIN_ADDR()));
        validate_builtin_pointers(
            *borrow(ctx, MM_INITIAL_PEDERSEN_ADDR()),
            *borrow(public_input, OFFSET_PEDERSEN_STOP_PTR()),
            PEDERSEN_BUILTIN_RATIO(),
            3,
            n_steps
        );

        // Pedersen's shiftPoint values.
        set_el(ctx, MM_PEDERSEN__SHIFT_POINT_X(), 0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804);
        set_el(ctx, MM_PEDERSEN__SHIFT_POINT_Y(), 0x3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a);

        // "range_check" memory segment.
        set_el(ctx, MM_INITIAL_RANGE_CHECK_ADDR(), *borrow(public_input, OFFSET_RANGE_CHECK_BEGIN_ADDR()));
        validate_builtin_pointers(
            *borrow(ctx, MM_INITIAL_RANGE_CHECK_ADDR()), *borrow(public_input, OFFSET_RANGE_CHECK_STOP_PTR()),
            RANGE_CHECK_BUILTIN_RATIO(), 1, n_steps);
        set_el(ctx, MM_RANGE_CHECK16__PERM__PUBLIC_MEMORY_PROD(), 1);

        // "bitwise" memory segment.
        set_el(ctx, MM_INITIAL_BITWISE_ADDR(), *borrow(public_input, OFFSET_BITWISE_BEGIN_ADDR()));
        validate_builtin_pointers(
            *borrow(ctx, MM_INITIAL_BITWISE_ADDR()), *borrow(public_input, OFFSET_BITWISE_STOP_ADDR()),
            BITWISE__RATIO(), 5, n_steps);

        set_el(ctx, MM_DILUTED_CHECK__PERMUTATION__PUBLIC_MEMORY_PROD(), 1);
        set_el(ctx, MM_DILUTED_CHECK__FIRST_ELM(), 0);

        // "poseidon" memory segment.
        set_el(ctx, MM_INITIAL_POSEIDON_ADDR(), *borrow(public_input, OFFSET_POSEIDON_BEGIN_ADDR()));
        validate_builtin_pointers(
            *borrow(ctx, MM_INITIAL_POSEIDON_ADDR()), *borrow(public_input, OFFSET_POSEIDON_STOP_PTR()),
            POSEIDON__RATIO(), 6, n_steps);
    }

    // Todo: implement
    public fun prepare_for_oods_check(ctx: &mut vector<u256>) {
        let oods_point = *borrow(ctx, MM_OODS_POINT());
        let n_steps = 1 << (*borrow(ctx, MM_LOG_N_STEPS()) as u8);

        // The number of copies in the pedersen hash periodic columns is
        // nSteps / PEDERSEN_BUILTIN_RATIO / PEDERSEN_BUILTIN_REPETITIONS.
        let n_pedersen_hash_copies = safe_div(
            n_steps,
            PEDERSEN_BUILTIN_RATIO() * PEDERSEN_BUILTIN_REPETITIONS());
        let z_point_pow_pedersen = fpow(oods_point, n_pedersen_hash_copies);
        // ctx[MM_PERIODIC_COLUMN__PEDERSEN__POINTS__X] = pedersenPointsX.compute(z_point_pow_pedersen);
        // ctx[MM_PERIODIC_COLUMN__PEDERSEN__POINTS__Y] = pedersenPointsY.compute(z_point_pow_pedersen);
        //
        // ctx[MM_DILUTED_CHECK__PERMUTATION__INTERACTION_ELM] = ctx[MM_INTERACTION_ELEMENTS +
        //     3];
        // ctx[MM_DILUTED_CHECK__INTERACTION_Z] = ctx[MM_INTERACTION_ELEMENTS + 4];
        // ctx[MM_DILUTED_CHECK__INTERACTION_ALPHA] = ctx[MM_INTERACTION_ELEMENTS +
        //     5];
        //
        // ctx[MM_DILUTED_CHECK__FINAL_CUM_VAL] = computeDilutedCumulativeValue(ctx);
        //
        // // The number of copies in the Poseidon hash periodic columns is
        // // nSteps / POSEIDON__RATIO.
        // let n_poseidon_hash_copies = safeDiv(
        //     2 * *ctx[MM_LOG_N_STEPS],
        //     POSEIDON__RATIO);
        // let z_point_pow_poseidon = fpow(oods_point, n_poseidon_hash_copies);
        //
        // ctx[MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY0] = poseidonPoseidonFullRoundKey0.compute(
        //     z_point_pow_poseidon
        // );
        // ctx[MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY1] = poseidonPoseidonFullRoundKey1.compute(
        //     z_point_pow_poseidon
        // );
        // ctx[MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__FULL_ROUND_KEY2] = poseidonPoseidonFullRoundKey2.compute(
        //     z_point_pow_poseidon
        // );
        // ctx[MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__PARTIAL_ROUND_KEY0] = poseidonPoseidonPartialRoundKey0.compute(
        //     z_point_pow_poseidon
        // );
        // ctx[MM_PERIODIC_COLUMN__POSEIDON__POSEIDON__PARTIAL_ROUND_KEY1] = poseidonPoseidonPartialRoundKey1.compute(
        //     z_point_pow_poseidon
        // );
    }

    // This function needs no `builtinName` as in original version
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

    public fun safe_div(numerator: u256, denominator: u256): u256 {
        assert!(denominator > 0, DENOMINATOR_MUST_NOT_BE_ZERO);
        assert!(numerator % denominator == 0, NUMERATOR_NOT_DIVISIBLE_BY_DENOMINATOR);
        numerator / denominator
    }

    public fun OUTPUT_BUILTIN_BIT(): u256 {
        0
    }

    public fun PEDERSEN_BUILTIN_BIT(): u256 {
        1
    }

    public fun RANGE_CHECK_BUILTIN_BIT(): u256 {
        2
    }

    public fun ECDSA_BUILTIN_BIT(): u256 {
        3
    }

    public fun BITWISE_BUILTIN_BIT(): u256 {
        4
    }

    public fun EC_OP_BUILTIN_BIT(): u256 {
        5
    }

    public fun KECCAK_BUILTIN_BIT(): u256 {
        6
    }

    public fun POSEIDON_BUILTIN_BIT(): u256 {
        7
    }

    // assertion codes
    const OUTPUT_BEGIN_ADDR_MUST_BE_LESS_THAN_OR_EQUAL_TO_STOP_PTR: u64 = 1;
    const OUT_OF_RANGE_OUTPUT_STOP_PTR: u64 = 2;
    const OUT_OF_RANGE_BEGIN_ADDR: u64 = 3;
    const INVALID_STOP_PTR: u64 = 4;
    const DENOMINATOR_MUST_NOT_BE_ZERO: u64 = 5;
    const NUMERATOR_NOT_DIVISIBLE_BY_DENOMINATOR: u64 = 6;
}
