module cpu_2_addr::cpu_constraint_poly {

    use std::vector;
    use std::vector::{push_back, borrow, borrow_mut};
    use lib_addr::prime_field_element_0::{fmul, fpow};


    const EPRODUCT_INVERSE_ZERO: u64 = 0x0001;

    const PRIME: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;

    // The Memory map during the execution of this contract is as follows:
    // [0x0, 0x20) - pedersen__points__x
    // [0x20, 0x40) - pedersen__points__y
    // [0x40, 0x60) - ecdsa__generator_points__x
    // [0x60, 0x80) - ecdsa__generator_points__y
    // [0x80, 0xa0) - poseidon__poseidon__full_round_key0
    // [0xa0, 0xc0) - poseidon__poseidon__full_round_key1
    // [0xc0, 0xe0) - poseidon__poseidon__full_round_key2
    // [0xe0, 0x100) - poseidon__poseidon__partial_round_key0
    // [0x100, 0x120) - poseidon__poseidon__partial_round_key1
    // [0x120, 0x140) - trace_length
    // [0x140, 0x160) - offset_size
    // [0x160, 0x180) - half_offset_size
    // [0x180, 0x1a0) - initial_ap
    // [0x1a0, 0x1c0) - initial_pc
    // [0x1c0, 0x1e0) - final_ap
    // [0x1e0, 0x200) - final_pc
    // [0x200, 0x220) - memory__multi_column_perm__perm__interaction_elm
    // [0x220, 0x240) - memory__multi_column_perm__hash_interaction_elm0
    // [0x240, 0x260) - memory__multi_column_perm__perm__public_memory_prod
    // [0x260, 0x280) - range_check16__perm__interaction_elm
    // [0x280, 0x2a0) - range_check16__perm__public_memory_prod
    // [0x2a0, 0x2c0) - range_check_min
    // [0x2c0, 0x2e0) - range_check_max
    // [0x2e0, 0x300) - diluted_check__permutation__interaction_elm
    // [0x300, 0x320) - diluted_check__permutation__public_memory_prod
    // [0x320, 0x340) - diluted_check__first_elm
    // [0x340, 0x360) - diluted_check__interaction_z
    // [0x360, 0x380) - diluted_check__interaction_alpha
    // [0x380, 0x3a0) - diluted_check__final_cum_val
    // [0x3a0, 0x3c0) - pedersen__shift_point__x
    // [0x3c0, 0x3e0) - pedersen__shift_point__y
    // [0x3e0, 0x400) - initial_pedersen_addr
    // [0x400, 0x420) - initial_range_check_addr
    // [0x420, 0x440) - ecdsa__sig_config__alpha
    // [0x440, 0x460) - ecdsa__sig_config__shift_point__x
    // [0x460, 0x480) - ecdsa__sig_config__shift_point__y
    // [0x480, 0x4a0) - ecdsa__sig_config__beta
    // [0x4a0, 0x4c0) - initial_ecdsa_addr
    // [0x4c0, 0x4e0) - initial_bitwise_addr
    // [0x4e0, 0x500) - initial_ec_op_addr
    // [0x500, 0x520) - ec_op__curve_config__alpha
    // [0x520, 0x540) - initial_poseidon_addr
    // [0x540, 0x560) - trace_generator
    // [0x560, 0x580) - oods_point
    // [0x580, 0x640) - interaction_elements
    // [0x640, 0x660) - composition_alpha
    // [0x660, 0x2840) - oods_values
    // [0x2840, 0x2860) - cpu__decode__opcode_range_check__bit_0
    // [0x2860, 0x2880) - cpu__decode__opcode_range_check__bit_2
    // [0x2880, 0x28a0) - cpu__decode__opcode_range_check__bit_4
    // [0x28a0, 0x28c0) - cpu__decode__opcode_range_check__bit_3
    // [0x28c0, 0x28e0) - cpu__decode__flag_op1_base_op0_0
    // [0x28e0, 0x2900) - cpu__decode__opcode_range_check__bit_5
    // [0x2900, 0x2920) - cpu__decode__opcode_range_check__bit_6
    // [0x2920, 0x2940) - cpu__decode__opcode_range_check__bit_9
    // [0x2940, 0x2960) - cpu__decode__flag_res_op1_0
    // [0x2960, 0x2980) - cpu__decode__opcode_range_check__bit_7
    // [0x2980, 0x29a0) - cpu__decode__opcode_range_check__bit_8
    // [0x29a0, 0x29c0) - cpu__decode__flag_pc_update_regular_0
    // [0x29c0, 0x29e0) - cpu__decode__opcode_range_check__bit_12
    // [0x29e0, 0x2a00) - cpu__decode__opcode_range_check__bit_13
    // [0x2a00, 0x2a20) - cpu__decode__fp_update_regular_0
    // [0x2a20, 0x2a40) - cpu__decode__opcode_range_check__bit_1
    // [0x2a40, 0x2a60) - npc_reg_0
    // [0x2a60, 0x2a80) - cpu__decode__opcode_range_check__bit_10
    // [0x2a80, 0x2aa0) - cpu__decode__opcode_range_check__bit_11
    // [0x2aa0, 0x2ac0) - cpu__decode__opcode_range_check__bit_14
    // [0x2ac0, 0x2ae0) - memory__address_diff_0
    // [0x2ae0, 0x2b00) - range_check16__diff_0
    // [0x2b00, 0x2b20) - pedersen__hash0__ec_subset_sum__bit_0
    // [0x2b20, 0x2b40) - pedersen__hash0__ec_subset_sum__bit_neg_0
    // [0x2b40, 0x2b60) - range_check_builtin__value0_0
    // [0x2b60, 0x2b80) - range_check_builtin__value1_0
    // [0x2b80, 0x2ba0) - range_check_builtin__value2_0
    // [0x2ba0, 0x2bc0) - range_check_builtin__value3_0
    // [0x2bc0, 0x2be0) - range_check_builtin__value4_0
    // [0x2be0, 0x2c00) - range_check_builtin__value5_0
    // [0x2c00, 0x2c20) - range_check_builtin__value6_0
    // [0x2c20, 0x2c40) - range_check_builtin__value7_0
    // [0x2c40, 0x2c60) - ecdsa__signature0__doubling_key__x_squared
    // [0x2c60, 0x2c80) - ecdsa__signature0__exponentiate_generator__bit_0
    // [0x2c80, 0x2ca0) - ecdsa__signature0__exponentiate_generator__bit_neg_0
    // [0x2ca0, 0x2cc0) - ecdsa__signature0__exponentiate_key__bit_0
    // [0x2cc0, 0x2ce0) - ecdsa__signature0__exponentiate_key__bit_neg_0
    // [0x2ce0, 0x2d00) - bitwise__sum_var_0_0
    // [0x2d00, 0x2d20) - bitwise__sum_var_8_0
    // [0x2d20, 0x2d40) - ec_op__doubling_q__x_squared_0
    // [0x2d40, 0x2d60) - ec_op__ec_subset_sum__bit_0
    // [0x2d60, 0x2d80) - ec_op__ec_subset_sum__bit_neg_0
    // [0x2d80, 0x2da0) - poseidon__poseidon__full_rounds_state0_cubed_0
    // [0x2da0, 0x2dc0) - poseidon__poseidon__full_rounds_state1_cubed_0
    // [0x2dc0, 0x2de0) - poseidon__poseidon__full_rounds_state2_cubed_0
    // [0x2de0, 0x2e00) - poseidon__poseidon__full_rounds_state0_cubed_7
    // [0x2e00, 0x2e20) - poseidon__poseidon__full_rounds_state1_cubed_7
    // [0x2e20, 0x2e40) - poseidon__poseidon__full_rounds_state2_cubed_7
    // [0x2e40, 0x2e60) - poseidon__poseidon__full_rounds_state0_cubed_3
    // [0x2e60, 0x2e80) - poseidon__poseidon__full_rounds_state1_cubed_3
    // [0x2e80, 0x2ea0) - poseidon__poseidon__full_rounds_state2_cubed_3
    // [0x2ea0, 0x2ec0) - poseidon__poseidon__partial_rounds_state0_cubed_0
    // [0x2ec0, 0x2ee0) - poseidon__poseidon__partial_rounds_state0_cubed_1
    // [0x2ee0, 0x2f00) - poseidon__poseidon__partial_rounds_state0_cubed_2
    // [0x2f00, 0x2f20) - poseidon__poseidon__partial_rounds_state1_cubed_0
    // [0x2f20, 0x2f40) - poseidon__poseidon__partial_rounds_state1_cubed_1
    // [0x2f40, 0x2f60) - poseidon__poseidon__partial_rounds_state1_cubed_2
    // [0x2f60, 0x2f80) - poseidon__poseidon__partial_rounds_state1_cubed_19
    // [0x2f80, 0x2fa0) - poseidon__poseidon__partial_rounds_state1_cubed_20
    // [0x2fa0, 0x2fc0) - poseidon__poseidon__partial_rounds_state1_cubed_21
    // [0x2fc0, 0x3680) - expmods
    // [0x3680, 0x3b40) - domains
    // [0x3b40, 0x3e80) - denominator_invs
    // [0x3e80, 0x41c0) - denominators
    // [0x41c0, 0x4280) - expmod_context

    #[view]
    public fun fallback(ctx: vector<u256>): u256 {
        let res = 0;

        let remain = 532 - vector::length(&ctx);

        for (i in 0..remain) {
            push_back(&mut ctx, 0);
        };

        let pedersen__points__x = *borrow(&ctx, 0);
        let pedersen__points__y = *borrow(&ctx, 1);
        let ecdsa__generator_points__x = *borrow(&ctx, 2);
        let ecdsa__generator_points__y = *borrow(&ctx, 3);
        let poseidon__poseidon__full_round_key0 = *borrow(&ctx, 4);
        let poseidon__poseidon__full_round_key1 = *borrow(&ctx, 5);
        let poseidon__poseidon__full_round_key2 = *borrow(&ctx, 6);
        let poseidon__poseidon__partial_round_key0 = *borrow(&ctx, 7);
        let poseidon__poseidon__partial_round_key1 = *borrow(&ctx, 8);
        let trace_length = *borrow(&ctx, 9);
        let offset_size = *borrow(&ctx, 10);
        let half_offset_size = *borrow(&ctx, 11);
        let initial_ap = *borrow(&ctx, 12);
        let initial_pc = *borrow(&ctx, 13);
        let final_ap = *borrow(&ctx, 14);
        let final_pc = *borrow(&ctx, 15);
        let memory__multi_column_perm__perm__interaction_elm = *borrow(&ctx, 16);
        let memory__multi_column_perm__hash_interaction_elm0 = *borrow(&ctx, 17);
        let memory__multi_column_perm__perm__public_memory_prod = *borrow(&ctx, 18);
        let range_check16__perm__interaction_elm = *borrow(&ctx, 19);
        let range_check16__perm__public_memory_prod = *borrow(&ctx, 20);
        let range_check_min = *borrow(&ctx, 21);
        let range_check_max = *borrow(&ctx, 22);
        let diluted_check__permutation__interaction_elm = *borrow(&ctx, 23);
        let diluted_check__permutation__public_memory_prod = *borrow(&ctx, 24);
        let diluted_check__first_elm = *borrow(&ctx, 25);
        let diluted_check__interaction_z = *borrow(&ctx, 26);
        let diluted_check__interaction_alpha = *borrow(&ctx, 27);
        let diluted_check__final_cum_val = *borrow(&ctx, 28);
        let pedersen__shift_point__x = *borrow(&ctx, 29);
        let pedersen__shift_point__y = *borrow(&ctx, 30);
        let initial_pedersen_addr = *borrow(&ctx, 31);
        let initial_range_check_addr = *borrow(&ctx, 32);
        let ecdsa__sig_config__alpha = *borrow(&ctx, 33);
        let ecdsa__sig_config__shift_point__x = *borrow(&ctx, 34);
        let ecdsa__sig_config__shift_point__y = *borrow(&ctx, 35);
        let ecdsa__sig_config__beta = *borrow(&ctx, 36);
        let initial_ecdsa_addr = *borrow(&ctx, 37);
        let initial_bitwise_addr = *borrow(&ctx, 38);
        let initial_ec_op_addr = *borrow(&ctx, 39);
        let ec_op__curve_config__alpha = *borrow(&ctx, 40);
        let initial_poseidon_addr = *borrow(&ctx, 41);
        // let trace_generator = *borrow(&ctx, 42);
        let oods_point = *borrow(&ctx, 43);
        // let interaction_elements = *borrow(&ctx, 44);
        // let composition_alpha = *borrow(&ctx, 50);
        // let oods_values = *borrow(&ctx, 51);
        // let cpu__decode__opcode_range_check__bit_0 = *borrow(&ctx, 322);
        // let cpu__decode__opcode_range_check__bit_2 = *borrow(&ctx, 323);
        // let cpu__decode__opcode_range_check__bit_4 = *borrow(&ctx, 324);
        // let cpu__decode__opcode_range_check__bit_3 = *borrow(&ctx, 325);
        // let cpu__decode__flag_op1_base_op0_0 = *borrow(&ctx, 326);
        // let cpu__decode__opcode_range_check__bit_5 = *borrow(&ctx, 327);
        // let cpu__decode__opcode_range_check__bit_6 = *borrow(&ctx, 328);
        // let cpu__decode__opcode_range_check__bit_9 = *borrow(&ctx, 329);
        // let cpu__decode__flag_res_op1_0 = *borrow(&ctx, 330);
        // let cpu__decode__opcode_range_check__bit_7 = *borrow(&ctx, 331);
        // let cpu__decode__opcode_range_check__bit_8 = *borrow(&ctx, 332);
        // let cpu__decode__flag_pc_update_regular_0 = *borrow(&ctx, 333);
        // let cpu__decode__opcode_range_check__bit_12 = *borrow(&ctx, 334);
        // let cpu__decode__opcode_range_check__bit_13 = *borrow(&ctx, 335);
        // let cpu__decode__fp_update_regular_0 = *borrow(&ctx, 336);
        // let cpu__decode__opcode_range_check__bit_1 = *borrow(&ctx, 337);
        // let npc_reg_0 = *borrow(&ctx, 338);
        // let cpu__decode__opcode_range_check__bit_10 = *borrow(&ctx, 339);
        // let cpu__decode__opcode_range_check__bit_11 = *borrow(&ctx, 340);
        // let cpu__decode__opcode_range_check__bit_14 = *borrow(&ctx, 341);
        // let memory__address_diff_0 = *borrow(&ctx, 342);
        // let range_check16__diff_0 = *borrow(&ctx, 343);
        // let pedersen__hash0__ec_subset_sum__bit_0 = *borrow(&ctx, 344);
        // let pedersen__hash0__ec_subset_sum__bit_neg_0 = *borrow(&ctx, 345);
        // let range_check_builtin__value0_0 = *borrow(&ctx, 346);
        // let range_check_builtin__value1_0 = *borrow(&ctx, 347);
        // let range_check_builtin__value2_0 = *borrow(&ctx, 348);
        // let range_check_builtin__value3_0 = *borrow(&ctx, 349);
        // let range_check_builtin__value4_0 = *borrow(&ctx, 350);
        // let range_check_builtin__value5_0 = *borrow(&ctx, 351);
        // let range_check_builtin__value6_0 = *borrow(&ctx, 352);
        // let range_check_builtin__value7_0 = *borrow(&ctx, 353);
        // let ecdsa__signature0__doubling_key__x_squared = *borrow(&ctx, 354);
        // let ecdsa__signature0__exponentiate_generator__bit_0 = *borrow(&ctx, 355);
        // let ecdsa__signature0__exponentiate_generator__bit_neg_0 = *borrow(&ctx, 356);
        // let ecdsa__signature0__exponentiate_key__bit_0 = *borrow(&ctx, 357);
        // let ecdsa__signature0__exponentiate_key__bit_neg_0 = *borrow(&ctx, 358);
        // let bitwise__sum_var_0_0 = *borrow(&ctx, 359);
        // let bitwise__sum_var_8_0 = *borrow(&ctx, 360);
        // let ec_op__doubling_q__x_squared_0 = *borrow(&ctx, 361);
        // let ec_op__ec_subset_sum__bit_0 = *borrow(&ctx, 362);
        // let ec_op__ec_subset_sum__bit_neg_0 = *borrow(&ctx, 363);
        // let poseidon__poseidon__full_rounds_state0_cubed_0 = *borrow(&ctx, 364);
        // let poseidon__poseidon__full_rounds_state1_cubed_0 = *borrow(&ctx, 365);
        // let poseidon__poseidon__full_rounds_state2_cubed_0 = *borrow(&ctx, 366);
        // let poseidon__poseidon__full_rounds_state0_cubed_7 = *borrow(&ctx, 367);
        // let poseidon__poseidon__full_rounds_state1_cubed_7 = *borrow(&ctx, 368);
        // let poseidon__poseidon__full_rounds_state2_cubed_7 = *borrow(&ctx, 369);
        // let poseidon__poseidon__full_rounds_state0_cubed_3 = *borrow(&ctx, 370);
        // let poseidon__poseidon__full_rounds_state1_cubed_3 = *borrow(&ctx, 371);
        // let poseidon__poseidon__full_rounds_state2_cubed_3 = *borrow(&ctx, 372);
        // let poseidon__poseidon__partial_rounds_state0_cubed_0 = *borrow(&ctx, 373);
        // let poseidon__poseidon__partial_rounds_state0_cubed_1 = *borrow(&ctx, 374);
        // let poseidon__poseidon__partial_rounds_state0_cubed_2 = *borrow(&ctx, 375);
        // let poseidon__poseidon__partial_rounds_state1_cubed_0 = *borrow(&ctx, 376);
        // let poseidon__poseidon__partial_rounds_state1_cubed_1 = *borrow(&ctx, 377);
        // let poseidon__poseidon__partial_rounds_state1_cubed_2 = *borrow(&ctx, 378);
        // let poseidon__poseidon__partial_rounds_state1_cubed_19 = *borrow(&ctx, 379);
        // let poseidon__poseidon__partial_rounds_state1_cubed_20 = *borrow(&ctx, 380);
        // let poseidon__poseidon__partial_rounds_state1_cubed_21 = *borrow(&ctx, 381);
        // let expmods = *borrow(&ctx, 382);
        // let domains = *borrow(&ctx, 436);
        // let denominator_invs = *borrow(&ctx, 474);
        // let denominators = *borrow(&ctx, 500);
        // let expmod_context = *borrow(&ctx, 526);


        let point = oods_point;

        {
            // compute expmods
            // expmods[0] = point^(trace_length / 32768)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 32768));
                *borrow_mut(&mut ctx, 382) = val;
            };
            // expmods[1] = point^(trace_length / 16384)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 16384));
                *borrow_mut(&mut ctx, 383) = val;
            };
            // expmods[2] = point^(trace_length / 1024)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 1024));
                *borrow_mut(&mut ctx, 384) = val;
            };
            // expmods[3] = point^(trace_length / 512)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 512));
                *borrow_mut(&mut ctx, 385) = val;
            };
            // expmods[4] = point^(trace_length / 256)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 256));
                *borrow_mut(&mut ctx, 386) = val;
            };
            // expmods[5] = point^(trace_length / 128)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 128));
                *borrow_mut(&mut ctx, 387) = val;
            };
            // expmods[6] = point^(trace_length / 64)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 64));
                *borrow_mut(&mut ctx, 388) = val;
            };
            // expmods[7] = point^(trace_length / 16)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 16));
                *borrow_mut(&mut ctx, 389) = val;
            };
            // expmods[8] = point^(trace_length / 8)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 8));
                *borrow_mut(&mut ctx, 390) = val;
            };
            // expmods[9] = point^(trace_length / 4)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 4));
                *borrow_mut(&mut ctx, 391) = val;
            };
            // expmods[10] = point^(trace_length / 2)
            {
                let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 2));
                *borrow_mut(&mut ctx, 392) = val;
            };
            // expmods[11] = point^trace_length
            {
                let val = fpow(/*point*/ point, /*trace_length*/ trace_length);
                *borrow_mut(&mut ctx, 393) = val;
            };
            // expmods[12] = trace_generator^(trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (/*trace_length*/ trace_length / 64));
                *borrow_mut(&mut ctx, 394) = val;
            };
            // expmods[13] = trace_generator^(trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (/*trace_length*/ trace_length / 32));
                *borrow_mut(&mut ctx, 395) = val;
            };
            // expmods[14] = trace_generator^(3 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(3, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 396) = val;
            };
            // expmods[15] = trace_generator^(trace_length / 16)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (/*trace_length*/ trace_length / 16));
                *borrow_mut(&mut ctx, 397) = val;
            };
            // expmods[16] = trace_generator^(5 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(5, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 398) = val;
            };
            // expmods[17] = trace_generator^(3 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(3, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 399) = val;
            };
            // expmods[18] = trace_generator^(7 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(7, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 400) = val;
            };
            // expmods[19] = trace_generator^(trace_length / 8)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (/*trace_length*/ trace_length / 8));
                *borrow_mut(&mut ctx, 401) = val;
            };
            // expmods[20] = trace_generator^(9 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(9, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 402) = val;
            };
            // expmods[21] = trace_generator^(5 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(5, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 403) = val;
            };
            // expmods[22] = trace_generator^(11 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(11, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 404) = val;
            };
            // expmods[23] = trace_generator^(3 * trace_length / 16)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(3, /*trace_length*/ trace_length) / 16));
                *borrow_mut(&mut ctx, 405) = val;
            };
            // expmods[24] = trace_generator^(13 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(13, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 406) = val;
            };
            // expmods[25] = trace_generator^(7 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(7, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 407) = val;
            };
            // expmods[26] = trace_generator^(15 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(15, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 408) = val;
            };
            // expmods[27] = trace_generator^(trace_length / 2)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (/*trace_length*/ trace_length / 2));
                *borrow_mut(&mut ctx, 409) = val;
            };
            // expmods[28] = trace_generator^(19 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(19, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 410) = val;
            };
            // expmods[29] = trace_generator^(5 * trace_length / 8)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(5, /*trace_length*/ trace_length) / 8));
                *borrow_mut(&mut ctx, 411) = val;
            };
            // expmods[30] = trace_generator^(21 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(21, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 412) = val;
            };
            // expmods[31] = trace_generator^(11 * trace_length / 16)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(11, /*trace_length*/ trace_length) / 16));
                *borrow_mut(&mut ctx, 413) = val;
            };
            // expmods[32] = trace_generator^(23 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(23, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 414) = val;
            };
            // expmods[33] = trace_generator^(3 * trace_length / 4)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(3, /*trace_length*/ trace_length) / 4));
                *borrow_mut(&mut ctx, 415) = val;
            };
            // expmods[34] = trace_generator^(25 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(25, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 416) = val;
            };
            // expmods[35] = trace_generator^(13 * trace_length / 16)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(13, /*trace_length*/ trace_length) / 16));
                *borrow_mut(&mut ctx, 417) = val;
            };
            // expmods[36] = trace_generator^(27 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(27, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 418) = val;
            };
            // expmods[37] = trace_generator^(7 * trace_length / 8)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(7, /*trace_length*/ trace_length) / 8));
                *borrow_mut(&mut ctx, 419) = val;
            };
            // expmods[38] = trace_generator^(29 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(29, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 420) = val;
            };
            // expmods[39] = trace_generator^(15 * trace_length / 16)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(15, /*trace_length*/ trace_length) / 16));
                *borrow_mut(&mut ctx, 421) = val;
            };
            // expmods[40] = trace_generator^(61 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(61, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 422) = val;
            };
            // expmods[41] = trace_generator^(31 * trace_length / 32)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(31, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 423) = val;
            };
            // expmods[42] = trace_generator^(251 * trace_length / 256)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(251, /*trace_length*/ trace_length) / 256));
                *borrow_mut(&mut ctx, 424) = val;
            };
            // expmods[43] = trace_generator^(63 * trace_length / 64)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(63, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 425) = val;
            };
            // expmods[44] = trace_generator^(255 * trace_length / 256)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), (fmul(255, /*trace_length*/ trace_length) / 256));
                *borrow_mut(&mut ctx, 426) = val;
            };
            // expmods[45] = trace_generator^(trace_length - 16)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 16)) % PRIME));
                *borrow_mut(&mut ctx, 427) = val;
            };
            // expmods[46] = trace_generator^(trace_length - 2)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 2)) % PRIME));
                *borrow_mut(&mut ctx, 428) = val;
            };
            // expmods[47] = trace_generator^(trace_length - 4)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 4)) % PRIME));
                *borrow_mut(&mut ctx, 429) = val;
            };
            // expmods[48] = trace_generator^(trace_length - 8)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 8)) % PRIME));
                *borrow_mut(&mut ctx, 430) = val;
            };
            // expmods[49] = trace_generator^(trace_length - 512)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 512)) % PRIME));
                *borrow_mut(&mut ctx, 431) = val;
            };
            // expmods[50] = trace_generator^(trace_length - 256)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 256)) % PRIME));
                *borrow_mut(&mut ctx, 432) = val;
            };
            // expmods[51] = trace_generator^(trace_length - 32768)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 32768)) % PRIME));
                *borrow_mut(&mut ctx, 433) = val;
            };
            // expmods[52] = trace_generator^(trace_length - 1024)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 1024)) % PRIME));
                *borrow_mut(&mut ctx, 434) = val;
            };
            // expmods[53] = trace_generator^(trace_length - 16384)
            {
                let val = fpow(/*trace_generator*/ *borrow(&ctx, 42), ((/*trace_length*/ trace_length + (PRIME - 16384)) % PRIME));
                *borrow_mut(&mut ctx, 435) = val;
            };

        };

        {
            // compute domains
            // domains[0] = point^trace_length - 1
            {
                let val = ((/*(point^trace_length)*/ *borrow(&ctx, 393) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 436) = val;
            };
            // domains[1] = point^(trace_length / 2) - 1
            {
                let val = ((/*(point^(trace_length/2))*/ *borrow(&ctx, 392) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 437) = val;
            };
            // domains[2] = point^(trace_length / 4) - 1
            {
                let val = ((/*(point^(trace_length/4))*/ *borrow(&ctx, 391) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 438) = val;
            };
            // domains[3] = point^(trace_length / 8) - 1
            {
                let val = ((/*(point^(trace_length/8))*/ *borrow(&ctx, 390) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 439) = val;
            };
            // domains[4] = point^(trace_length / 16) - trace_generator^(15 * trace_length / 16)
            {
                let val = ((/*(point^(trace_length/16))*/ *borrow(&ctx, 389) + (PRIME - /*(trace_generator^((15*trace_length)/16))*/ *borrow(&ctx, 421))) % PRIME);
                *borrow_mut(&mut ctx, 440) = val;
            };
            // domains[5] = point^(trace_length / 16) - 1
            {
                let val = ((/*(point^(trace_length/16))*/ *borrow(&ctx, 389) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 441) = val;
            };
            // domains[6] = point^(trace_length / 64) - 1
            {
                let val = ((/*(point^(trace_length/64))*/ *borrow(&ctx, 388) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 442) = val;
            };
            // domains[7] = point^(trace_length / 128) - 1
            {
                let val = ((/*(point^(trace_length/128))*/ *borrow(&ctx, 387) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 443) = val;
            };
            // domains[8] = point^(trace_length / 256) - 1
            {
                let val = ((/*(point^(trace_length/256))*/ *borrow(&ctx, 386) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 444) = val;
            };
            // domains[9] = point^(trace_length / 256) - trace_generator^(255 * trace_length / 256)
            {
                let val = ((/*(point^(trace_length/256))*/ *borrow(&ctx, 386) + (PRIME - /*(trace_generator^((255*trace_length)/256))*/ *borrow(&ctx, 426))) % PRIME);
                *borrow_mut(&mut ctx, 445) = val;
            };
            // domains[10] = point^(trace_length / 256) - trace_generator^(63 * trace_length / 64)
            {
                let val = ((/*(point^(trace_length/256))*/ *borrow(&ctx, 386) + (PRIME - /*(trace_generator^((63*trace_length)/64))*/ *borrow(&ctx, 425))) % PRIME);
                *borrow_mut(&mut ctx, 446) = val;
            };
            // domains[11] = point^(trace_length / 256) - trace_generator^(3 * trace_length / 4)
            {
                let val = ((/*(point^(trace_length/256))*/ *borrow(&ctx, 386) + (PRIME - /*(trace_generator^((3*trace_length)/4))*/ *borrow(&ctx, 415))) % PRIME);
                *borrow_mut(&mut ctx, 447) = val;
            };
            // domains[12] = point^(trace_length / 512) - trace_generator^(trace_length / 2)
            {
                let val = ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^(trace_length/2))*/ *borrow(&ctx, 409))) % PRIME);
                *borrow_mut(&mut ctx, 448) = val;
            };
            // domains[13] = point^(trace_length / 512) - 1
            {
                let val = ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 449) = val;
            };
            // domains[14] = point^(trace_length / 512) - trace_generator^(31 * trace_length / 32)
            {
                let val = ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((31*trace_length)/32))*/ *borrow(&ctx, 423))) % PRIME);
                *borrow_mut(&mut ctx, 450) = val;
            };
            // domains[15] = (point^(trace_length / 512) - trace_generator^(11 * trace_length / 16)) * (point^(trace_length / 512) - trace_generator^(23 * trace_length / 32)) * (point^(trace_length / 512) - trace_generator^(3 * trace_length / 4)) * (point^(trace_length / 512) - trace_generator^(25 * trace_length / 32)) * (point^(trace_length / 512) - trace_generator^(13 * trace_length / 16)) * (point^(trace_length / 512) - trace_generator^(27 * trace_length / 32)) * (point^(trace_length / 512) - trace_generator^(7 * trace_length / 8)) * (point^(trace_length / 512) - trace_generator^(29 * trace_length / 32)) * (point^(trace_length / 512) - trace_generator^(15 * trace_length / 16)) * domain14
            {
                let val = fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((11*trace_length)/16))*/ *borrow(&ctx, 413))) % PRIME), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((23*trace_length)/32))*/ *borrow(&ctx, 414))) % PRIME)), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((3*trace_length)/4))*/ *borrow(&ctx, 415))) % PRIME)), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((25*trace_length)/32))*/ *borrow(&ctx, 416))) % PRIME)), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((13*trace_length)/16))*/ *borrow(&ctx, 417))) % PRIME)), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((27*trace_length)/32))*/ *borrow(&ctx, 418))) % PRIME)), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((7*trace_length)/8))*/ *borrow(&ctx, 419))) % PRIME)), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((29*trace_length)/32))*/ *borrow(&ctx, 420))) % PRIME)), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((15*trace_length)/16))*/ *borrow(&ctx, 421))) % PRIME)), /*domain14*/ *borrow(&ctx, 450));
                *borrow_mut(&mut ctx, 451) = val;
            };
            // domains[16] = (point^(trace_length / 512) - trace_generator^(61 * trace_length / 64)) * (point^(trace_length / 512) - trace_generator^(63 * trace_length / 64)) * domain14
            {
                let val = fmul(fmul(((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((61*trace_length)/64))*/ *borrow(&ctx, 422))) % PRIME), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((63*trace_length)/64))*/ *borrow(&ctx, 425))) % PRIME)), /*domain14*/ *borrow(&ctx, 450));
                *borrow_mut(&mut ctx, 452) = val;
            };
            // domains[17] = (point^(trace_length / 512) - trace_generator^(19 * trace_length / 32)) * (point^(trace_length / 512) - trace_generator^(5 * trace_length / 8)) * (point^(trace_length / 512) - trace_generator^(21 * trace_length / 32)) * domain15
            {
                let val = fmul(fmul(fmul(((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((19*trace_length)/32))*/ *borrow(&ctx, 410))) % PRIME), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((5*trace_length)/8))*/ *borrow(&ctx, 411))) % PRIME)), ((/*(point^(trace_length/512))*/ *borrow(&ctx, 385) + (PRIME - /*(trace_generator^((21*trace_length)/32))*/ *borrow(&ctx, 412))) % PRIME)), /*domain15*/ *borrow(&ctx, 451));
                *borrow_mut(&mut ctx, 453) = val;
            };
            // domains[18] = point^(trace_length / 1024) - trace_generator^(3 * trace_length / 4)
            {
                let val = ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((3*trace_length)/4))*/ *borrow(&ctx, 415))) % PRIME);
                *borrow_mut(&mut ctx, 454) = val;
            };
            // domains[19] = point^(trace_length / 1024) - 1
            {
                let val = ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 455) = val;
            };
            // domains[20] = (point^(trace_length / 1024) - trace_generator^(trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(trace_length / 32)) * (point^(trace_length / 1024) - trace_generator^(3 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(trace_length / 16)) * (point^(trace_length / 1024) - trace_generator^(5 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(3 * trace_length / 32)) * (point^(trace_length / 1024) - trace_generator^(7 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(trace_length / 8)) * (point^(trace_length / 1024) - trace_generator^(9 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(5 * trace_length / 32)) * (point^(trace_length / 1024) - trace_generator^(11 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(3 * trace_length / 16)) * (point^(trace_length / 1024) - trace_generator^(13 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(7 * trace_length / 32)) * (point^(trace_length / 1024) - trace_generator^(15 * trace_length / 64)) * domain19
            {
                let val = fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^(trace_length/64))*/ *borrow(&ctx, 394))) % PRIME), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^(trace_length/32))*/ *borrow(&ctx, 395))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((3*trace_length)/64))*/ *borrow(&ctx, 396))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^(trace_length/16))*/ *borrow(&ctx, 397))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((5*trace_length)/64))*/ *borrow(&ctx, 398))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((3*trace_length)/32))*/ *borrow(&ctx, 399))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((7*trace_length)/64))*/ *borrow(&ctx, 400))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^(trace_length/8))*/ *borrow(&ctx, 401))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((9*trace_length)/64))*/ *borrow(&ctx, 402))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((5*trace_length)/32))*/ *borrow(&ctx, 403))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((11*trace_length)/64))*/ *borrow(&ctx, 404))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((3*trace_length)/16))*/ *borrow(&ctx, 405))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((13*trace_length)/64))*/ *borrow(&ctx, 406))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((7*trace_length)/32))*/ *borrow(&ctx, 407))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 384) + (PRIME - /*(trace_generator^((15*trace_length)/64))*/ *borrow(&ctx, 408))) % PRIME)), /*domain19*/ *borrow(&ctx, 455));
                *borrow_mut(&mut ctx, 456) = val;
            };
            // domains[21] = point^(trace_length / 16384) - trace_generator^(255 * trace_length / 256)
            {
                let val = ((/*(point^(trace_length/16384))*/ *borrow(&ctx, 383) + (PRIME - /*(trace_generator^((255*trace_length)/256))*/ *borrow(&ctx, 426))) % PRIME);
                *borrow_mut(&mut ctx, 457) = val;
            };
            // domains[22] = point^(trace_length / 16384) - trace_generator^(251 * trace_length / 256)
            {
                let val = ((/*(point^(trace_length/16384))*/ *borrow(&ctx, 383) + (PRIME - /*(trace_generator^((251*trace_length)/256))*/ *borrow(&ctx, 424))) % PRIME);
                *borrow_mut(&mut ctx, 458) = val;
            };
            // domains[23] = point^(trace_length / 16384) - 1
            {
                let val = ((/*(point^(trace_length/16384))*/ *borrow(&ctx, 383) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 459) = val;
            };
            // domains[24] = point^(trace_length / 16384) - trace_generator^(63 * trace_length / 64)
            {
                let val = ((/*(point^(trace_length/16384))*/ *borrow(&ctx, 383) + (PRIME - /*(trace_generator^((63*trace_length)/64))*/ *borrow(&ctx, 425))) % PRIME);
                *borrow_mut(&mut ctx, 460) = val;
            };
            // domains[25] = point^(trace_length / 32768) - trace_generator^(255 * trace_length / 256)
            {
                let val = ((/*(point^(trace_length/32768))*/ *borrow(&ctx, 382) + (PRIME - /*(trace_generator^((255*trace_length)/256))*/ *borrow(&ctx, 426))) % PRIME);
                *borrow_mut(&mut ctx, 461) = val;
            };
            // domains[26] = point^(trace_length / 32768) - trace_generator^(251 * trace_length / 256)
            {
                let val = ((/*(point^(trace_length/32768))*/ *borrow(&ctx, 382) + (PRIME - /*(trace_generator^((251*trace_length)/256))*/ *borrow(&ctx, 424))) % PRIME);
                *borrow_mut(&mut ctx, 462) = val;
            };
            // domains[27] = point^(trace_length / 32768) - 1
            {
                let val = ((/*(point^(trace_length/32768))*/ *borrow(&ctx, 382) + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 463) = val;
            };
            // domains[28] = point - trace_generator^(trace_length - 16)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-16))*/ *borrow(&ctx, 427))) % PRIME);
                *borrow_mut(&mut ctx, 464) = val;
            };
            // domains[29] = point - 1
            {
                let val = ((/*point*/ point + (PRIME - 1)) % PRIME);
                *borrow_mut(&mut ctx, 465) = val;
            };
            // domains[30] = point - trace_generator^(trace_length - 2)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-2))*/ *borrow(&ctx, 428))) % PRIME);
                *borrow_mut(&mut ctx, 466) = val;
            };
            // domains[31] = point - trace_generator^(trace_length - 4)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-4))*/ *borrow(&ctx, 429))) % PRIME);
                *borrow_mut(&mut ctx, 467) = val;
            };
            // domains[32] = point - trace_generator^(trace_length - 8)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-8))*/ *borrow(&ctx, 430))) % PRIME);
                *borrow_mut(&mut ctx, 468) = val;
            };
            // domains[33] = point - trace_generator^(trace_length - 512)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-512))*/ *borrow(&ctx, 431))) % PRIME);
                *borrow_mut(&mut ctx, 469) = val;
            };
            // domains[34] = point - trace_generator^(trace_length - 256)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-256))*/ *borrow(&ctx, 432))) % PRIME);
                *borrow_mut(&mut ctx, 470) = val;
            };
            // domains[35] = point - trace_generator^(trace_length - 32768)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-32768))*/ *borrow(&ctx, 433))) % PRIME);
                *borrow_mut(&mut ctx, 471) = val;
            };
            // domains[36] = point - trace_generator^(trace_length - 1024)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-1024))*/ *borrow(&ctx, 434))) % PRIME);
                *borrow_mut(&mut ctx, 472) = val;
            };
            // domains[37] = point - trace_generator^(trace_length - 16384)
            {
                let val = ((/*point*/ point + (PRIME - /*(trace_generator^(trace_length-16384))*/ *borrow(&ctx, 435))) % PRIME);
                *borrow_mut(&mut ctx, 473) = val;
            };


        };

        {
            // compute denominators
            // denominators[0] = domains[0]
            {
                let val = /*domains[0]*/ *borrow(&ctx, 436);
                *borrow_mut(&mut ctx, 500) = val;
            };
            // denominators[1] = domains[4]
            {
                let val = /*domains[4]*/ *borrow(&ctx, 440);
                *borrow_mut(&mut ctx, 501) = val;
            };
            // denominators[2] = domains[5]
            {
                let val = /*domains[5]*/ *borrow(&ctx, 441);
                *borrow_mut(&mut ctx, 502) = val;
            };
            // denominators[3] = domains[28]
            {
                let val = /*domains[28]*/ *borrow(&ctx, 464);
                *borrow_mut(&mut ctx, 503) = val;
            };
            // denominators[4] = domains[29]
            {
                let val = /*domains[29]*/ *borrow(&ctx, 465);
                *borrow_mut(&mut ctx, 504) = val;
            };
            // denominators[5] = domains[1]
            {
                let val = /*domains[1]*/ *borrow(&ctx, 437);
                *borrow_mut(&mut ctx, 505) = val;
            };
            // denominators[6] = domains[30]
            {
                let val = /*domains[30]*/ *borrow(&ctx, 466);
                *borrow_mut(&mut ctx, 506) = val;
            };
            // denominators[7] = domains[3]
            {
                let val = /*domains[3]*/ *borrow(&ctx, 439);
                *borrow_mut(&mut ctx, 507) = val;
            };
            // denominators[8] = domains[2]
            {
                let val = /*domains[2]*/ *borrow(&ctx, 438);
                *borrow_mut(&mut ctx, 508) = val;
            };
            // denominators[9] = domains[31]
            {
                let val = /*domains[31]*/ *borrow(&ctx, 467);
                *borrow_mut(&mut ctx, 509) = val;
            };
            // denominators[10] = domains[32]
            {
                let val = /*domains[32]*/ *borrow(&ctx, 468);
                *borrow_mut(&mut ctx, 510) = val;
            };
            // denominators[11] = domains[8]
            {
                let val = /*domains[8]*/ *borrow(&ctx, 444);
                *borrow_mut(&mut ctx, 511) = val;
            };
            // denominators[12] = domains[9]
            {
                let val = /*domains[9]*/ *borrow(&ctx, 445);
                *borrow_mut(&mut ctx, 512) = val;
            };
            // denominators[13] = domains[10]
            {
                let val = /*domains[10]*/ *borrow(&ctx, 446);
                *borrow_mut(&mut ctx, 513) = val;
            };
            // denominators[14] = domains[13]
            {
                let val = /*domains[13]*/ *borrow(&ctx, 449);
                *borrow_mut(&mut ctx, 514) = val;
            };
            // denominators[15] = domains[6]
            {
                let val = /*domains[6]*/ *borrow(&ctx, 442);
                *borrow_mut(&mut ctx, 515) = val;
            };
            // denominators[16] = domains[21]
            {
                let val = /*domains[21]*/ *borrow(&ctx, 457);
                *borrow_mut(&mut ctx, 516) = val;
            };
            // denominators[17] = domains[7]
            {
                let val = /*domains[7]*/ *borrow(&ctx, 443);
                *borrow_mut(&mut ctx, 517) = val;
            };
            // denominators[18] = domains[25]
            {
                let val = /*domains[25]*/ *borrow(&ctx, 461);
                *borrow_mut(&mut ctx, 518) = val;
            };
            // denominators[19] = domains[26]
            {
                let val = /*domains[26]*/ *borrow(&ctx, 462);
                *borrow_mut(&mut ctx, 519) = val;
            };
            // denominators[20] = domains[22]
            {
                let val = /*domains[22]*/ *borrow(&ctx, 458);
                *borrow_mut(&mut ctx, 520) = val;
            };
            // denominators[21] = domains[27]
            {
                let val = /*domains[27]*/ *borrow(&ctx, 463);
                *borrow_mut(&mut ctx, 521) = val;
            };
            // denominators[22] = domains[23]
            {
                let val = /*domains[23]*/ *borrow(&ctx, 459);
                *borrow_mut(&mut ctx, 522) = val;
            };
            // denominators[23] = domains[19]
            {
                let val = /*domains[19]*/ *borrow(&ctx, 455);
                *borrow_mut(&mut ctx, 523) = val;
            };
            // denominators[24] = domains[20]
            {
                let val = /*domains[20]*/ *borrow(&ctx, 456);
                *borrow_mut(&mut ctx, 524) = val;
            };
            // denominators[25] = domains[24]
            {
                let val = /*domains[24]*/ *borrow(&ctx, 460);
                *borrow_mut(&mut ctx, 525) = val;
            };

        };

        {
            // compute denominator_invs

            // Start by computing the cumulative product.
            // Let (d_0, d_1, d_2, ..., d_{n-1}) be the values in denominators. After this loop
            // denominatorInvs will be (1, d_0, d_0 * d_1, ...) and prod will contain the value of
            // d_0 * ... * d_{n-1}.
            // Compute the offset between the partialProducts array and the input values array.
            let productsToValuesOffset = 26;
            let prod = 1u256;
            let partialProductEndPtr = 500;
            let partialProductPtr = 474;
            while (partialProductPtr < partialProductEndPtr) {
                *vector::borrow_mut(&mut ctx, partialProductPtr) = prod;
                // prod *= d_{i}.
                prod = fmul(prod, *borrow(&ctx, partialProductPtr + productsToValuesOffset));
                partialProductPtr = partialProductPtr + 1;

            };

            let firstPartialProductPtr = 474;
            // Compute the inverse of the product.

            let prodInv = fpow(prod, PRIME - 2);

            assert!(prodInv != 0, EPRODUCT_INVERSE_ZERO);

            // Compute the inverses.
            // Loop over denominator_invs in reverse order.
            // currentPartialProductPtr is initialized to one past the end.
            let currentPartialProductPtr = 500;
            while (currentPartialProductPtr > firstPartialProductPtr) {
                currentPartialProductPtr = currentPartialProductPtr - 1;
                // Store 1/d_{i} = (d_0 * ... * d_{i-1}) * 1/(d_0 * ... * d_{i}).
                *borrow_mut(&mut ctx, currentPartialProductPtr) = fmul(*borrow(&ctx, currentPartialProductPtr), prodInv);
                // Update prodInv to be 1/(d_0 * ... * d_{i-1}) by multiplying by d_i.
                prodInv = fmul(prodInv, *borrow(&ctx, currentPartialProductPtr + productsToValuesOffset));
            };

        };

        {
            // cpu/decode/opcode_range_check/bit_0 = column0_row0 - (column0_row1 + column0_row1)
            {
                let val = ((/*column0_row0*/ *borrow(&ctx, 51) + (PRIME - ((/*column0_row1*/ *borrow(&ctx, 52) + /*column0_row1*/ *borrow(&ctx, 52)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 322) = val;
            };
            // cpu/decode/opcode_range_check/bit_2 = column0_row2 - (column0_row3 + column0_row3)
            {
                let val = ((/*column0_row2*/ *borrow(&ctx, 53) + (PRIME - ((/*column0_row3*/ *borrow(&ctx, 54) + /*column0_row3*/ *borrow(&ctx, 54)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 323) = val;
            };
            // cpu/decode/opcode_range_check/bit_4 = column0_row4 - (column0_row5 + column0_row5)
            {
                let val = ((/*column0_row4*/ *borrow(&ctx, 55) + (PRIME - ((/*column0_row5*/ *borrow(&ctx, 56) + /*column0_row5*/ *borrow(&ctx, 56)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 324) = val;
            };
            // cpu/decode/opcode_range_check/bit_3 = column0_row3 - (column0_row4 + column0_row4)
            {
                let val = ((/*column0_row3*/ *borrow(&ctx, 54) + (PRIME - ((/*column0_row4*/ *borrow(&ctx, 55) + /*column0_row4*/ *borrow(&ctx, 55)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 325) = val;
            };
            // cpu/decode/flag_op1_base_op0_0 = 1 - (cpu__decode__opcode_range_check__bit_2 + cpu__decode__opcode_range_check__bit_4 + cpu__decode__opcode_range_check__bit_3)
            {
                let val = ((1 + (PRIME - ((((/*cpu__decode__opcode_range_check__bit_2*/ *borrow(&ctx, 323) + /*cpu__decode__opcode_range_check__bit_4*/ *borrow(&ctx, 324)) % PRIME) + /*cpu__decode__opcode_range_check__bit_3*/ *borrow(&ctx, 325)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 326) = val;
            };
            // cpu/decode/opcode_range_check/bit_5 = column0_row5 - (column0_row6 + column0_row6)
            {
                let val = ((/*column0_row5*/ *borrow(&ctx, 56) + (PRIME - ((/*column0_row6*/ *borrow(&ctx, 57) + /*column0_row6*/ *borrow(&ctx, 57)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 327) = val;
            };
            // cpu/decode/opcode_range_check/bit_6 = column0_row6 - (column0_row7 + column0_row7)
            {
                let val = ((/*column0_row6*/ *borrow(&ctx, 57) + (PRIME - ((/*column0_row7*/ *borrow(&ctx, 58) + /*column0_row7*/ *borrow(&ctx, 58)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 328) = val;
            };
            // cpu/decode/opcode_range_check/bit_9 = column0_row9 - (column0_row10 + column0_row10)
            {
                let val = ((/*column0_row9*/ *borrow(&ctx, 60) + (PRIME - ((/*column0_row10*/ *borrow(&ctx, 61) + /*column0_row10*/ *borrow(&ctx, 61)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 329) = val;
            };
            // cpu/decode/flag_res_op1_0 = 1 - (cpu__decode__opcode_range_check__bit_5 + cpu__decode__opcode_range_check__bit_6 + cpu__decode__opcode_range_check__bit_9)
            {
                let val = ((1 + (PRIME - ((((/*cpu__decode__opcode_range_check__bit_5*/ *borrow(&ctx, 327) + /*cpu__decode__opcode_range_check__bit_6*/ *borrow(&ctx, 328)) % PRIME) + /*cpu__decode__opcode_range_check__bit_9*/ *borrow(&ctx, 329)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 330) = val;
            };
            // cpu/decode/opcode_range_check/bit_7 = column0_row7 - (column0_row8 + column0_row8)
            {
                let val = ((/*column0_row7*/ *borrow(&ctx, 58) + (PRIME - ((/*column0_row8*/ *borrow(&ctx, 59) + /*column0_row8*/ *borrow(&ctx, 59)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 331) = val;
            };
            // cpu/decode/opcode_range_check/bit_8 = column0_row8 - (column0_row9 + column0_row9)
            {
                let val = ((/*column0_row8*/ *borrow(&ctx, 59) + (PRIME - ((/*column0_row9*/ *borrow(&ctx, 60) + /*column0_row9*/ *borrow(&ctx, 60)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 332) = val;
            };
            // cpu/decode/flag_pc_update_regular_0 = 1 - (cpu__decode__opcode_range_check__bit_7 + cpu__decode__opcode_range_check__bit_8 + cpu__decode__opcode_range_check__bit_9)
            {
                let val = ((1 + (PRIME - ((((/*cpu__decode__opcode_range_check__bit_7*/ *borrow(&ctx, 331) + /*cpu__decode__opcode_range_check__bit_8*/ *borrow(&ctx, 332)) % PRIME) + /*cpu__decode__opcode_range_check__bit_9*/ *borrow(&ctx, 329)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 333) = val;
            };
            // cpu/decode/opcode_range_check/bit_12 = column0_row12 - (column0_row13 + column0_row13)
            {
                let val = ((/*column0_row12*/ *borrow(&ctx, 63) + (PRIME - ((/*column0_row13*/ *borrow(&ctx, 64) + /*column0_row13*/ *borrow(&ctx, 64)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 334) = val;
            };
            // cpu/decode/opcode_range_check/bit_13 = column0_row13 - (column0_row14 + column0_row14)
            {
                let val = ((/*column0_row13*/ *borrow(&ctx, 64) + (PRIME - ((/*column0_row14*/ *borrow(&ctx, 65) + /*column0_row14*/ *borrow(&ctx, 65)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 335) = val;
            };
            // cpu/decode/fp_update_regular_0 = 1 - (cpu__decode__opcode_range_check__bit_12 + cpu__decode__opcode_range_check__bit_13)
            {
                let val = ((1 + (PRIME - ((/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334) + /*cpu__decode__opcode_range_check__bit_13*/ *borrow(&ctx, 335)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 336) = val;
            };
            // cpu/decode/opcode_range_check/bit_1 = column0_row1 - (column0_row2 + column0_row2)
            {
                let val = ((/*column0_row1*/ *borrow(&ctx, 52) + (PRIME - ((/*column0_row2*/ *borrow(&ctx, 53) + /*column0_row2*/ *borrow(&ctx, 53)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 337) = val;
            };
            // npc_reg_0 = column5_row0 + cpu__decode__opcode_range_check__bit_2 + 1
            {
                let val = ((((/*column5_row0*/ *borrow(&ctx, 87) + /*cpu__decode__opcode_range_check__bit_2*/ *borrow(&ctx, 323)) % PRIME) + 1) % PRIME);
                *borrow_mut(&mut ctx, 338) = val;
            };
            // cpu/decode/opcode_range_check/bit_10 = column0_row10 - (column0_row11 + column0_row11)
            {
                let val = ((/*column0_row10*/ *borrow(&ctx, 61) + (PRIME - ((/*column0_row11*/ *borrow(&ctx, 62) + /*column0_row11*/ *borrow(&ctx, 62)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 339) = val;
            };
            // cpu/decode/opcode_range_check/bit_11 = column0_row11 - (column0_row12 + column0_row12)
            {
                let val = ((/*column0_row11*/ *borrow(&ctx, 62) + (PRIME - ((/*column0_row12*/ *borrow(&ctx, 63) + /*column0_row12*/ *borrow(&ctx, 63)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 340) = val;
            };
            // cpu/decode/opcode_range_check/bit_14 = column0_row14 - (column0_row15 + column0_row15)
            {
                let val = ((/*column0_row14*/ *borrow(&ctx, 65) + (PRIME - ((/*column0_row15*/ *borrow(&ctx, 66) + /*column0_row15*/ *borrow(&ctx, 66)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 341) = val;
            };
            // memory/address_diff_0 = column6_row2 - column6_row0
            {
                let val = ((/*column6_row2*/ *borrow(&ctx, 151) + (PRIME - /*column6_row0*/ *borrow(&ctx, 149))) % PRIME);
                *borrow_mut(&mut ctx, 342) = val;
            };
            // range_check16/diff_0 = column7_row6 - column7_row2
            {
                let val = ((/*column7_row6*/ *borrow(&ctx, 159) + (PRIME - /*column7_row2*/ *borrow(&ctx, 155))) % PRIME);
                *borrow_mut(&mut ctx, 343) = val;
            };
            // pedersen/hash0/ec_subset_sum/bit_0 = column3_row0 - (column3_row1 + column3_row1)
            {
                let val = ((/*column3_row0*/ *borrow(&ctx, 76) + (PRIME - ((/*column3_row1*/ *borrow(&ctx, 77) + /*column3_row1*/ *borrow(&ctx, 77)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 344) = val;
            };
            // pedersen/hash0/ec_subset_sum/bit_neg_0 = 1 - pedersen__hash0__ec_subset_sum__bit_0
            {
                let val = ((1 + (PRIME - /*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 344))) % PRIME);
                *borrow_mut(&mut ctx, 345) = val;
            };
            // range_check_builtin/value0_0 = column7_row12
            {
                let val = /*column7_row12*/ *borrow(&ctx, 164);
                *borrow_mut(&mut ctx, 346) = val;
            };
            // range_check_builtin/value1_0 = range_check_builtin__value0_0 * offset_size + column7_row44
            {
                let val = ((fmul(/*range_check_builtin__value0_0*/ *borrow(&ctx, 346), /*offset_size*/ offset_size) + /*column7_row44*/ *borrow(&ctx, 172)) % PRIME);
                *borrow_mut(&mut ctx, 347) = val;
            };
            // range_check_builtin/value2_0 = range_check_builtin__value1_0 * offset_size + column7_row76
            {
                let val = ((fmul(/*range_check_builtin__value1_0*/ *borrow(&ctx, 347), /*offset_size*/ offset_size) + /*column7_row76*/ *borrow(&ctx, 175)) % PRIME);
                *borrow_mut(&mut ctx, 348) = val;
            };
            // range_check_builtin/value3_0 = range_check_builtin__value2_0 * offset_size + column7_row108
            {
                let val = ((fmul(/*range_check_builtin__value2_0*/ *borrow(&ctx, 348), /*offset_size*/ offset_size) + /*column7_row108*/ *borrow(&ctx, 178)) % PRIME);
                *borrow_mut(&mut ctx, 349) = val;
            };
            // range_check_builtin/value4_0 = range_check_builtin__value3_0 * offset_size + column7_row140
            {
                let val = ((fmul(/*range_check_builtin__value3_0*/ *borrow(&ctx, 349), /*offset_size*/ offset_size) + /*column7_row140*/ *borrow(&ctx, 181)) % PRIME);
                *borrow_mut(&mut ctx, 350) = val;
            };
            // range_check_builtin/value5_0 = range_check_builtin__value4_0 * offset_size + column7_row172
            {
                let val = ((fmul(/*range_check_builtin__value4_0*/ *borrow(&ctx, 350), /*offset_size*/ offset_size) + /*column7_row172*/ *borrow(&ctx, 184)) % PRIME);
                *borrow_mut(&mut ctx, 351) = val;
            };
            // range_check_builtin/value6_0 = range_check_builtin__value5_0 * offset_size + column7_row204
            {
                let val = ((fmul(/*range_check_builtin__value5_0*/ *borrow(&ctx, 351), /*offset_size*/ offset_size) + /*column7_row204*/ *borrow(&ctx, 187)) % PRIME);
                *borrow_mut(&mut ctx, 352) = val;
            };
            // range_check_builtin/value7_0 = range_check_builtin__value6_0 * offset_size + column7_row236
            {
                let val = ((fmul(/*range_check_builtin__value6_0*/ *borrow(&ctx, 352), /*offset_size*/ offset_size) + /*column7_row236*/ *borrow(&ctx, 190)) % PRIME);
                *borrow_mut(&mut ctx, 353) = val;
            };
            // ecdsa/signature0/doubling_key/x_squared = column8_row1 * column8_row1
            {
                let val = fmul(/*column8_row1*/ *borrow(&ctx, 210), /*column8_row1*/ *borrow(&ctx, 210));
                *borrow_mut(&mut ctx, 354) = val;
            };
            // ecdsa/signature0/exponentiate_generator/bit_0 = column8_row59 - (column8_row187 + column8_row187)
            {
                let val = ((/*column8_row59*/ *borrow(&ctx, 247) + (PRIME - ((/*column8_row187*/ *borrow(&ctx, 266) + /*column8_row187*/ *borrow(&ctx, 266)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 355) = val;
            };
            // ecdsa/signature0/exponentiate_generator/bit_neg_0 = 1 - ecdsa__signature0__exponentiate_generator__bit_0
            {
                let val = ((1 + (PRIME - /*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 355))) % PRIME);
                *borrow_mut(&mut ctx, 356) = val;
            };
            // ecdsa/signature0/exponentiate_key/bit_0 = column8_row9 - (column8_row73 + column8_row73)
            {
                let val = ((/*column8_row9*/ *borrow(&ctx, 218) + (PRIME - ((/*column8_row73*/ *borrow(&ctx, 252) + /*column8_row73*/ *borrow(&ctx, 252)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 357) = val;
            };
            // ecdsa/signature0/exponentiate_key/bit_neg_0 = 1 - ecdsa__signature0__exponentiate_key__bit_0
            {
                let val = ((1 + (PRIME - /*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 357))) % PRIME);
                *borrow_mut(&mut ctx, 358) = val;
            };
            // bitwise/sum_var_0_0 = column7_row1 + column7_row17 * 2 + column7_row33 * 4 + column7_row49 * 8 + column7_row65 * 18446744073709551616 + column7_row81 * 36893488147419103232 + column7_row97 * 73786976294838206464 + column7_row113 * 147573952589676412928
            {
                let val = ((((((((((((((/*column7_row1*/ *borrow(&ctx, 154) + fmul(/*column7_row17*/ *borrow(&ctx, 167), 2)) % PRIME) + fmul(/*column7_row33*/ *borrow(&ctx, 171), 4)) % PRIME) + fmul(/*column7_row49*/ *borrow(&ctx, 173), 8)) % PRIME) + fmul(/*column7_row65*/ *borrow(&ctx, 174), 18446744073709551616)) % PRIME) + fmul(/*column7_row81*/ *borrow(&ctx, 176), 36893488147419103232)) % PRIME) + fmul(/*column7_row97*/ *borrow(&ctx, 177), 73786976294838206464)) % PRIME) + fmul(/*column7_row113*/ *borrow(&ctx, 179), 147573952589676412928)) % PRIME);
                *borrow_mut(&mut ctx, 359) = val;
            };
            // bitwise/sum_var_8_0 = column7_row129 * 340282366920938463463374607431768211456 + column7_row145 * 680564733841876926926749214863536422912 + column7_row161 * 1361129467683753853853498429727072845824 + column7_row177 * 2722258935367507707706996859454145691648 + column7_row193 * 6277101735386680763835789423207666416102355444464034512896 + column7_row209 * 12554203470773361527671578846415332832204710888928069025792 + column7_row225 * 25108406941546723055343157692830665664409421777856138051584 + column7_row241 * 50216813883093446110686315385661331328818843555712276103168
            {
                let val = ((((((((((((((fmul(/*column7_row129*/ *borrow(&ctx, 180), 340282366920938463463374607431768211456) + fmul(/*column7_row145*/ *borrow(&ctx, 182), 680564733841876926926749214863536422912)) % PRIME) + fmul(/*column7_row161*/ *borrow(&ctx, 183), 1361129467683753853853498429727072845824)) % PRIME) + fmul(/*column7_row177*/ *borrow(&ctx, 185), 2722258935367507707706996859454145691648)) % PRIME) + fmul(/*column7_row193*/ *borrow(&ctx, 186), 6277101735386680763835789423207666416102355444464034512896)) % PRIME) + fmul(/*column7_row209*/ *borrow(&ctx, 188), 12554203470773361527671578846415332832204710888928069025792)) % PRIME) + fmul(/*column7_row225*/ *borrow(&ctx, 189), 25108406941546723055343157692830665664409421777856138051584)) % PRIME) + fmul(/*column7_row241*/ *borrow(&ctx, 191), 50216813883093446110686315385661331328818843555712276103168)) % PRIME);
                *borrow_mut(&mut ctx, 360) = val;
            };
            // ec_op/doubling_q/x_squared_0 = column8_row41 * column8_row41
            {
                let val = fmul(/*column8_row41*/ *borrow(&ctx, 238), /*column8_row41*/ *borrow(&ctx, 238));
                *borrow_mut(&mut ctx, 361) = val;
            };
            // ec_op/ec_subset_sum/bit_0 = column8_row21 - (column8_row85 + column8_row85)
            {
                let val = ((/*column8_row21*/ *borrow(&ctx, 227) + (PRIME - ((/*column8_row85*/ *borrow(&ctx, 255) + /*column8_row85*/ *borrow(&ctx, 255)) % PRIME))) % PRIME);
                *borrow_mut(&mut ctx, 362) = val;
            };
            // ec_op/ec_subset_sum/bit_neg_0 = 1 - ec_op__ec_subset_sum__bit_0
            {
                let val = ((1 + (PRIME - /*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 362))) % PRIME);
                *borrow_mut(&mut ctx, 363) = val;
            };
            // poseidon/poseidon/full_rounds_state0_cubed_0 = column8_row53 * column8_row29
            {
                let val = fmul(/*column8_row53*/ *borrow(&ctx, 244), /*column8_row29*/ *borrow(&ctx, 232));
                *borrow_mut(&mut ctx, 364) = val;
            };
            // poseidon/poseidon/full_rounds_state1_cubed_0 = column8_row13 * column8_row61
            {
                let val = fmul(/*column8_row13*/ *borrow(&ctx, 222), /*column8_row61*/ *borrow(&ctx, 248));
                *borrow_mut(&mut ctx, 365) = val;
            };
            // poseidon/poseidon/full_rounds_state2_cubed_0 = column8_row45 * column8_row3
            {
                let val = fmul(/*column8_row45*/ *borrow(&ctx, 240), /*column8_row3*/ *borrow(&ctx, 212));
                *borrow_mut(&mut ctx, 366) = val;
            };
            // poseidon/poseidon/full_rounds_state0_cubed_7 = column8_row501 * column8_row477
            {
                let val = fmul(/*column8_row501*/ *borrow(&ctx, 287), /*column8_row477*/ *borrow(&ctx, 285));
                *borrow_mut(&mut ctx, 367) = val;
            };
            // poseidon/poseidon/full_rounds_state1_cubed_7 = column8_row461 * column8_row509
            {
                let val = fmul(/*column8_row461*/ *borrow(&ctx, 284), /*column8_row509*/ *borrow(&ctx, 288));
                *borrow_mut(&mut ctx, 368) = val;
            };
            // poseidon/poseidon/full_rounds_state2_cubed_7 = column8_row493 * column8_row451
            {
                let val = fmul(/*column8_row493*/ *borrow(&ctx, 286), /*column8_row451*/ *borrow(&ctx, 283));
                *borrow_mut(&mut ctx, 369) = val;
            };
            // poseidon/poseidon/full_rounds_state0_cubed_3 = column8_row245 * column8_row221
            {
                let val = fmul(/*column8_row245*/ *borrow(&ctx, 272), /*column8_row221*/ *borrow(&ctx, 270));
                *borrow_mut(&mut ctx, 370) = val;
            };
            // poseidon/poseidon/full_rounds_state1_cubed_3 = column8_row205 * column8_row253
            {
                let val = fmul(/*column8_row205*/ *borrow(&ctx, 268), /*column8_row253*/ *borrow(&ctx, 273));
                *borrow_mut(&mut ctx, 371) = val;
            };
            // poseidon/poseidon/full_rounds_state2_cubed_3 = column8_row237 * column8_row195
            {
                let val = fmul(/*column8_row237*/ *borrow(&ctx, 271), /*column8_row195*/ *borrow(&ctx, 267));
                *borrow_mut(&mut ctx, 372) = val;
            };
            // poseidon/poseidon/partial_rounds_state0_cubed_0 = column7_row3 * column7_row7
            {
                let val = fmul(/*column7_row3*/ *borrow(&ctx, 156), /*column7_row7*/ *borrow(&ctx, 160));
                *borrow_mut(&mut ctx, 373) = val;
            };
            // poseidon/poseidon/partial_rounds_state0_cubed_1 = column7_row11 * column7_row15
            {
                let val = fmul(/*column7_row11*/ *borrow(&ctx, 163), /*column7_row15*/ *borrow(&ctx, 166));
                *borrow_mut(&mut ctx, 374) = val;
            };
            // poseidon/poseidon/partial_rounds_state0_cubed_2 = column7_row19 * column7_row23
            {
                let val = fmul(/*column7_row19*/ *borrow(&ctx, 168), /*column7_row23*/ *borrow(&ctx, 169));
                *borrow_mut(&mut ctx, 375) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_0 = column8_row6 * column8_row14
            {
                let val = fmul(/*column8_row6*/ *borrow(&ctx, 215), /*column8_row14*/ *borrow(&ctx, 223));
                *borrow_mut(&mut ctx, 376) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_1 = column8_row22 * column8_row30
            {
                let val = fmul(/*column8_row22*/ *borrow(&ctx, 228), /*column8_row30*/ *borrow(&ctx, 233));
                *borrow_mut(&mut ctx, 377) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_2 = column8_row38 * column8_row46
            {
                let val = fmul(/*column8_row38*/ *borrow(&ctx, 237), /*column8_row46*/ *borrow(&ctx, 241));
                *borrow_mut(&mut ctx, 378) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_19 = column8_row310 * column8_row318
            {
                let val = fmul(/*column8_row310*/ *borrow(&ctx, 277), /*column8_row318*/ *borrow(&ctx, 278));
                *borrow_mut(&mut ctx, 379) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_20 = column8_row326 * column8_row334
            {
                let val = fmul(/*column8_row326*/ *borrow(&ctx, 279), /*column8_row334*/ *borrow(&ctx, 280));
                *borrow_mut(&mut ctx, 380) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_21 = column8_row342 * column8_row350
            {
                let val = fmul(/*column8_row342*/ *borrow(&ctx, 281), /*column8_row350*/ *borrow(&ctx, 282));
                *borrow_mut(&mut ctx, 381) = val;
            };


            // compute compositions

            let composition_alpha_pow = 1u256;
            let composition_alpha = /*composition_alpha*/ *borrow(&ctx, 50);


            //Constraint expression for cpu/decode/opcode_range_check/bit: cpu__decode__opcode_range_check__bit_0 * cpu__decode__opcode_range_check__bit_0 - cpu__decode__opcode_range_check__bit_0
            {
                let val =((fmul(/*cpu__decode__opcode_range_check__bit_0*/ *borrow(&ctx, 322), /*cpu__decode__opcode_range_check__bit_0*/ *borrow(&ctx, 322)) + (PRIME - /*cpu__decode__opcode_range_check__bit_0*/ *borrow(&ctx, 322))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 501));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 474));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/opcode_range_check/zero: column0_row0
            {
                let val =/*column0_row0*/ *borrow(&ctx, 51);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 475));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/opcode_range_check_input: column5_row1 - (((column0_row0 * offset_size + column7_row4) * offset_size + column7_row8) * offset_size + column7_row0)
            {
                let val =((/*column5_row1*/ *borrow(&ctx, 88) + (PRIME - ((fmul(((fmul(((fmul(/*column0_row0*/ *borrow(&ctx, 51), /*offset_size*/ offset_size) + /*column7_row4*/ *borrow(&ctx, 157)) % PRIME), /*offset_size*/ offset_size) + /*column7_row8*/ *borrow(&ctx, 161)) % PRIME), /*offset_size*/ offset_size) + /*column7_row0*/ *borrow(&ctx, 153)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/flag_op1_base_op0_bit: cpu__decode__flag_op1_base_op0_0 * cpu__decode__flag_op1_base_op0_0 - cpu__decode__flag_op1_base_op0_0
            {
                let val =((fmul(/*cpu__decode__flag_op1_base_op0_0*/ *borrow(&ctx, 326), /*cpu__decode__flag_op1_base_op0_0*/ *borrow(&ctx, 326)) + (PRIME - /*cpu__decode__flag_op1_base_op0_0*/ *borrow(&ctx, 326))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/flag_res_op1_bit: cpu__decode__flag_res_op1_0 * cpu__decode__flag_res_op1_0 - cpu__decode__flag_res_op1_0
            {
                let val =((fmul(/*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 330), /*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 330)) + (PRIME - /*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 330))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/flag_pc_update_regular_bit: cpu__decode__flag_pc_update_regular_0 * cpu__decode__flag_pc_update_regular_0 - cpu__decode__flag_pc_update_regular_0
            {
                let val =((fmul(/*cpu__decode__flag_pc_update_regular_0*/ *borrow(&ctx, 333), /*cpu__decode__flag_pc_update_regular_0*/ *borrow(&ctx, 333)) + (PRIME - /*cpu__decode__flag_pc_update_regular_0*/ *borrow(&ctx, 333))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/fp_update_regular_bit: cpu__decode__fp_update_regular_0 * cpu__decode__fp_update_regular_0 - cpu__decode__fp_update_regular_0
            {
                let val =((fmul(/*cpu__decode__fp_update_regular_0*/ *borrow(&ctx, 336), /*cpu__decode__fp_update_regular_0*/ *borrow(&ctx, 336)) + (PRIME - /*cpu__decode__fp_update_regular_0*/ *borrow(&ctx, 336))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/mem_dst_addr: column5_row8 + half_offset_size - (cpu__decode__opcode_range_check__bit_0 * column8_row8 + (1 - cpu__decode__opcode_range_check__bit_0) * column8_row0 + column7_row0)
            {
                let val =((((/*column5_row8*/ *borrow(&ctx, 95) + /*half_offset_size*/ half_offset_size) % PRIME) + (PRIME - ((((fmul(/*cpu__decode__opcode_range_check__bit_0*/ *borrow(&ctx, 322), /*column8_row8*/ *borrow(&ctx, 217)) + fmul(((1 + (PRIME - /*cpu__decode__opcode_range_check__bit_0*/ *borrow(&ctx, 322))) % PRIME), /*column8_row0*/ *borrow(&ctx, 209))) % PRIME) + /*column7_row0*/ *borrow(&ctx, 153)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/mem0_addr: column5_row4 + half_offset_size - (cpu__decode__opcode_range_check__bit_1 * column8_row8 + (1 - cpu__decode__opcode_range_check__bit_1) * column8_row0 + column7_row8)
            {
                let val =((((/*column5_row4*/ *borrow(&ctx, 91) + /*half_offset_size*/ half_offset_size) % PRIME) + (PRIME - ((((fmul(/*cpu__decode__opcode_range_check__bit_1*/ *borrow(&ctx, 337), /*column8_row8*/ *borrow(&ctx, 217)) + fmul(((1 + (PRIME - /*cpu__decode__opcode_range_check__bit_1*/ *borrow(&ctx, 337))) % PRIME), /*column8_row0*/ *borrow(&ctx, 209))) % PRIME) + /*column7_row8*/ *borrow(&ctx, 161)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/mem1_addr: column5_row12 + half_offset_size - (cpu__decode__opcode_range_check__bit_2 * column5_row0 + cpu__decode__opcode_range_check__bit_4 * column8_row0 + cpu__decode__opcode_range_check__bit_3 * column8_row8 + cpu__decode__flag_op1_base_op0_0 * column5_row5 + column7_row4)
            {
                let val =((((/*column5_row12*/ *borrow(&ctx, 97) + /*half_offset_size*/ half_offset_size) % PRIME) + (PRIME - ((((((((fmul(/*cpu__decode__opcode_range_check__bit_2*/ *borrow(&ctx, 323), /*column5_row0*/ *borrow(&ctx, 87)) + fmul(/*cpu__decode__opcode_range_check__bit_4*/ *borrow(&ctx, 324), /*column8_row0*/ *borrow(&ctx, 209))) % PRIME) + fmul(/*cpu__decode__opcode_range_check__bit_3*/ *borrow(&ctx, 325), /*column8_row8*/ *borrow(&ctx, 217))) % PRIME) + fmul(/*cpu__decode__flag_op1_base_op0_0*/ *borrow(&ctx, 326), /*column5_row5*/ *borrow(&ctx, 92))) % PRIME) + /*column7_row4*/ *borrow(&ctx, 157)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/ops_mul: column8_row4 - column5_row5 * column5_row13
            {
                let val =((/*column8_row4*/ *borrow(&ctx, 213) + (PRIME - fmul(/*column5_row5*/ *borrow(&ctx, 92), /*column5_row13*/ *borrow(&ctx, 98)))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/res: (1 - cpu__decode__opcode_range_check__bit_9) * column8_row12 - (cpu__decode__opcode_range_check__bit_5 * (column5_row5 + column5_row13) + cpu__decode__opcode_range_check__bit_6 * column8_row4 + cpu__decode__flag_res_op1_0 * column5_row13)
            {
                let val =((fmul(((1 + (PRIME - /*cpu__decode__opcode_range_check__bit_9*/ *borrow(&ctx, 329))) % PRIME), /*column8_row12*/ *borrow(&ctx, 221)) + (PRIME - ((((fmul(/*cpu__decode__opcode_range_check__bit_5*/ *borrow(&ctx, 327), ((/*column5_row5*/ *borrow(&ctx, 92) + /*column5_row13*/ *borrow(&ctx, 98)) % PRIME)) + fmul(/*cpu__decode__opcode_range_check__bit_6*/ *borrow(&ctx, 328), /*column8_row4*/ *borrow(&ctx, 213))) % PRIME) + fmul(/*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 330), /*column5_row13*/ *borrow(&ctx, 98))) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_pc/tmp0: column8_row2 - cpu__decode__opcode_range_check__bit_9 * column5_row9
            {
                let val =((/*column8_row2*/ *borrow(&ctx, 211) + (PRIME - fmul(/*cpu__decode__opcode_range_check__bit_9*/ *borrow(&ctx, 329), /*column5_row9*/ *borrow(&ctx, 96)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 503));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_pc/tmp1: column8_row10 - column8_row2 * column8_row12
            {
                let val =((/*column8_row10*/ *borrow(&ctx, 219) + (PRIME - fmul(/*column8_row2*/ *borrow(&ctx, 211), /*column8_row12*/ *borrow(&ctx, 221)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 503));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_pc/pc_cond_negative: (1 - cpu__decode__opcode_range_check__bit_9) * column5_row16 + column8_row2 * (column5_row16 - (column5_row0 + column5_row13)) - (cpu__decode__flag_pc_update_regular_0 * npc_reg_0 + cpu__decode__opcode_range_check__bit_7 * column8_row12 + cpu__decode__opcode_range_check__bit_8 * (column5_row0 + column8_row12))
            {
                let val =((((fmul(((1 + (PRIME - /*cpu__decode__opcode_range_check__bit_9*/ *borrow(&ctx, 329))) % PRIME), /*column5_row16*/ *borrow(&ctx, 99)) + fmul(/*column8_row2*/ *borrow(&ctx, 211), ((/*column5_row16*/ *borrow(&ctx, 99) + (PRIME - ((/*column5_row0*/ *borrow(&ctx, 87) + /*column5_row13*/ *borrow(&ctx, 98)) % PRIME))) % PRIME))) % PRIME) + (PRIME - ((((fmul(/*cpu__decode__flag_pc_update_regular_0*/ *borrow(&ctx, 333), /*npc_reg_0*/ *borrow(&ctx, 338)) + fmul(/*cpu__decode__opcode_range_check__bit_7*/ *borrow(&ctx, 331), /*column8_row12*/ *borrow(&ctx, 221))) % PRIME) + fmul(/*cpu__decode__opcode_range_check__bit_8*/ *borrow(&ctx, 332), ((/*column5_row0*/ *borrow(&ctx, 87) + /*column8_row12*/ *borrow(&ctx, 221)) % PRIME))) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 503));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_pc/pc_cond_positive: (column8_row10 - cpu__decode__opcode_range_check__bit_9) * (column5_row16 - npc_reg_0)
            {
                let val =fmul(((/*column8_row10*/ *borrow(&ctx, 219) + (PRIME - /*cpu__decode__opcode_range_check__bit_9*/ *borrow(&ctx, 329))) % PRIME), ((/*column5_row16*/ *borrow(&ctx, 99) + (PRIME - /*npc_reg_0*/ *borrow(&ctx, 338))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 503));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_ap/ap_update: column8_row16 - (column8_row0 + cpu__decode__opcode_range_check__bit_10 * column8_row12 + cpu__decode__opcode_range_check__bit_11 + cpu__decode__opcode_range_check__bit_12 * 2)
            {
                let val =((/*column8_row16*/ *borrow(&ctx, 224) + (PRIME - ((((((/*column8_row0*/ *borrow(&ctx, 209) + fmul(/*cpu__decode__opcode_range_check__bit_10*/ *borrow(&ctx, 339), /*column8_row12*/ *borrow(&ctx, 221))) % PRIME) + /*cpu__decode__opcode_range_check__bit_11*/ *borrow(&ctx, 340)) % PRIME) + fmul(/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334), 2)) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 503));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_fp/fp_update: column8_row24 - (cpu__decode__fp_update_regular_0 * column8_row8 + cpu__decode__opcode_range_check__bit_13 * column5_row9 + cpu__decode__opcode_range_check__bit_12 * (column8_row0 + 2))
            {
                let val =((/*column8_row24*/ *borrow(&ctx, 229) + (PRIME - ((((fmul(/*cpu__decode__fp_update_regular_0*/ *borrow(&ctx, 336), /*column8_row8*/ *borrow(&ctx, 217)) + fmul(/*cpu__decode__opcode_range_check__bit_13*/ *borrow(&ctx, 335), /*column5_row9*/ *borrow(&ctx, 96))) % PRIME) + fmul(/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334), ((/*column8_row0*/ *borrow(&ctx, 209) + 2) % PRIME))) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 503));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/push_fp: cpu__decode__opcode_range_check__bit_12 * (column5_row9 - column8_row8)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334), ((/*column5_row9*/ *borrow(&ctx, 96) + (PRIME - /*column8_row8*/ *borrow(&ctx, 217))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/push_pc: cpu__decode__opcode_range_check__bit_12 * (column5_row5 - (column5_row0 + cpu__decode__opcode_range_check__bit_2 + 1))
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334), ((/*column5_row5*/ *borrow(&ctx, 92) + (PRIME - /*((column5_row0+cpu__decode__opcode_range_check__bit_2)+1)*/ *borrow(&ctx, 338))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/off0: cpu__decode__opcode_range_check__bit_12 * (column7_row0 - half_offset_size)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334), ((/*column7_row0*/ *borrow(&ctx, 153) + (PRIME - /*half_offset_size*/ half_offset_size)) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/off1: cpu__decode__opcode_range_check__bit_12 * (column7_row8 - (half_offset_size + 1))
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334), ((/*column7_row8*/ *borrow(&ctx, 161) + (PRIME - ((/*half_offset_size*/ half_offset_size + 1) % PRIME))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/flags: cpu__decode__opcode_range_check__bit_12 * (cpu__decode__opcode_range_check__bit_12 + cpu__decode__opcode_range_check__bit_12 + 1 + 1 - (cpu__decode__opcode_range_check__bit_0 + cpu__decode__opcode_range_check__bit_1 + 4))
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334), ((((((((/*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334) + /*cpu__decode__opcode_range_check__bit_12*/ *borrow(&ctx, 334)) % PRIME) + 1) % PRIME) + 1) % PRIME) + (PRIME - ((((/*cpu__decode__opcode_range_check__bit_0*/ *borrow(&ctx, 322) + /*cpu__decode__opcode_range_check__bit_1*/ *borrow(&ctx, 337)) % PRIME) + 4) % PRIME))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/ret/off0: cpu__decode__opcode_range_check__bit_13 * (column7_row0 + 2 - half_offset_size)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_13*/ *borrow(&ctx, 335), ((((/*column7_row0*/ *borrow(&ctx, 153) + 2) % PRIME) + (PRIME - /*half_offset_size*/ half_offset_size)) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/ret/off2: cpu__decode__opcode_range_check__bit_13 * (column7_row4 + 1 - half_offset_size)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_13*/ *borrow(&ctx, 335), ((((/*column7_row4*/ *borrow(&ctx, 157) + 1) % PRIME) + (PRIME - /*half_offset_size*/ half_offset_size)) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/ret/flags: cpu__decode__opcode_range_check__bit_13 * (cpu__decode__opcode_range_check__bit_7 + cpu__decode__opcode_range_check__bit_0 + cpu__decode__opcode_range_check__bit_3 + cpu__decode__flag_res_op1_0 - 4)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_13*/ *borrow(&ctx, 335), ((((((((/*cpu__decode__opcode_range_check__bit_7*/ *borrow(&ctx, 331) + /*cpu__decode__opcode_range_check__bit_0*/ *borrow(&ctx, 322)) % PRIME) + /*cpu__decode__opcode_range_check__bit_3*/ *borrow(&ctx, 325)) % PRIME) + /*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 330)) % PRIME) + (PRIME - 4)) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/assert_eq/assert_eq: cpu__decode__opcode_range_check__bit_14 * (column5_row9 - column8_row12)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_14*/ *borrow(&ctx, 341), ((/*column5_row9*/ *borrow(&ctx, 96) + (PRIME - /*column8_row12*/ *borrow(&ctx, 221))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for initial_ap: column8_row0 - initial_ap
            {
                let val =((/*column8_row0*/ *borrow(&ctx, 209) + (PRIME - /*initial_ap*/ initial_ap)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for initial_fp: column8_row8 - initial_ap
            {
                let val =((/*column8_row8*/ *borrow(&ctx, 217) + (PRIME - /*initial_ap*/ initial_ap)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for initial_pc: column5_row0 - initial_pc
            {
                let val =((/*column5_row0*/ *borrow(&ctx, 87) + (PRIME - /*initial_pc*/ initial_pc)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for final_ap: column8_row0 - final_ap
            {
                let val =((/*column8_row0*/ *borrow(&ctx, 209) + (PRIME - /*final_ap*/ final_ap)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 477));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for final_fp: column8_row8 - initial_ap
            {
                let val =((/*column8_row8*/ *borrow(&ctx, 217) + (PRIME - /*initial_ap*/ initial_ap)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 477));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for final_pc: column5_row0 - final_pc
            {
                let val =((/*column5_row0*/ *borrow(&ctx, 87) + (PRIME - /*final_pc*/ final_pc)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 477));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/multi_column_perm/perm/init0: (memory__multi_column_perm__perm__interaction_elm - (column6_row0 + memory__multi_column_perm__hash_interaction_elm0 * column6_row1)) * column9_inter1_row0 + column5_row0 + memory__multi_column_perm__hash_interaction_elm0 * column5_row1 - memory__multi_column_perm__perm__interaction_elm
            {
                let val =((((((fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm + (PRIME - ((/*column6_row0*/ *borrow(&ctx, 149) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column6_row1*/ *borrow(&ctx, 150))) % PRIME))) % PRIME), /*column9_inter1_row0*/ *borrow(&ctx, 314)) + /*column5_row0*/ *borrow(&ctx, 87)) % PRIME) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column5_row1*/ *borrow(&ctx, 88))) % PRIME) + (PRIME - /*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/multi_column_perm/perm/step0: (memory__multi_column_perm__perm__interaction_elm - (column6_row2 + memory__multi_column_perm__hash_interaction_elm0 * column6_row3)) * column9_inter1_row2 - (memory__multi_column_perm__perm__interaction_elm - (column5_row2 + memory__multi_column_perm__hash_interaction_elm0 * column5_row3)) * column9_inter1_row0
            {
                let val =((fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm + (PRIME - ((/*column6_row2*/ *borrow(&ctx, 151) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column6_row3*/ *borrow(&ctx, 152))) % PRIME))) % PRIME), /*column9_inter1_row2*/ *borrow(&ctx, 316)) + (PRIME - fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm + (PRIME - ((/*column5_row2*/ *borrow(&ctx, 89) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column5_row3*/ *borrow(&ctx, 90))) % PRIME))) % PRIME), /*column9_inter1_row0*/ *borrow(&ctx, 314)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 506));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 479));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/multi_column_perm/perm/last: column9_inter1_row0 - memory__multi_column_perm__perm__public_memory_prod
            {
                let val =((/*column9_inter1_row0*/ *borrow(&ctx, 314) + (PRIME - /*memory__multi_column_perm__perm__public_memory_prod*/ memory__multi_column_perm__perm__public_memory_prod)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 480));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/diff_is_bit: memory__address_diff_0 * memory__address_diff_0 - memory__address_diff_0
            {
                let val =((fmul(/*memory__address_diff_0*/ *borrow(&ctx, 342), /*memory__address_diff_0*/ *borrow(&ctx, 342)) + (PRIME - /*memory__address_diff_0*/ *borrow(&ctx, 342))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 506));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 479));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/is_func: (memory__address_diff_0 - 1) * (column6_row1 - column6_row3)
            {
                let val =fmul(((/*memory__address_diff_0*/ *borrow(&ctx, 342) + (PRIME - 1)) % PRIME), ((/*column6_row1*/ *borrow(&ctx, 150) + (PRIME - /*column6_row3*/ *borrow(&ctx, 152))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 506));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 479));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/initial_addr: column6_row0 - 1
            {
                let val =((/*column6_row0*/ *borrow(&ctx, 149) + (PRIME - 1)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for public_memory_addr_zero: column5_row2
            {
                let val =/*column5_row2*/ *borrow(&ctx, 89);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 481));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for public_memory_value_zero: column5_row3
            {
                let val =/*column5_row3*/ *borrow(&ctx, 90);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 481));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/perm/init0: (range_check16__perm__interaction_elm - column7_row2) * column9_inter1_row1 + column7_row0 - range_check16__perm__interaction_elm
            {
                let val =((((fmul(((/*range_check16__perm__interaction_elm*/ range_check16__perm__interaction_elm + (PRIME - /*column7_row2*/ *borrow(&ctx, 155))) % PRIME), /*column9_inter1_row1*/ *borrow(&ctx, 315)) + /*column7_row0*/ *borrow(&ctx, 153)) % PRIME) + (PRIME - /*range_check16__perm__interaction_elm*/ range_check16__perm__interaction_elm)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/perm/step0: (range_check16__perm__interaction_elm - column7_row6) * column9_inter1_row5 - (range_check16__perm__interaction_elm - column7_row4) * column9_inter1_row1
            {
                let val =((fmul(((/*range_check16__perm__interaction_elm*/ range_check16__perm__interaction_elm + (PRIME - /*column7_row6*/ *borrow(&ctx, 159))) % PRIME), /*column9_inter1_row5*/ *borrow(&ctx, 318)) + (PRIME - fmul(((/*range_check16__perm__interaction_elm*/ range_check16__perm__interaction_elm + (PRIME - /*column7_row4*/ *borrow(&ctx, 157))) % PRIME), /*column9_inter1_row1*/ *borrow(&ctx, 315)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 509));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 482));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/perm/last: column9_inter1_row1 - range_check16__perm__public_memory_prod
            {
                let val =((/*column9_inter1_row1*/ *borrow(&ctx, 315) + (PRIME - /*range_check16__perm__public_memory_prod*/ range_check16__perm__public_memory_prod)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 483));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/diff_is_bit: range_check16__diff_0 * range_check16__diff_0 - range_check16__diff_0
            {
                let val =((fmul(/*range_check16__diff_0*/ *borrow(&ctx, 343), /*range_check16__diff_0*/ *borrow(&ctx, 343)) + (PRIME - /*range_check16__diff_0*/ *borrow(&ctx, 343))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 509));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 482));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/minimum: column7_row2 - range_check_min
            {
                let val =((/*column7_row2*/ *borrow(&ctx, 155) + (PRIME - /*range_check_min*/ range_check_min)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/maximum: column7_row2 - range_check_max
            {
                let val =((/*column7_row2*/ *borrow(&ctx, 155) + (PRIME - /*range_check_max*/ range_check_max)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 483));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/permutation/init0: (diluted_check__permutation__interaction_elm - column7_row5) * column9_inter1_row7 + column7_row1 - diluted_check__permutation__interaction_elm
            {
                let val =((((fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm + (PRIME - /*column7_row5*/ *borrow(&ctx, 158))) % PRIME), /*column9_inter1_row7*/ *borrow(&ctx, 319)) + /*column7_row1*/ *borrow(&ctx, 154)) % PRIME) + (PRIME - /*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/permutation/step0: (diluted_check__permutation__interaction_elm - column7_row13) * column9_inter1_row15 - (diluted_check__permutation__interaction_elm - column7_row9) * column9_inter1_row7
            {
                let val =((fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm + (PRIME - /*column7_row13*/ *borrow(&ctx, 165))) % PRIME), /*column9_inter1_row15*/ *borrow(&ctx, 321)) + (PRIME - fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm + (PRIME - /*column7_row9*/ *borrow(&ctx, 162))) % PRIME), /*column9_inter1_row7*/ *borrow(&ctx, 319)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 510));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 481));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/permutation/last: column9_inter1_row7 - diluted_check__permutation__public_memory_prod
            {
                let val =((/*column9_inter1_row7*/ *borrow(&ctx, 319) + (PRIME - /*diluted_check__permutation__public_memory_prod*/ diluted_check__permutation__public_memory_prod)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 484));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/init: column9_inter1_row3 - 1
            {
                let val =((/*column9_inter1_row3*/ *borrow(&ctx, 317) + (PRIME - 1)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/first_element: column7_row5 - diluted_check__first_elm
            {
                let val =((/*column7_row5*/ *borrow(&ctx, 158) + (PRIME - /*diluted_check__first_elm*/ diluted_check__first_elm)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/step: column9_inter1_row11 - (column9_inter1_row3 * (1 + diluted_check__interaction_z * (column7_row13 - column7_row5)) + diluted_check__interaction_alpha * (column7_row13 - column7_row5) * (column7_row13 - column7_row5))
            {
                let val =((/*column9_inter1_row11*/ *borrow(&ctx, 320) + (PRIME - ((fmul(/*column9_inter1_row3*/ *borrow(&ctx, 317), ((1 + fmul(/*diluted_check__interaction_z*/ diluted_check__interaction_z, ((/*column7_row13*/ *borrow(&ctx, 165) + (PRIME - /*column7_row5*/ *borrow(&ctx, 158))) % PRIME))) % PRIME)) + fmul(fmul(/*diluted_check__interaction_alpha*/ diluted_check__interaction_alpha, ((/*column7_row13*/ *borrow(&ctx, 165) + (PRIME - /*column7_row5*/ *borrow(&ctx, 158))) % PRIME)), ((/*column7_row13*/ *borrow(&ctx, 165) + (PRIME - /*column7_row5*/ *borrow(&ctx, 158))) % PRIME))) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 510));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 481));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/last: column9_inter1_row3 - diluted_check__final_cum_val
            {
                let val =((/*column9_inter1_row3*/ *borrow(&ctx, 317) + (PRIME - /*diluted_check__final_cum_val*/ diluted_check__final_cum_val)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 484));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/last_one_is_zero: column8_row71 * (column3_row0 - (column3_row1 + column3_row1))
            {
                let val =fmul(/*column8_row71*/ *borrow(&ctx, 251), /*(column3_row0-(column3_row1+column3_row1))*/ *borrow(&ctx, 344));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones0: column8_row71 * (column3_row1 - 3138550867693340381917894711603833208051177722232017256448 * column3_row192)
            {
                let val =fmul(/*column8_row71*/ *borrow(&ctx, 251), ((/*column3_row1*/ *borrow(&ctx, 77) + (PRIME - fmul(3138550867693340381917894711603833208051177722232017256448, /*column3_row192*/ *borrow(&ctx, 78)))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit192: column8_row71 - column4_row255 * (column3_row192 - (column3_row193 + column3_row193))
            {
                let val =((/*column8_row71*/ *borrow(&ctx, 251) + (PRIME - fmul(/*column4_row255*/ *borrow(&ctx, 86), ((/*column3_row192*/ *borrow(&ctx, 78) + (PRIME - ((/*column3_row193*/ *borrow(&ctx, 79) + /*column3_row193*/ *borrow(&ctx, 79)) % PRIME))) % PRIME)))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones192: column4_row255 * (column3_row193 - 8 * column3_row196)
            {
                let val =fmul(/*column4_row255*/ *borrow(&ctx, 86), ((/*column3_row193*/ *borrow(&ctx, 79) + (PRIME - fmul(8, /*column3_row196*/ *borrow(&ctx, 80)))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit196: column4_row255 - (column3_row251 - (column3_row252 + column3_row252)) * (column3_row196 - (column3_row197 + column3_row197))
            {
                let val =((/*column4_row255*/ *borrow(&ctx, 86) + (PRIME - fmul(((/*column3_row251*/ *borrow(&ctx, 82) + (PRIME - ((/*column3_row252*/ *borrow(&ctx, 83) + /*column3_row252*/ *borrow(&ctx, 83)) % PRIME))) % PRIME), ((/*column3_row196*/ *borrow(&ctx, 80) + (PRIME - ((/*column3_row197*/ *borrow(&ctx, 81) + /*column3_row197*/ *borrow(&ctx, 81)) % PRIME))) % PRIME)))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones196: (column3_row251 - (column3_row252 + column3_row252)) * (column3_row197 - 18014398509481984 * column3_row251)
            {
                let val =fmul(((/*column3_row251*/ *borrow(&ctx, 82) + (PRIME - ((/*column3_row252*/ *borrow(&ctx, 83) + /*column3_row252*/ *borrow(&ctx, 83)) % PRIME))) % PRIME), ((/*column3_row197*/ *borrow(&ctx, 81) + (PRIME - fmul(18014398509481984, /*column3_row251*/ *borrow(&ctx, 82)))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/booleanity_test: pedersen__hash0__ec_subset_sum__bit_0 * (pedersen__hash0__ec_subset_sum__bit_0 - 1)
            {
                let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 344), ((/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 344) + (PRIME - 1)) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 512));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 474));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_extraction_end: column3_row0
            {
                let val =/*column3_row0*/ *borrow(&ctx, 76);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 487));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/zeros_tail: column3_row0
            {
                let val =/*column3_row0*/ *borrow(&ctx, 76);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 486));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/add_points/slope: pedersen__hash0__ec_subset_sum__bit_0 * (column2_row0 - pedersen__points__y) - column4_row0 * (column1_row0 - pedersen__points__x)
            {
                let val =((fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 344), ((/*column2_row0*/ *borrow(&ctx, 72) + (PRIME - /*pedersen__points__y*/ pedersen__points__y)) % PRIME)) + (PRIME - fmul(/*column4_row0*/ *borrow(&ctx, 85), ((/*column1_row0*/ *borrow(&ctx, 67) + (PRIME - /*pedersen__points__x*/ pedersen__points__x)) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 512));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 474));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/add_points/x: column4_row0 * column4_row0 - pedersen__hash0__ec_subset_sum__bit_0 * (column1_row0 + pedersen__points__x + column1_row1)
            {
                let val =((fmul(/*column4_row0*/ *borrow(&ctx, 85), /*column4_row0*/ *borrow(&ctx, 85)) + (PRIME - fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 344), ((((/*column1_row0*/ *borrow(&ctx, 67) + /*pedersen__points__x*/ pedersen__points__x) % PRIME) + /*column1_row1*/ *borrow(&ctx, 68)) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 512));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 474));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/add_points/y: pedersen__hash0__ec_subset_sum__bit_0 * (column2_row0 + column2_row1) - column4_row0 * (column1_row0 - column1_row1)
            {
                let val =((fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 344), ((/*column2_row0*/ *borrow(&ctx, 72) + /*column2_row1*/ *borrow(&ctx, 73)) % PRIME)) + (PRIME - fmul(/*column4_row0*/ *borrow(&ctx, 85), ((/*column1_row0*/ *borrow(&ctx, 67) + (PRIME - /*column1_row1*/ *borrow(&ctx, 68))) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 512));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 474));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/copy_point/x: pedersen__hash0__ec_subset_sum__bit_neg_0 * (column1_row1 - column1_row0)
            {
                let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_neg_0*/ *borrow(&ctx, 345), ((/*column1_row1*/ *borrow(&ctx, 68) + (PRIME - /*column1_row0*/ *borrow(&ctx, 67))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 512));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 474));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/copy_point/y: pedersen__hash0__ec_subset_sum__bit_neg_0 * (column2_row1 - column2_row0)
            {
                let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_neg_0*/ *borrow(&ctx, 345), ((/*column2_row1*/ *borrow(&ctx, 73) + (PRIME - /*column2_row0*/ *borrow(&ctx, 72))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 512));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 474));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/copy_point/x: column1_row256 - column1_row255
            {
                let val =((/*column1_row256*/ *borrow(&ctx, 70) + (PRIME - /*column1_row255*/ *borrow(&ctx, 69))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 448));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/copy_point/y: column2_row256 - column2_row255
            {
                let val =((/*column2_row256*/ *borrow(&ctx, 75) + (PRIME - /*column2_row255*/ *borrow(&ctx, 74))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 448));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/init/x: column1_row0 - pedersen__shift_point.x
            {
                let val =((/*column1_row0*/ *borrow(&ctx, 67) + (PRIME - /*pedersen__shift_point__x*/ pedersen__shift_point__x)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/init/y: column2_row0 - pedersen__shift_point.y
            {
                let val =((/*column2_row0*/ *borrow(&ctx, 72) + (PRIME - /*pedersen__shift_point__y*/ pedersen__shift_point__y)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/input0_value0: column5_row7 - column3_row0
            {
                let val =((/*column5_row7*/ *borrow(&ctx, 94) + (PRIME - /*column3_row0*/ *borrow(&ctx, 76))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/input0_addr: column5_row518 - (column5_row134 + 1)
            {
                let val =((/*column5_row518*/ *borrow(&ctx, 124) + (PRIME - ((/*column5_row134*/ *borrow(&ctx, 106) + 1) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 469));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/init_addr: column5_row6 - initial_pedersen_addr
            {
                let val =((/*column5_row6*/ *borrow(&ctx, 93) + (PRIME - /*initial_pedersen_addr*/ initial_pedersen_addr)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/input1_value0: column5_row263 - column3_row256
            {
                let val =((/*column5_row263*/ *borrow(&ctx, 113) + (PRIME - /*column3_row256*/ *borrow(&ctx, 84))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/input1_addr: column5_row262 - (column5_row6 + 1)
            {
                let val =((/*column5_row262*/ *borrow(&ctx, 112) + (PRIME - ((/*column5_row6*/ *borrow(&ctx, 93) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/output_value0: column5_row135 - column1_row511
            {
                let val =((/*column5_row135*/ *borrow(&ctx, 107) + (PRIME - /*column1_row511*/ *borrow(&ctx, 71))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/output_addr: column5_row134 - (column5_row262 + 1)
            {
                let val =((/*column5_row134*/ *borrow(&ctx, 106) + (PRIME - ((/*column5_row262*/ *borrow(&ctx, 112) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check_builtin/value: range_check_builtin__value7_0 - column5_row71
            {
                let val =((/*range_check_builtin__value7_0*/ *borrow(&ctx, 353) + (PRIME - /*column5_row71*/ *borrow(&ctx, 103))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check_builtin/addr_step: column5_row326 - (column5_row70 + 1)
            {
                let val =((/*column5_row326*/ *borrow(&ctx, 116) + (PRIME - ((/*column5_row70*/ *borrow(&ctx, 102) + 1) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 470));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check_builtin/init_addr: column5_row70 - initial_range_check_addr
            {
                let val =((/*column5_row70*/ *borrow(&ctx, 102) + (PRIME - /*initial_range_check_addr*/ initial_range_check_addr)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/doubling_key/slope: ecdsa__signature0__doubling_key__x_squared + ecdsa__signature0__doubling_key__x_squared + ecdsa__signature0__doubling_key__x_squared + ecdsa__sig_config.alpha - (column8_row33 + column8_row33) * column8_row35
            {
                let val =((((((((/*ecdsa__signature0__doubling_key__x_squared*/ *borrow(&ctx, 354) + /*ecdsa__signature0__doubling_key__x_squared*/ *borrow(&ctx, 354)) % PRIME) + /*ecdsa__signature0__doubling_key__x_squared*/ *borrow(&ctx, 354)) % PRIME) + /*ecdsa__sig_config__alpha*/ ecdsa__sig_config__alpha) % PRIME) + (PRIME - fmul(((/*column8_row33*/ *borrow(&ctx, 234) + /*column8_row33*/ *borrow(&ctx, 234)) % PRIME), /*column8_row35*/ *borrow(&ctx, 235)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/doubling_key/x: column8_row35 * column8_row35 - (column8_row1 + column8_row1 + column8_row65)
            {
                let val =((fmul(/*column8_row35*/ *borrow(&ctx, 235), /*column8_row35*/ *borrow(&ctx, 235)) + (PRIME - ((((/*column8_row1*/ *borrow(&ctx, 210) + /*column8_row1*/ *borrow(&ctx, 210)) % PRIME) + /*column8_row65*/ *borrow(&ctx, 249)) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/doubling_key/y: column8_row33 + column8_row97 - column8_row35 * (column8_row1 - column8_row65)
            {
                let val =((((/*column8_row33*/ *borrow(&ctx, 234) + /*column8_row97*/ *borrow(&ctx, 258)) % PRIME) + (PRIME - fmul(/*column8_row35*/ *borrow(&ctx, 235), ((/*column8_row1*/ *borrow(&ctx, 210) + (PRIME - /*column8_row65*/ *borrow(&ctx, 249))) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/booleanity_test: ecdsa__signature0__exponentiate_generator__bit_0 * (ecdsa__signature0__exponentiate_generator__bit_0 - 1)
            {
                let val =fmul(/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 355), ((/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 355) + (PRIME - 1)) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 518));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 491));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/bit_extraction_end: column8_row59
            {
                let val =/*column8_row59*/ *borrow(&ctx, 247);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 493));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/zeros_tail: column8_row59
            {
                let val =/*column8_row59*/ *borrow(&ctx, 247);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 492));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/slope: ecdsa__signature0__exponentiate_generator__bit_0 * (column8_row91 - ecdsa__generator_points__y) - column8_row123 * (column8_row27 - ecdsa__generator_points__x)
            {
                let val =((fmul(/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 355), ((/*column8_row91*/ *borrow(&ctx, 257) + (PRIME - /*ecdsa__generator_points__y*/ ecdsa__generator_points__y)) % PRIME)) + (PRIME - fmul(/*column8_row123*/ *borrow(&ctx, 264), ((/*column8_row27*/ *borrow(&ctx, 231) + (PRIME - /*ecdsa__generator_points__x*/ ecdsa__generator_points__x)) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 518));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 491));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/x: column8_row123 * column8_row123 - ecdsa__signature0__exponentiate_generator__bit_0 * (column8_row27 + ecdsa__generator_points__x + column8_row155)
            {
                let val =((fmul(/*column8_row123*/ *borrow(&ctx, 264), /*column8_row123*/ *borrow(&ctx, 264)) + (PRIME - fmul(/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 355), ((((/*column8_row27*/ *borrow(&ctx, 231) + /*ecdsa__generator_points__x*/ ecdsa__generator_points__x) % PRIME) + /*column8_row155*/ *borrow(&ctx, 265)) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 518));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 491));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/y: ecdsa__signature0__exponentiate_generator__bit_0 * (column8_row91 + column8_row219) - column8_row123 * (column8_row27 - column8_row155)
            {
                let val =((fmul(/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 355), ((/*column8_row91*/ *borrow(&ctx, 257) + /*column8_row219*/ *borrow(&ctx, 269)) % PRIME)) + (PRIME - fmul(/*column8_row123*/ *borrow(&ctx, 264), ((/*column8_row27*/ *borrow(&ctx, 231) + (PRIME - /*column8_row155*/ *borrow(&ctx, 265))) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 518));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 491));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/x_diff_inv: column8_row7 * (column8_row27 - ecdsa__generator_points__x) - 1
            {
                let val =((fmul(/*column8_row7*/ *borrow(&ctx, 216), ((/*column8_row27*/ *borrow(&ctx, 231) + (PRIME - /*ecdsa__generator_points__x*/ ecdsa__generator_points__x)) % PRIME)) + (PRIME - 1)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 518));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 491));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/copy_point/x: ecdsa__signature0__exponentiate_generator__bit_neg_0 * (column8_row155 - column8_row27)
            {
                let val =fmul(/*ecdsa__signature0__exponentiate_generator__bit_neg_0*/ *borrow(&ctx, 356), ((/*column8_row155*/ *borrow(&ctx, 265) + (PRIME - /*column8_row27*/ *borrow(&ctx, 231))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 518));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 491));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_generator/copy_point/y: ecdsa__signature0__exponentiate_generator__bit_neg_0 * (column8_row219 - column8_row91)
            {
                let val =fmul(/*ecdsa__signature0__exponentiate_generator__bit_neg_0*/ *borrow(&ctx, 356), ((/*column8_row219*/ *borrow(&ctx, 269) + (PRIME - /*column8_row91*/ *borrow(&ctx, 257))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 518));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 491));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/booleanity_test: ecdsa__signature0__exponentiate_key__bit_0 * (ecdsa__signature0__exponentiate_key__bit_0 - 1)
            {
                let val =fmul(/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 357), ((/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 357) + (PRIME - 1)) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/bit_extraction_end: column8_row9
            {
                let val =/*column8_row9*/ *borrow(&ctx, 218);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 494));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/zeros_tail: column8_row9
            {
                let val =/*column8_row9*/ *borrow(&ctx, 218);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 490));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/add_points/slope: ecdsa__signature0__exponentiate_key__bit_0 * (column8_row49 - column8_row33) - column8_row19 * (column8_row17 - column8_row1)
            {
                let val =((fmul(/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 357), ((/*column8_row49*/ *borrow(&ctx, 242) + (PRIME - /*column8_row33*/ *borrow(&ctx, 234))) % PRIME)) + (PRIME - fmul(/*column8_row19*/ *borrow(&ctx, 226), ((/*column8_row17*/ *borrow(&ctx, 225) + (PRIME - /*column8_row1*/ *borrow(&ctx, 210))) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/add_points/x: column8_row19 * column8_row19 - ecdsa__signature0__exponentiate_key__bit_0 * (column8_row17 + column8_row1 + column8_row81)
            {
                let val =((fmul(/*column8_row19*/ *borrow(&ctx, 226), /*column8_row19*/ *borrow(&ctx, 226)) + (PRIME - fmul(/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 357), ((((/*column8_row17*/ *borrow(&ctx, 225) + /*column8_row1*/ *borrow(&ctx, 210)) % PRIME) + /*column8_row81*/ *borrow(&ctx, 254)) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/add_points/y: ecdsa__signature0__exponentiate_key__bit_0 * (column8_row49 + column8_row113) - column8_row19 * (column8_row17 - column8_row81)
            {
                let val =((fmul(/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 357), ((/*column8_row49*/ *borrow(&ctx, 242) + /*column8_row113*/ *borrow(&ctx, 262)) % PRIME)) + (PRIME - fmul(/*column8_row19*/ *borrow(&ctx, 226), ((/*column8_row17*/ *borrow(&ctx, 225) + (PRIME - /*column8_row81*/ *borrow(&ctx, 254))) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/add_points/x_diff_inv: column8_row51 * (column8_row17 - column8_row1) - 1
            {
                let val =((fmul(/*column8_row51*/ *borrow(&ctx, 243), ((/*column8_row17*/ *borrow(&ctx, 225) + (PRIME - /*column8_row1*/ *borrow(&ctx, 210))) % PRIME)) + (PRIME - 1)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/copy_point/x: ecdsa__signature0__exponentiate_key__bit_neg_0 * (column8_row81 - column8_row17)
            {
                let val =fmul(/*ecdsa__signature0__exponentiate_key__bit_neg_0*/ *borrow(&ctx, 358), ((/*column8_row81*/ *borrow(&ctx, 254) + (PRIME - /*column8_row17*/ *borrow(&ctx, 225))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/exponentiate_key/copy_point/y: ecdsa__signature0__exponentiate_key__bit_neg_0 * (column8_row113 - column8_row49)
            {
                let val =fmul(/*ecdsa__signature0__exponentiate_key__bit_neg_0*/ *borrow(&ctx, 358), ((/*column8_row113*/ *borrow(&ctx, 262) + (PRIME - /*column8_row49*/ *borrow(&ctx, 242))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/init_gen/x: column8_row27 - ecdsa__sig_config.shift_point.x
            {
                let val =((/*column8_row27*/ *borrow(&ctx, 231) + (PRIME - /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/init_gen/y: column8_row91 + ecdsa__sig_config.shift_point.y
            {
                let val =((/*column8_row91*/ *borrow(&ctx, 257) + /*ecdsa__sig_config__shift_point__y*/ ecdsa__sig_config__shift_point__y) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/init_key/x: column8_row17 - ecdsa__sig_config.shift_point.x
            {
                let val =((/*column8_row17*/ *borrow(&ctx, 225) + (PRIME - /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/init_key/y: column8_row49 - ecdsa__sig_config.shift_point.y
            {
                let val =((/*column8_row49*/ *borrow(&ctx, 242) + (PRIME - /*ecdsa__sig_config__shift_point__y*/ ecdsa__sig_config__shift_point__y)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/add_results/slope: column8_row32731 - (column8_row16369 + column8_row32763 * (column8_row32667 - column8_row16337))
            {
                let val =((/*column8_row32731*/ *borrow(&ctx, 310) + (PRIME - ((/*column8_row16369*/ *borrow(&ctx, 302) + fmul(/*column8_row32763*/ *borrow(&ctx, 313), ((/*column8_row32667*/ *borrow(&ctx, 307) + (PRIME - /*column8_row16337*/ *borrow(&ctx, 297))) % PRIME))) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/add_results/x: column8_row32763 * column8_row32763 - (column8_row32667 + column8_row16337 + column8_row16385)
            {
                let val =((fmul(/*column8_row32763*/ *borrow(&ctx, 313), /*column8_row32763*/ *borrow(&ctx, 313)) + (PRIME - ((((/*column8_row32667*/ *borrow(&ctx, 307) + /*column8_row16337*/ *borrow(&ctx, 297)) % PRIME) + /*column8_row16385*/ *borrow(&ctx, 304)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/add_results/y: column8_row32731 + column8_row16417 - column8_row32763 * (column8_row32667 - column8_row16385)
            {
                let val =((((/*column8_row32731*/ *borrow(&ctx, 310) + /*column8_row16417*/ *borrow(&ctx, 305)) % PRIME) + (PRIME - fmul(/*column8_row32763*/ *borrow(&ctx, 313), ((/*column8_row32667*/ *borrow(&ctx, 307) + (PRIME - /*column8_row16385*/ *borrow(&ctx, 304))) % PRIME)))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/add_results/x_diff_inv: column8_row32647 * (column8_row32667 - column8_row16337) - 1
            {
                let val =((fmul(/*column8_row32647*/ *borrow(&ctx, 306), ((/*column8_row32667*/ *borrow(&ctx, 307) + (PRIME - /*column8_row16337*/ *borrow(&ctx, 297))) % PRIME)) + (PRIME - 1)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/extract_r/slope: column8_row32753 + ecdsa__sig_config.shift_point.y - column8_row16331 * (column8_row32721 - ecdsa__sig_config.shift_point.x)
            {
                let val =((((/*column8_row32753*/ *borrow(&ctx, 312) + /*ecdsa__sig_config__shift_point__y*/ ecdsa__sig_config__shift_point__y) % PRIME) + (PRIME - fmul(/*column8_row16331*/ *borrow(&ctx, 296), ((/*column8_row32721*/ *borrow(&ctx, 309) + (PRIME - /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x)) % PRIME)))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/extract_r/x: column8_row16331 * column8_row16331 - (column8_row32721 + ecdsa__sig_config.shift_point.x + column8_row9)
            {
                let val =((fmul(/*column8_row16331*/ *borrow(&ctx, 296), /*column8_row16331*/ *borrow(&ctx, 296)) + (PRIME - ((((/*column8_row32721*/ *borrow(&ctx, 309) + /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x) % PRIME) + /*column8_row9*/ *borrow(&ctx, 218)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/extract_r/x_diff_inv: column8_row32715 * (column8_row32721 - ecdsa__sig_config.shift_point.x) - 1
            {
                let val =((fmul(/*column8_row32715*/ *borrow(&ctx, 308), ((/*column8_row32721*/ *borrow(&ctx, 309) + (PRIME - /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x)) % PRIME)) + (PRIME - 1)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/z_nonzero: column8_row59 * column8_row16363 - 1
            {
                let val =((fmul(/*column8_row59*/ *borrow(&ctx, 247), /*column8_row16363*/ *borrow(&ctx, 301)) + (PRIME - 1)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/r_and_w_nonzero: column8_row9 * column8_row16355 - 1
            {
                let val =((fmul(/*column8_row9*/ *borrow(&ctx, 218), /*column8_row16355*/ *borrow(&ctx, 299)) + (PRIME - 1)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/q_on_curve/x_squared: column8_row32747 - column8_row1 * column8_row1
            {
                let val =((/*column8_row32747*/ *borrow(&ctx, 311) + (PRIME - /*(column8_row1*column8_row1)*/ *borrow(&ctx, 354))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/signature0/q_on_curve/on_curve: column8_row33 * column8_row33 - (column8_row1 * column8_row32747 + ecdsa__sig_config.alpha * column8_row1 + ecdsa__sig_config.beta)
            {
                let val =((fmul(/*column8_row33*/ *borrow(&ctx, 234), /*column8_row33*/ *borrow(&ctx, 234)) + (PRIME - ((((fmul(/*column8_row1*/ *borrow(&ctx, 210), /*column8_row32747*/ *borrow(&ctx, 311)) + fmul(/*ecdsa__sig_config__alpha*/ ecdsa__sig_config__alpha, /*column8_row1*/ *borrow(&ctx, 210))) % PRIME) + /*ecdsa__sig_config__beta*/ ecdsa__sig_config__beta) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/init_addr: column5_row390 - initial_ecdsa_addr
            {
                let val =((/*column5_row390*/ *borrow(&ctx, 119) + (PRIME - /*initial_ecdsa_addr*/ initial_ecdsa_addr)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/message_addr: column5_row16774 - (column5_row390 + 1)
            {
                let val =((/*column5_row16774*/ *borrow(&ctx, 145) + (PRIME - ((/*column5_row390*/ *borrow(&ctx, 119) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/pubkey_addr: column5_row33158 - (column5_row16774 + 1)
            {
                let val =((/*column5_row33158*/ *borrow(&ctx, 148) + (PRIME - ((/*column5_row16774*/ *borrow(&ctx, 145) + 1) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 471));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/message_value0: column5_row16775 - column8_row59
            {
                let val =((/*column5_row16775*/ *borrow(&ctx, 146) + (PRIME - /*column8_row59*/ *borrow(&ctx, 247))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ecdsa/pubkey_value0: column5_row391 - column8_row1
            {
                let val =((/*column5_row391*/ *borrow(&ctx, 120) + (PRIME - /*column8_row1*/ *borrow(&ctx, 210))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 495));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/init_var_pool_addr: column5_row198 - initial_bitwise_addr
            {
                let val =((/*column5_row198*/ *borrow(&ctx, 110) + (PRIME - /*initial_bitwise_addr*/ initial_bitwise_addr)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/step_var_pool_addr: column5_row454 - (column5_row198 + 1)
            {
                let val =((/*column5_row454*/ *borrow(&ctx, 123) + (PRIME - ((/*column5_row198*/ *borrow(&ctx, 110) + 1) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 454));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/x_or_y_addr: column5_row902 - (column5_row966 + 1)
            {
                let val =((/*column5_row902*/ *borrow(&ctx, 126) + (PRIME - ((/*column5_row966*/ *borrow(&ctx, 128) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 497));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/next_var_pool_addr: column5_row1222 - (column5_row902 + 1)
            {
                let val =((/*column5_row1222*/ *borrow(&ctx, 130) + (PRIME - ((/*column5_row902*/ *borrow(&ctx, 126) + 1) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 472));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 497));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/partition: bitwise__sum_var_0_0 + bitwise__sum_var_8_0 - column5_row199
            {
                let val =((((/*bitwise__sum_var_0_0*/ *borrow(&ctx, 359) + /*bitwise__sum_var_8_0*/ *borrow(&ctx, 360)) % PRIME) + (PRIME - /*column5_row199*/ *borrow(&ctx, 111))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/or_is_and_plus_xor: column5_row903 - (column5_row711 + column5_row967)
            {
                let val =((/*column5_row903*/ *borrow(&ctx, 127) + (PRIME - ((/*column5_row711*/ *borrow(&ctx, 125) + /*column5_row967*/ *borrow(&ctx, 129)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 497));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/addition_is_xor_with_and: column7_row1 + column7_row257 - (column7_row769 + column7_row513 + column7_row513)
            {
                let val =((((/*column7_row1*/ *borrow(&ctx, 154) + /*column7_row257*/ *borrow(&ctx, 192)) % PRIME) + (PRIME - ((((/*column7_row769*/ *borrow(&ctx, 203) + /*column7_row513*/ *borrow(&ctx, 197)) % PRIME) + /*column7_row513*/ *borrow(&ctx, 197)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 498));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/unique_unpacking192: (column7_row705 + column7_row961) * 16 - column7_row9
            {
                let val =((fmul(((/*column7_row705*/ *borrow(&ctx, 199) + /*column7_row961*/ *borrow(&ctx, 205)) % PRIME), 16) + (PRIME - /*column7_row9*/ *borrow(&ctx, 162))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 497));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/unique_unpacking193: (column7_row721 + column7_row977) * 16 - column7_row521
            {
                let val =((fmul(((/*column7_row721*/ *borrow(&ctx, 200) + /*column7_row977*/ *borrow(&ctx, 206)) % PRIME), 16) + (PRIME - /*column7_row521*/ *borrow(&ctx, 198))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 497));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/unique_unpacking194: (column7_row737 + column7_row993) * 16 - column7_row265
            {
                let val =((fmul(((/*column7_row737*/ *borrow(&ctx, 201) + /*column7_row993*/ *borrow(&ctx, 207)) % PRIME), 16) + (PRIME - /*column7_row265*/ *borrow(&ctx, 193))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 497));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/unique_unpacking195: (column7_row753 + column7_row1009) * 256 - column7_row777
            {
                let val =((fmul(((/*column7_row753*/ *borrow(&ctx, 202) + /*column7_row1009*/ *borrow(&ctx, 208)) % PRIME), 256) + (PRIME - /*column7_row777*/ *borrow(&ctx, 204))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 497));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/init_addr: column5_row8582 - initial_ec_op_addr
            {
                let val =((/*column5_row8582*/ *borrow(&ctx, 137) + (PRIME - /*initial_ec_op_addr*/ initial_ec_op_addr)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/p_x_addr: column5_row24966 - (column5_row8582 + 7)
            {
                let val =((/*column5_row24966*/ *borrow(&ctx, 147) + (PRIME - ((/*column5_row8582*/ *borrow(&ctx, 137) + 7) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 473));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/p_y_addr: column5_row4486 - (column5_row8582 + 1)
            {
                let val =((/*column5_row4486*/ *borrow(&ctx, 133) + (PRIME - ((/*column5_row8582*/ *borrow(&ctx, 137) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/q_x_addr: column5_row12678 - (column5_row4486 + 1)
            {
                let val =((/*column5_row12678*/ *borrow(&ctx, 141) + (PRIME - ((/*column5_row4486*/ *borrow(&ctx, 133) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/q_y_addr: column5_row2438 - (column5_row12678 + 1)
            {
                let val =((/*column5_row2438*/ *borrow(&ctx, 131) + (PRIME - ((/*column5_row12678*/ *borrow(&ctx, 141) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/m_addr: column5_row10630 - (column5_row2438 + 1)
            {
                let val =((/*column5_row10630*/ *borrow(&ctx, 139) + (PRIME - ((/*column5_row2438*/ *borrow(&ctx, 131) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/r_x_addr: column5_row6534 - (column5_row10630 + 1)
            {
                let val =((/*column5_row6534*/ *borrow(&ctx, 135) + (PRIME - ((/*column5_row10630*/ *borrow(&ctx, 139) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/r_y_addr: column5_row14726 - (column5_row6534 + 1)
            {
                let val =((/*column5_row14726*/ *borrow(&ctx, 143) + (PRIME - ((/*column5_row6534*/ *borrow(&ctx, 135) + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/doubling_q/slope: ec_op__doubling_q__x_squared_0 + ec_op__doubling_q__x_squared_0 + ec_op__doubling_q__x_squared_0 + ec_op__curve_config.alpha - (column8_row25 + column8_row25) * column8_row57
            {
                let val =((((((((/*ec_op__doubling_q__x_squared_0*/ *borrow(&ctx, 361) + /*ec_op__doubling_q__x_squared_0*/ *borrow(&ctx, 361)) % PRIME) + /*ec_op__doubling_q__x_squared_0*/ *borrow(&ctx, 361)) % PRIME) + /*ec_op__curve_config__alpha*/ ec_op__curve_config__alpha) % PRIME) + (PRIME - fmul(((/*column8_row25*/ *borrow(&ctx, 230) + /*column8_row25*/ *borrow(&ctx, 230)) % PRIME), /*column8_row57*/ *borrow(&ctx, 246)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/doubling_q/x: column8_row57 * column8_row57 - (column8_row41 + column8_row41 + column8_row105)
            {
                let val =((fmul(/*column8_row57*/ *borrow(&ctx, 246), /*column8_row57*/ *borrow(&ctx, 246)) + (PRIME - ((((/*column8_row41*/ *borrow(&ctx, 238) + /*column8_row41*/ *borrow(&ctx, 238)) % PRIME) + /*column8_row105*/ *borrow(&ctx, 260)) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/doubling_q/y: column8_row25 + column8_row89 - column8_row57 * (column8_row41 - column8_row105)
            {
                let val =((((/*column8_row25*/ *borrow(&ctx, 230) + /*column8_row89*/ *borrow(&ctx, 256)) % PRIME) + (PRIME - fmul(/*column8_row57*/ *borrow(&ctx, 246), ((/*column8_row41*/ *borrow(&ctx, 238) + (PRIME - /*column8_row105*/ *borrow(&ctx, 260))) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/get_q_x: column5_row12679 - column8_row41
            {
                let val =((/*column5_row12679*/ *borrow(&ctx, 142) + (PRIME - /*column8_row41*/ *borrow(&ctx, 238))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/get_q_y: column5_row2439 - column8_row25
            {
                let val =((/*column5_row2439*/ *borrow(&ctx, 132) + (PRIME - /*column8_row25*/ *borrow(&ctx, 230))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/bit_unpacking/last_one_is_zero: column8_row16371 * (column8_row21 - (column8_row85 + column8_row85))
            {
                let val =fmul(/*column8_row16371*/ *borrow(&ctx, 303), /*(column8_row21-(column8_row85+column8_row85))*/ *borrow(&ctx, 362));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/bit_unpacking/zeroes_between_ones0: column8_row16371 * (column8_row85 - 3138550867693340381917894711603833208051177722232017256448 * column8_row12309)
            {
                let val =fmul(/*column8_row16371*/ *borrow(&ctx, 303), ((/*column8_row85*/ *borrow(&ctx, 255) + (PRIME - fmul(3138550867693340381917894711603833208051177722232017256448, /*column8_row12309*/ *borrow(&ctx, 289)))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/bit_unpacking/cumulative_bit192: column8_row16371 - column8_row16339 * (column8_row12309 - (column8_row12373 + column8_row12373))
            {
                let val =((/*column8_row16371*/ *borrow(&ctx, 303) + (PRIME - fmul(/*column8_row16339*/ *borrow(&ctx, 298), ((/*column8_row12309*/ *borrow(&ctx, 289) + (PRIME - ((/*column8_row12373*/ *borrow(&ctx, 290) + /*column8_row12373*/ *borrow(&ctx, 290)) % PRIME))) % PRIME)))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/bit_unpacking/zeroes_between_ones192: column8_row16339 * (column8_row12373 - 8 * column8_row12565)
            {
                let val =fmul(/*column8_row16339*/ *borrow(&ctx, 298), ((/*column8_row12373*/ *borrow(&ctx, 290) + (PRIME - fmul(8, /*column8_row12565*/ *borrow(&ctx, 291)))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/bit_unpacking/cumulative_bit196: column8_row16339 - (column8_row16085 - (column8_row16149 + column8_row16149)) * (column8_row12565 - (column8_row12629 + column8_row12629))
            {
                let val =((/*column8_row16339*/ *borrow(&ctx, 298) + (PRIME - fmul(((/*column8_row16085*/ *borrow(&ctx, 293) + (PRIME - ((/*column8_row16149*/ *borrow(&ctx, 294) + /*column8_row16149*/ *borrow(&ctx, 294)) % PRIME))) % PRIME), ((/*column8_row12565*/ *borrow(&ctx, 291) + (PRIME - ((/*column8_row12629*/ *borrow(&ctx, 292) + /*column8_row12629*/ *borrow(&ctx, 292)) % PRIME))) % PRIME)))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/bit_unpacking/zeroes_between_ones196: (column8_row16085 - (column8_row16149 + column8_row16149)) * (column8_row12629 - 18014398509481984 * column8_row16085)
            {
                let val =fmul(((/*column8_row16085*/ *borrow(&ctx, 293) + (PRIME - ((/*column8_row16149*/ *borrow(&ctx, 294) + /*column8_row16149*/ *borrow(&ctx, 294)) % PRIME))) % PRIME), ((/*column8_row12629*/ *borrow(&ctx, 292) + (PRIME - fmul(18014398509481984, /*column8_row16085*/ *borrow(&ctx, 293)))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/booleanity_test: ec_op__ec_subset_sum__bit_0 * (ec_op__ec_subset_sum__bit_0 - 1)
            {
                let val =fmul(/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 362), ((/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 362) + (PRIME - 1)) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/bit_extraction_end: column8_row21
            {
                let val =/*column8_row21*/ *borrow(&ctx, 227);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 499));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/zeros_tail: column8_row21
            {
                let val =/*column8_row21*/ *borrow(&ctx, 227);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 490));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/add_points/slope: ec_op__ec_subset_sum__bit_0 * (column8_row37 - column8_row25) - column8_row11 * (column8_row5 - column8_row41)
            {
                let val =((fmul(/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 362), ((/*column8_row37*/ *borrow(&ctx, 236) + (PRIME - /*column8_row25*/ *borrow(&ctx, 230))) % PRIME)) + (PRIME - fmul(/*column8_row11*/ *borrow(&ctx, 220), ((/*column8_row5*/ *borrow(&ctx, 214) + (PRIME - /*column8_row41*/ *borrow(&ctx, 238))) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/add_points/x: column8_row11 * column8_row11 - ec_op__ec_subset_sum__bit_0 * (column8_row5 + column8_row41 + column8_row69)
            {
                let val =((fmul(/*column8_row11*/ *borrow(&ctx, 220), /*column8_row11*/ *borrow(&ctx, 220)) + (PRIME - fmul(/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 362), ((((/*column8_row5*/ *borrow(&ctx, 214) + /*column8_row41*/ *borrow(&ctx, 238)) % PRIME) + /*column8_row69*/ *borrow(&ctx, 250)) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/add_points/y: ec_op__ec_subset_sum__bit_0 * (column8_row37 + column8_row101) - column8_row11 * (column8_row5 - column8_row69)
            {
                let val =((fmul(/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 362), ((/*column8_row37*/ *borrow(&ctx, 236) + /*column8_row101*/ *borrow(&ctx, 259)) % PRIME)) + (PRIME - fmul(/*column8_row11*/ *borrow(&ctx, 220), ((/*column8_row5*/ *borrow(&ctx, 214) + (PRIME - /*column8_row69*/ *borrow(&ctx, 250))) % PRIME)))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/add_points/x_diff_inv: column8_row43 * (column8_row5 - column8_row41) - 1
            {
                let val =((fmul(/*column8_row43*/ *borrow(&ctx, 239), ((/*column8_row5*/ *borrow(&ctx, 214) + (PRIME - /*column8_row41*/ *borrow(&ctx, 238))) % PRIME)) + (PRIME - 1)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/copy_point/x: ec_op__ec_subset_sum__bit_neg_0 * (column8_row69 - column8_row5)
            {
                let val =fmul(/*ec_op__ec_subset_sum__bit_neg_0*/ *borrow(&ctx, 363), ((/*column8_row69*/ *borrow(&ctx, 250) + (PRIME - /*column8_row5*/ *borrow(&ctx, 214))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/ec_subset_sum/copy_point/y: ec_op__ec_subset_sum__bit_neg_0 * (column8_row101 - column8_row37)
            {
                let val =fmul(/*ec_op__ec_subset_sum__bit_neg_0*/ *borrow(&ctx, 363), ((/*column8_row101*/ *borrow(&ctx, 259) + (PRIME - /*column8_row37*/ *borrow(&ctx, 236))) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 516));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/get_m: column8_row21 - column5_row10631
            {
                let val =((/*column8_row21*/ *borrow(&ctx, 227) + (PRIME - /*column5_row10631*/ *borrow(&ctx, 140))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/get_p_x: column5_row8583 - column8_row5
            {
                let val =((/*column5_row8583*/ *borrow(&ctx, 138) + (PRIME - /*column8_row5*/ *borrow(&ctx, 214))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/get_p_y: column5_row4487 - column8_row37
            {
                let val =((/*column5_row4487*/ *borrow(&ctx, 134) + (PRIME - /*column8_row37*/ *borrow(&ctx, 236))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/set_r_x: column5_row6535 - column8_row16325
            {
                let val =((/*column5_row6535*/ *borrow(&ctx, 136) + (PRIME - /*column8_row16325*/ *borrow(&ctx, 295))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for ec_op/set_r_y: column5_row14727 - column8_row16357
            {
                let val =((/*column5_row14727*/ *borrow(&ctx, 144) + (PRIME - /*column8_row16357*/ *borrow(&ctx, 300))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 496));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_0/init_input_output_addr: column5_row38 - initial_poseidon_addr
            {
                let val =((/*column5_row38*/ *borrow(&ctx, 100) + (PRIME - /*initial_poseidon_addr*/ initial_poseidon_addr)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_0/addr_input_output_step: column5_row294 - (column5_row38 + 3)
            {
                let val =((/*column5_row294*/ *borrow(&ctx, 114) + (PRIME - ((/*column5_row38*/ *borrow(&ctx, 100) + 3) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 470));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_1/init_input_output_addr: column5_row166 - (initial_poseidon_addr + 1)
            {
                let val =((/*column5_row166*/ *borrow(&ctx, 108) + (PRIME - ((/*initial_poseidon_addr*/ initial_poseidon_addr + 1) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_1/addr_input_output_step: column5_row422 - (column5_row166 + 3)
            {
                let val =((/*column5_row422*/ *borrow(&ctx, 121) + (PRIME - ((/*column5_row166*/ *borrow(&ctx, 108) + 3) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 470));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_2/init_input_output_addr: column5_row102 - (initial_poseidon_addr + 2)
            {
                let val =((/*column5_row102*/ *borrow(&ctx, 104) + (PRIME - ((/*initial_poseidon_addr*/ initial_poseidon_addr + 2) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 478));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_2/addr_input_output_step: column5_row358 - (column5_row102 + 3)
            {
                let val =((/*column5_row358*/ *borrow(&ctx, 117) + (PRIME - ((/*column5_row102*/ *borrow(&ctx, 104) + 3) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 470));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 485));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_rounds_state0_squaring: column8_row53 * column8_row53 - column8_row29
            {
                let val =((fmul(/*column8_row53*/ *borrow(&ctx, 244), /*column8_row53*/ *borrow(&ctx, 244)) + (PRIME - /*column8_row29*/ *borrow(&ctx, 232))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_rounds_state1_squaring: column8_row13 * column8_row13 - column8_row61
            {
                let val =((fmul(/*column8_row13*/ *borrow(&ctx, 222), /*column8_row13*/ *borrow(&ctx, 222)) + (PRIME - /*column8_row61*/ *borrow(&ctx, 248))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_rounds_state2_squaring: column8_row45 * column8_row45 - column8_row3
            {
                let val =((fmul(/*column8_row45*/ *borrow(&ctx, 240), /*column8_row45*/ *borrow(&ctx, 240)) + (PRIME - /*column8_row3*/ *borrow(&ctx, 212))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/partial_rounds_state0_squaring: column7_row3 * column7_row3 - column7_row7
            {
                let val =((fmul(/*column7_row3*/ *borrow(&ctx, 156), /*column7_row3*/ *borrow(&ctx, 156)) + (PRIME - /*column7_row7*/ *borrow(&ctx, 160))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 481));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/partial_rounds_state1_squaring: column8_row6 * column8_row6 - column8_row14
            {
                let val =((fmul(/*column8_row6*/ *borrow(&ctx, 215), /*column8_row6*/ *borrow(&ctx, 215)) + (PRIME - /*column8_row14*/ *borrow(&ctx, 223))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 451));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/add_first_round_key0: column5_row39 + 2950795762459345168613727575620414179244544320470208355568817838579231751791 - column8_row53
            {
                let val =((((/*column5_row39*/ *borrow(&ctx, 101) + 2950795762459345168613727575620414179244544320470208355568817838579231751791) % PRIME) + (PRIME - /*column8_row53*/ *borrow(&ctx, 244))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/add_first_round_key1: column5_row167 + 1587446564224215276866294500450702039420286416111469274423465069420553242820 - column8_row13
            {
                let val =((((/*column5_row167*/ *borrow(&ctx, 109) + 1587446564224215276866294500450702039420286416111469274423465069420553242820) % PRIME) + (PRIME - /*column8_row13*/ *borrow(&ctx, 222))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/add_first_round_key2: column5_row103 + 1645965921169490687904413452218868659025437693527479459426157555728339600137 - column8_row45
            {
                let val =((((/*column5_row103*/ *borrow(&ctx, 105) + 1645965921169490687904413452218868659025437693527479459426157555728339600137) % PRIME) + (PRIME - /*column8_row45*/ *borrow(&ctx, 240))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_round0: column8_row117 - (poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state1_cubed_0 + poseidon__poseidon__full_rounds_state2_cubed_0 + poseidon__poseidon__full_round_key0)
            {
                let val =((/*column8_row117*/ *borrow(&ctx, 263) + (PRIME - ((((((((((/*poseidon__poseidon__full_rounds_state0_cubed_0*/ *borrow(&ctx, 364) + /*poseidon__poseidon__full_rounds_state0_cubed_0*/ *borrow(&ctx, 364)) % PRIME) + /*poseidon__poseidon__full_rounds_state0_cubed_0*/ *borrow(&ctx, 364)) % PRIME) + /*poseidon__poseidon__full_rounds_state1_cubed_0*/ *borrow(&ctx, 365)) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_0*/ *borrow(&ctx, 366)) % PRIME) + /*poseidon__poseidon__full_round_key0*/ poseidon__poseidon__full_round_key0) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 447));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_round1: column8_row77 + poseidon__poseidon__full_rounds_state1_cubed_0 - (poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state2_cubed_0 + poseidon__poseidon__full_round_key1)
            {
                let val =((((/*column8_row77*/ *borrow(&ctx, 253) + /*poseidon__poseidon__full_rounds_state1_cubed_0*/ *borrow(&ctx, 365)) % PRIME) + (PRIME - ((((/*poseidon__poseidon__full_rounds_state0_cubed_0*/ *borrow(&ctx, 364) + /*poseidon__poseidon__full_rounds_state2_cubed_0*/ *borrow(&ctx, 366)) % PRIME) + /*poseidon__poseidon__full_round_key1*/ poseidon__poseidon__full_round_key1) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 447));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_round2: column8_row109 + poseidon__poseidon__full_rounds_state2_cubed_0 + poseidon__poseidon__full_rounds_state2_cubed_0 - (poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state1_cubed_0 + poseidon__poseidon__full_round_key2)
            {
                let val =((((((/*column8_row109*/ *borrow(&ctx, 261) + /*poseidon__poseidon__full_rounds_state2_cubed_0*/ *borrow(&ctx, 366)) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_0*/ *borrow(&ctx, 366)) % PRIME) + (PRIME - ((((/*poseidon__poseidon__full_rounds_state0_cubed_0*/ *borrow(&ctx, 364) + /*poseidon__poseidon__full_rounds_state1_cubed_0*/ *borrow(&ctx, 365)) % PRIME) + /*poseidon__poseidon__full_round_key2*/ poseidon__poseidon__full_round_key2) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 447));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 489));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/last_full_round0: column5_row295 - (poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state1_cubed_7 + poseidon__poseidon__full_rounds_state2_cubed_7)
            {
                let val =((/*column5_row295*/ *borrow(&ctx, 115) + (PRIME - ((((((((/*poseidon__poseidon__full_rounds_state0_cubed_7*/ *borrow(&ctx, 367) + /*poseidon__poseidon__full_rounds_state0_cubed_7*/ *borrow(&ctx, 367)) % PRIME) + /*poseidon__poseidon__full_rounds_state0_cubed_7*/ *borrow(&ctx, 367)) % PRIME) + /*poseidon__poseidon__full_rounds_state1_cubed_7*/ *borrow(&ctx, 368)) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_7*/ *borrow(&ctx, 369)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/last_full_round1: column5_row423 + poseidon__poseidon__full_rounds_state1_cubed_7 - (poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state2_cubed_7)
            {
                let val =((((/*column5_row423*/ *borrow(&ctx, 122) + /*poseidon__poseidon__full_rounds_state1_cubed_7*/ *borrow(&ctx, 368)) % PRIME) + (PRIME - ((/*poseidon__poseidon__full_rounds_state0_cubed_7*/ *borrow(&ctx, 367) + /*poseidon__poseidon__full_rounds_state2_cubed_7*/ *borrow(&ctx, 369)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/last_full_round2: column5_row359 + poseidon__poseidon__full_rounds_state2_cubed_7 + poseidon__poseidon__full_rounds_state2_cubed_7 - (poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state1_cubed_7)
            {
                let val =((((((/*column5_row359*/ *borrow(&ctx, 118) + /*poseidon__poseidon__full_rounds_state2_cubed_7*/ *borrow(&ctx, 369)) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_7*/ *borrow(&ctx, 369)) % PRIME) + (PRIME - ((/*poseidon__poseidon__full_rounds_state0_cubed_7*/ *borrow(&ctx, 367) + /*poseidon__poseidon__full_rounds_state1_cubed_7*/ *borrow(&ctx, 368)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/copy_partial_rounds0_i0: column7_row491 - column8_row6
            {
                let val =((/*column7_row491*/ *borrow(&ctx, 194) + (PRIME - /*column8_row6*/ *borrow(&ctx, 215))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/copy_partial_rounds0_i1: column7_row499 - column8_row22
            {
                let val =((/*column7_row499*/ *borrow(&ctx, 195) + (PRIME - /*column8_row22*/ *borrow(&ctx, 228))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/copy_partial_rounds0_i2: column7_row507 - column8_row38
            {
                let val =((/*column7_row507*/ *borrow(&ctx, 196) + (PRIME - /*column8_row38*/ *borrow(&ctx, 237))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_full_to_partial0: column7_row3 + poseidon__poseidon__full_rounds_state2_cubed_3 + poseidon__poseidon__full_rounds_state2_cubed_3 - (poseidon__poseidon__full_rounds_state0_cubed_3 + poseidon__poseidon__full_rounds_state1_cubed_3 + 2121140748740143694053732746913428481442990369183417228688865837805149503386)
            {
                let val =((((((/*column7_row3*/ *borrow(&ctx, 156) + /*poseidon__poseidon__full_rounds_state2_cubed_3*/ *borrow(&ctx, 372)) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_3*/ *borrow(&ctx, 372)) % PRIME) + (PRIME - ((((/*poseidon__poseidon__full_rounds_state0_cubed_3*/ *borrow(&ctx, 370) + /*poseidon__poseidon__full_rounds_state1_cubed_3*/ *borrow(&ctx, 371)) % PRIME) + 2121140748740143694053732746913428481442990369183417228688865837805149503386) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_full_to_partial1: column7_row11 - (3618502788666131213697322783095070105623107215331596699973092056135872020477 * poseidon__poseidon__full_rounds_state1_cubed_3 + 10 * poseidon__poseidon__full_rounds_state2_cubed_3 + 4 * column7_row3 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state0_cubed_0 + 2006642341318481906727563724340978325665491359415674592697055778067937914672)
            {
                let val =((/*column7_row11*/ *borrow(&ctx, 163) + (PRIME - ((((((((fmul(3618502788666131213697322783095070105623107215331596699973092056135872020477, /*poseidon__poseidon__full_rounds_state1_cubed_3*/ *borrow(&ctx, 371)) + fmul(10, /*poseidon__poseidon__full_rounds_state2_cubed_3*/ *borrow(&ctx, 372))) % PRIME) + fmul(4, /*column7_row3*/ *borrow(&ctx, 156))) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state0_cubed_0*/ *borrow(&ctx, 373))) % PRIME) + 2006642341318481906727563724340978325665491359415674592697055778067937914672) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_full_to_partial2: column7_row19 - (8 * poseidon__poseidon__full_rounds_state2_cubed_3 + 4 * column7_row3 + 6 * poseidon__poseidon__partial_rounds_state0_cubed_0 + column7_row11 + column7_row11 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state0_cubed_1 + 427751140904099001132521606468025610873158555767197326325930641757709538586)
            {
                let val =((/*column7_row19*/ *borrow(&ctx, 168) + (PRIME - ((((((((((((fmul(8, /*poseidon__poseidon__full_rounds_state2_cubed_3*/ *borrow(&ctx, 372)) + fmul(4, /*column7_row3*/ *borrow(&ctx, 156))) % PRIME) + fmul(6, /*poseidon__poseidon__partial_rounds_state0_cubed_0*/ *borrow(&ctx, 373))) % PRIME) + /*column7_row11*/ *borrow(&ctx, 163)) % PRIME) + /*column7_row11*/ *borrow(&ctx, 163)) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state0_cubed_1*/ *borrow(&ctx, 374))) % PRIME) + 427751140904099001132521606468025610873158555767197326325930641757709538586) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/partial_round0: column7_row27 - (8 * poseidon__poseidon__partial_rounds_state0_cubed_0 + 4 * column7_row11 + 6 * poseidon__poseidon__partial_rounds_state0_cubed_1 + column7_row19 + column7_row19 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state0_cubed_2 + poseidon__poseidon__partial_round_key0)
            {
                let val =((/*column7_row27*/ *borrow(&ctx, 170) + (PRIME - ((((((((((((fmul(8, /*poseidon__poseidon__partial_rounds_state0_cubed_0*/ *borrow(&ctx, 373)) + fmul(4, /*column7_row11*/ *borrow(&ctx, 163))) % PRIME) + fmul(6, /*poseidon__poseidon__partial_rounds_state0_cubed_1*/ *borrow(&ctx, 374))) % PRIME) + /*column7_row19*/ *borrow(&ctx, 168)) % PRIME) + /*column7_row19*/ *borrow(&ctx, 168)) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state0_cubed_2*/ *borrow(&ctx, 375))) % PRIME) + /*poseidon__poseidon__partial_round_key0*/ poseidon__poseidon__partial_round_key0) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 452));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 481));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/partial_round1: column8_row54 - (8 * poseidon__poseidon__partial_rounds_state1_cubed_0 + 4 * column8_row22 + 6 * poseidon__poseidon__partial_rounds_state1_cubed_1 + column8_row38 + column8_row38 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state1_cubed_2 + poseidon__poseidon__partial_round_key1)
            {
                let val =((/*column8_row54*/ *borrow(&ctx, 245) + (PRIME - ((((((((((((fmul(8, /*poseidon__poseidon__partial_rounds_state1_cubed_0*/ *borrow(&ctx, 376)) + fmul(4, /*column8_row22*/ *borrow(&ctx, 228))) % PRIME) + fmul(6, /*poseidon__poseidon__partial_rounds_state1_cubed_1*/ *borrow(&ctx, 377))) % PRIME) + /*column8_row38*/ *borrow(&ctx, 237)) % PRIME) + /*column8_row38*/ *borrow(&ctx, 237)) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state1_cubed_2*/ *borrow(&ctx, 378))) % PRIME) + /*poseidon__poseidon__partial_round_key1*/ poseidon__poseidon__partial_round_key1) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 453));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 476));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_partial_to_full0: column8_row309 - (16 * poseidon__poseidon__partial_rounds_state1_cubed_19 + 8 * column8_row326 + 16 * poseidon__poseidon__partial_rounds_state1_cubed_20 + 6 * column8_row342 + poseidon__poseidon__partial_rounds_state1_cubed_21 + 560279373700919169769089400651532183647886248799764942664266404650165812023)
            {
                let val =((/*column8_row309*/ *borrow(&ctx, 276) + (PRIME - ((((((((((fmul(16, /*poseidon__poseidon__partial_rounds_state1_cubed_19*/ *borrow(&ctx, 379)) + fmul(8, /*column8_row326*/ *borrow(&ctx, 279))) % PRIME) + fmul(16, /*poseidon__poseidon__partial_rounds_state1_cubed_20*/ *borrow(&ctx, 380))) % PRIME) + fmul(6, /*column8_row342*/ *borrow(&ctx, 281))) % PRIME) + /*poseidon__poseidon__partial_rounds_state1_cubed_21*/ *borrow(&ctx, 381)) % PRIME) + 560279373700919169769089400651532183647886248799764942664266404650165812023) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_partial_to_full1: column8_row269 - (4 * poseidon__poseidon__partial_rounds_state1_cubed_20 + column8_row342 + column8_row342 + poseidon__poseidon__partial_rounds_state1_cubed_21 + 1401754474293352309994371631695783042590401941592571735921592823982231996415)
            {
                let val =((/*column8_row269*/ *borrow(&ctx, 274) + (PRIME - ((((((((fmul(4, /*poseidon__poseidon__partial_rounds_state1_cubed_20*/ *borrow(&ctx, 380)) + /*column8_row342*/ *borrow(&ctx, 281)) % PRIME) + /*column8_row342*/ *borrow(&ctx, 281)) % PRIME) + /*poseidon__poseidon__partial_rounds_state1_cubed_21*/ *borrow(&ctx, 381)) % PRIME) + 1401754474293352309994371631695783042590401941592571735921592823982231996415) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_partial_to_full2: column8_row301 - (8 * poseidon__poseidon__partial_rounds_state1_cubed_19 + 4 * column8_row326 + 6 * poseidon__poseidon__partial_rounds_state1_cubed_20 + column8_row342 + column8_row342 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state1_cubed_21 + 1246177936547655338400308396717835700699368047388302793172818304164989556526)
            {
                let val =((/*column8_row301*/ *borrow(&ctx, 275) + (PRIME - ((((((((((((fmul(8, /*poseidon__poseidon__partial_rounds_state1_cubed_19*/ *borrow(&ctx, 379)) + fmul(4, /*column8_row326*/ *borrow(&ctx, 279))) % PRIME) + fmul(6, /*poseidon__poseidon__partial_rounds_state1_cubed_20*/ *borrow(&ctx, 380))) % PRIME) + /*column8_row342*/ *borrow(&ctx, 281)) % PRIME) + /*column8_row342*/ *borrow(&ctx, 281)) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state1_cubed_21*/ *borrow(&ctx, 381))) % PRIME) + 1246177936547655338400308396717835700699368047388302793172818304164989556526) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 488));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

        };
        res
    }

    #[test]
    fun test_fallback() {
        let ctx: vector<u256> = vector[
            448893933714983651254026328822380289147025478770042347723704114845659030101,
            2642494279642232232962611145163464145219765114453340323607461598386282796045,
            1784684692308597838526962595444656712340031409494565856436324101259282408010,
            211994987640757267158803568479900821579206516038931311649588141335871484717,
            1390159518751441967435313968527396985923038844785204457618064117748036187765,
            1555080581019560094302321870902270531327689980572559209527620746367894386618,
            569579038475898966452154337684925764851336918976701059460465935494708369361,
            1701708339916311773381215006599230984223017232996469441826047918637221410742,
            3401479903986665934286641489992207047274492079969382987539690348682559310231,
            2097152,
            65536,
            32768,
            731,
            1,
            2115,
            5,
            380363825616489357312203008388378685760169152665837432018297029608498465756,
            1549145168165173220040350885610997168399341064111108246336441153947168333508,
            1383182562295496733403626563206829469833021061405962093847241449217790397645,
            2750110380067743423557850088912195303540921282240736572328660741834505559036,
            1,
            0,
            32796,
            2781442066600553197484775829159443071082670931702739716515473413498154211723,
            1,
            0,
            2915684684325943429861460914050764753086912937538776538448668567666662727190,
            3424737268247368323349883463438010202791623275818581956045183135674968381150,
            1429878038888886386230981544356342585936603898518210246662136852379057895795,
            2089986280348253421170679821480865132823066470938446095505822317253594081284,
            1713931329540660377023406109199410414810705867260802078187082345529207694986,
            2122,
            14410,
            1,
            2089986280348253421170679821480865132823066470938446095505822317253594081284,
            1713931329540660377023406109199410414810705867260802078187082345529207694986,
            3141592653589793238462643383279502884197169399375105820974944592307816406665,
            22602,
            22730,
            32970,
            1,
            33866,
            884767640635888335079619399138397816824468332068211437205303391566300183736,
            2121279549955046749412990564602598069750399907565215606373337541873041914543,
            380363825616489357312203008388378685760169152665837432018297029608498465756,
            1549145168165173220040350885610997168399341064111108246336441153947168333508,
            2750110380067743423557850088912195303540921282240736572328660741834505559036,
            2781442066600553197484775829159443071082670931702739716515473413498154211723,
            2915684684325943429861460914050764753086912937538776538448668567666662727190,
            3424737268247368323349883463438010202791623275818581956045183135674968381150,
            2929707851975936714003064445723343255584021698327411607527938356857391359500,
            379271585456812121937051587286039818159759890451182675133871376475040595228,
            2186462305695043360215575560456464372519857839058670923868888916085558154677,
            811607264105721734972525555892062304815093035105070978201668787209048198023,
            3252305674062547507081774215218781977617257382272297078076033656677424993317,
            15085038486354410871853397101405829418574837253953263534848801719804900584,
            415666449186669902192266895607395596386921056221186594006268096874093972384,
            990478843962748085154098380782483160236405322881261392254769769502853675778,
            1379217990689172203713334054464326158718151685472203988292813507667015389512,
            219373597567732418287028785037149112408196354166431473305351795043376866901,
            1406918655628496249054068513206523228150011910363085300049619720891706302531,
            1513822267824545702869443825315946589347568999366949496291944554799185435042,
            2373899576211622534421211814141931092678096670408875298445758688913110613646,
            2527905096963904697314508290762439668440377261724135464956148694603241159688,
            2923796768177645240982565937831515603717954417214597761358194228232815824745,
            615740021455641764962044299734956045546922842194207477862611881270136211934,
            2098543937362900587544043554274712594902953877351672152336201521006898895917,
            521686085861003585409571043257406059947464968348437109731956520455938486954,
            2321552365517805854078394052857448421960312427942109490647227140019323183859,
            37499175642126434121034786707678278433271733436516511618943895202397294285,
            1814870998096133926762250251239868665413495475154853347177273880678798935446,
            893197525169319981328325133657372249216684257044672697945751107691647293723,
            3286186856912116806382483428747346016129574100226564397345606027021217300742,
            1951957895927859788317120654464152649024705435085964345847563026544665452947,
            1698799765768835133180952747608183779375324863469061071686292147784525810489,
            2010118177882614105964489584650399220755923119094531003261945572732513866076,
            1945351860057288929577430765992681404642077247225035952804423627825019946313,
            1096083228437337374964890704335164895966799334322528612441394601715952509855,
            2030872422074096198401481252263545666745378831907383624102216351682480126117,
            382081561275490109780724990633642750428601382023890858364547873773438386846,
            450729452282763659839903825270090950363910969595689471088979906250964408240,
            2424304076361067431227354424703408637290081003828018027144644671035423049752,
            1549658798106619640071758012792237116577690908691529582032700261337159698543,
            3544711156720419905052647495613851228118642030407209744715614662120325455789,
            644742325162507549418790937396236588765155888278647678955471362972140021737,
            3260423660584692751090883424011322669033856255200718259349378618153117710429,
            3456536988888574252925229066641240545286983797135415174490721529524817939264,
            69079223144706149284081069438690652701300131268334673169482800908912040724,
            2568682852886864161307654579839849023188934783044898230045663881414687625990,
            3378702100674496983242249735977371309247972716367212239002235081523992614571,
            1751150751738562169511675704180277263301820848322165493728934935355035378452,
            756836399490160393202665291053766532342234468354407782739608448007528868661,
            1539997515970310553162956380432134205420977770997355029160998016189082913582,
            58152389776753508370764417856876515556358008987948298801915775786371564188,
            2386757632810271024761856245510007138446204982867296661299683246298469601906,
            468140268046961046604912374744784210169198878168779438290506783183804310387,
            226122886539146541472890786019727023269842120115431419914678919663609515980,
            1183962314915958369862601541586166260435919063240660821111955134982586142544,
            805400757117196064410096003943097314876134468927352594160306109435539333842,
            515260211447228679720890515763262952202757111596205544948256337371046190553,
            1024980548737630891327174043315549389737613181143949990071766211967484341748,
            818429284044469397230503933984668281559729658833634584636553255408003077042,
            2448719118389526868209686203503049302723462371612624625279309313343823685028,
            1439249179157168807833829141915814395594499962323713165631860260497050196719,
            2944766253116286920716712099128148493358511406524093878563796312569034510452,
            135431813054306848545563540806912354454572535353214109549560632341667939821,
            756674904409250872099282089124101121100150452559991744752636688331153936517,
            63963957954257182989414778291148152150464417393304770806676865533121633930,
            1918308314388760477431263995624508324743509760847348730708654843528259917192,
            2617145493557033967772048017510676637700247327677908218064881807853334855220,
            1241845375499653583605858058734127647339645729817354850352168373504412721245,
            3330309266060073201806352508496412893508095812393282271903139343979834409274,
            1946117207953806424630388944405899963990396252125080206128480580654484172356,
            1158197026081595270656857012428702270276923212435394525661921865393763724634,
            1618123723068950411693116441435475551515560773741125967915872420600806055143,
            1680595040207462495192970369891666807426972211540966506770428088230619181279,
            1836157409010661970359461389464328260712346784696931839482482757778917059846,
            2259432343761099038853365566555597912644568804653430721698249025435981873742,
            24556723759432090491977107925564865163826238356910848135428331247862473716,
            1283689860527620340453362079453991729634849613705393345913753006315653033294,
            2552705057640709669415465550293274479103707297365049007207519146680128842127,
            2994830808208656065101146382080043372319171875249795882116699271217110452802,
            1320151671974427922214341346699658574545019380270954193318000212044936283777,
            328546065659042787734450325024901364149983584393209498277932311852938149980,
            229253844770440962914431488838350295868157676141248030884804119986199573688,
            691317294923035174132241694022033915815392230342867895731234180499461312360,
            2632874045949153402733977530132392594963654333272997026910797074558855260725,
            1074509403084901480513772211528163088369573090282447510227830353052043581375,
            1812711280069355320327846499329160986279251977060590455027403693226381153292,
            305789348395744785249756986325338579342080498242274825179101117763443148755,
            3481340853128621935882647747757610623026606930948694298966165805308136006950,
            2044368427753448328230442789351587454748252142223207664736963517617014277003,
            2952965005315810363378638969189072403275688304608231658550972187304982930517,
            2022107484707586536068787868466379421055708385865804249642619113487202002971,
            2111879500556750387084258145985496698624827709154598228103186606162562898120,
            2043625451745314351361459994561479800338302403378968078997515889502368874087,
            1172044780146339039316498554453122866308397138794611206569891323119718789965,
            2661042090305734345098871864059035726322614604145879805520581170597677604073,
            1994531653706229332336996390090349473345510710941185909965253642439661580480,
            226316250846302986940246978856231034974469536192124363574495043183775375430,
            1289974133482093568974405672852538914694185076685868209263783625769030950567,
            316152484210089686922840137607381594591720344595189620229606126928681047658,
            1353377987055061806365280816158446571533321770779368713733581656972505989781,
            389083911154304497356949982714188010549029879141568515984926291352643914719,
            1253638659530239447566087257687983499802006031846332294627164096275256487632,
            2161984870369162381603742377152588499511802430933290952134450732637682470181,
            21314554163412667907487811430755631872422523719065683424177366830243456049,
            2861177911694539416322263408280533041301266118168135364510436226676062002386,
            864453467323516828130921631533388931913331300529773052168526402258666331376,
            2771495722570401499690928699769402984679985266855982399238904168139383172950,
            3390994355635076388169444752658038692770315012745773919152887463093904182696,
            2629103092352196357151215080755879018424930391257034301229751124052472029747,
            210106867557960662779990651828652850988179009113649668387772153477429141801,
            2839460402502436082522689302361744543659363598912508098822604418324208396191,
            3361059631952311335291331720347586228435111941915870567529548042065701606524,
            1626151762979164447009562776841942514478083657915291217636964244110351198516,
            1401940154936776694539099022255377330497618572250065656361290261941859398181,
            702737392279447193134607223627404804320583784194744686709734419060181272667,
            1935943777015208539297707415683985881324119458420292181830790386432694401626,
            878925994799694671520685438835000556055492956840204398821113249451096912177,
            885861033976525226902339246375288685073042112593605130118185699350749879205,
            2348798325461405130391462288739308106372272159061910681917267683651115056602,
            338913627806282289899861390090918676230900739356344130294676461707716650138,
            2017808606717061475766040513478520794451366657095567555831419584758128628489,
            1097701392415182282288807610079437369920691793627519374658550023687424648365,
            589527789463386707536394331890597932949548398427404754517895524753066492561,
            304014621100237655864499288232771968909393577050999796836482786389271479822,
            2944376311254428483643587777071535773900153413765397281839999458414341150336,
            651208711053254838095244151644141535761886511122279893827630256534939087423,
            2133315325920884835471520129123111004514345662042598462319954337489555277624,
            2670149575792040836607799592166084471205933412418871526004934185408658776550,
            3470544507704055958796423656535018425763733737407397358741910653165118601316,
            3295234860436322704830238117985514159631790863849623386695502304896680144014,
            1658835607278103913161171512537590196101993616011456869357878977736966462592,
            2929687841655210634184810889169174395027503496969702171898758767390163692609,
            347066894349626557689280519532875192202346413966431984190788624864212666884,
            2248861454894955288043008183420514208604396934012347038645065798496886600486,
            2472545739459550202229322104866697884137977690831868397238506166950833154988,
            1795538516589660162556753650762751131340010620284917551676481838824763764543,
            1676208256828851885995121693559687878885145245564451244741775805996229731834,
            2666154733496309819904279134220182772149492171589122411198554132304804568862,
            36298527974122869382783506177357696426006457072822620730437297253573714400,
            942481122436804232145691055830046715406082188357904173476676100188497875756,
            1629802347359880146998310593921753375319934515302102120609857300686771513117,
            689171813814613876906453981309712492131783048469880957537197753647881970041,
            1661531209012226241610088414314758730609623038562860419297611840469833866016,
            342545322846376029826078918142333900058919032022160942987507633185844158286,
            3094768225729033515196907882081715657762098850832800541582879225472027434240,
            1546856061050465102742387528573708869425662285280645742030050174997740789391,
            2893100485746361240271206407702055624674638858165521038167839030469112820758,
            2382059029061702136599422085482810326964922312120937006518894807263163895126,
            2372341071803329810715564164829265323492936602606942041274574280050162791463,
            936274422084703446929423190935337967369306348539112378216663054685498921632,
            1258184540963100095654525037979022378763221502055295302562973635097965733498,
            1543728765745059519681415359184918184340321712362501918887867467655168156141,
            175024043049585390389738116446149888149720282484796840986293549437974575856,
            2675942181516019849160141684342129363688604160879653231921591003743387194571,
            2856756767634426969874607786596959123453269881343611833484124053174420954838,
            545527631903417605152548321267846811791183245578053151656640643630942675801,
            288330436449483044169946247114637659324643884863275650462958054968099159712,
            3032823623815617486776934956175377434716855750105562967234926289628616128462,
            2257733536635170988280163655143887926892307450355240246510922045057930787407,
            2746554740918665086468485369468161976487077566839379221535697332318832432137,
            966635514985248160849772804217695548757135685591246002491381811229853932449,
            1733946783425073545253711392729785174079045255133469799052351024140974142121,
            3397649141120210906849866934348634953112677612741860746932019021447962990899,
            2214068010675065223376795782721419460094070252526421788371781274919067796271,
            3452363819410273046845566882388169736810887053759837975226786258624057803839,
            1649920251314543650721149960153958577636835129120067949673230682688325936011,
            2640920518011402225253473877157458974632676097221874439632501445064685563725,
            1600647403189953911243219831497132953775944206504763990096547680260753539904,
            1357513476682798366391704210821674087984938513614388202960496620166541809377,
            1063954880403175193533473108162723501145808764940555145596052665949027116419,
            1429334407333326360397805784854618327478310862626846059715801293504186895510,
            2476458450650842279570328316660338368829298560224561495801259819380801170473,
            2510638823222659816956414186046160444063927264657518728160282920610322892225,
            1719472559110625561342179186987030872558386691520489467127378473347247792618,
            359099159857058523168749835052608378841882704191068063315589920502923670205,
            2476548206092698621771793016041947537127056802439632395537967648338513080532,
            23513948534939661782035622773153832838873110286002672074418199645528517075,
            1542835205686813325968248155612043893643831687021357363395632282281398880235,
            585157730415187567632549052701728799312971637137498261170789039262205050837,
            1322280557553067257157223956983599470701178278273407143437880071171321496193,
            3522961061611370030437859948968830698507091366015913109846677541708617659487,
            3492758853698239006614629725662194057247259146537342036674543416507544593179,
            3218884730569630600114091643409694059367958704909899787884822499737463874395,
            3328919485625880490559221986076606086634943548775694423166926742747645935616,
            1850470904515954441454123870762174480308867034146677481674536323116450903000,
            14550625109941929762680369402508154480278683951467190799679071977609704008,
            812198558372698158669930375933787037309506493921868598494138886806995991609,
            2527092335278682123113853061728586847604893175161115901584020401503024408582,
            2846165733149824054310247941138517776376379456958334748127532885074287952174,
            2137533284257627850503780481931444867305032705012173695174594563727097681433,
            1265817479601840993142280480581646759721681285859080783206359900735764164926,
            2789136998118432008440916297468227203036677698661162987578494530500007596979,
            275133691087464142252191335793143663219412480983199659329826246651810651071,
            1102977027335275615826560887843924111604495193618378313895607954573899803237,
            2473326004466268977517428671074248246920172800560107045545898299897413850248,
            2768588923544245600078797396366815589306595063035056888681698629303713349885,
            1618933502964465684889854100236069328574517347500756292071758009723629042217,
            1775602250368228044518380762586786329753917846142007434302347714482066845717,
            2180676912390781204576872930191097108834639928606461663261500650817425444269,
            1002694567781533026687285545249141937941098813131442796428648474516579924188,
            2630168070979540047926357256707360090157887393551561152714632772859561384908,
            1267671804100147902837396865074582664799085202565907810327624477477400470404,
            706763734966941521495751171515111487211598836284762107898854056407048879874,
            391944271666651066748921889287803735277897351435978796705572074249532118434,
            3148545442152868726553688034221336674816611354845901855284218780773232224327,
            440461422658123531146543942243540932883454163656867982435578542365496312489,
            845943468978963978839997885899305496227758755156492176376043774584698676891,
            1667275182245671004354602025488454384072565235887196935838538944819900651364,
            1473597125245323651298207941134886469903535839234704788413225922685381250614,
            3238964248785748260142806305528232212064334271014180098172224059598992434827,
            873782023768637642047527794300123880985390914537675137109242050550743487203,
            707728020917417026207155862043132875642042250396505015106886571978195448846,
            1530342900567084689172337623527125365630220581199425506872292972362102207328,
            730830733437545244957826614734344066439379049032234327913083038032877637870,
            2179833763999043557171996120860683353327571666562610911147486526646953320436,
            458948912366552869699871065426421567520257465817499346685747882042731666210,
            2234885962041530301853130501339422088904919144410190340074724557568250092310,
            1449150003246277696206000630753164083470987361223631085245389968694351432204,
            3531548464721726793273625565674221017659039590462833762032050967238741980499,
            1864676423348679542129160104965320204605872128272221993921443219996054452781,
            1194979453625867838624821938505996867224352612234415152691209793564887333122,
            1763989181442565825054645084177720442182665526493287746520840061722457615883,
            2364951057486286099812679859848405413934908707274132702209993443811504564267,
            3314811005076847278268705192617128517531064897255138819138205270126861362805,
            881936007231970149517828360367670731984532843845681763312044399404150929038,
            321668454027844841937647270704364977253795338152445577794235079666548336436,
            3004765204311844273076027100089995310893372012597062466602451244952492259408,
            459783523503714185747072407633481657238060062031872896691795347628291119696,
            2754437648794001580721573563833787856850236103220299542391312223870444400773,
            1914588359355274977084032297694535149206268737488235761277494166112696084533,
            1058180051446179878161777047912883168268425469075152670625272917034706724573,
            147256981836452818034411518062201461997995319288451996153397407940577893732,
            330555940802022821614685771676814065335322707621827900647642362048812358597,
            879927874238304298241843534468539989807959513004689982792150227776724548945,
            631816807615967510974411722625095807120954970742941033248478515570257045728,
            2639413607152479807623191641594769963187796903243586720524822202932297949266,
            3580119683368180643496383816052989785479293789031746175199821987000445601741,
            814809762814153305854855157116636638631649516358300507004712793065534039301,
            1387124104179687860400407939061819306144976819085619302730271847492045797224,
            1360474414258533350616864767424218043037065592164915748219896904200428968632,
            2826141556388609268535312128691353958632448731055267268776944321626353581423,
            3316325968666964446030882240355740135418705860103080376057913364796077117,
            2492496845418936886982149997984858027002138291438844573592330415420340411582,
            1558991743022743341179912865724522595891105300517226356462065884933410126764,
            2013953277070043699818818774434183388932780666018625756927565156951388563827,
            2909022307628767197500663199076504089448984230998059142482546399249873904885,
            554852240639064547665720393403903639333024666961252821475963565192206551058,
            1578023583371336266411688637694854870879888989312214923759105379000175693801,
            515654026882190953273029864416716472110448727060891585692107067684674693878,
            2340778636872651641324102070503405683076230119464208867088693878547773902812,
            199604013070606267892076407236374163655387867034576290089822116091832109077,
            2433212841646641796539812340923290217101776800069285976739940636807123728647,
            3242068596312391090696245299831624882126722295147658342857372290682898705966,
            1965887289804230735407689575050870863242548690751726307433555798659849874751,
            239243900616025614650380594638146309229602690934803459430900331542832573352,
            1211950080938027251096197232133941798630893826522036070573173522083828552084,
            2677948316276889262388418804522831057762521072796015066965056253681485647820,
            2137334592413411858195482485436021216536316001966381939793702798130463290485,
            1717318569226522504937159962972274348697045162800663417597674443987294124959,
            230750354752577209424672442523685490354458748422435558962435295872727547585,
            2536584267308394345563180685554172260963158152367393409614277396685857753397,
            769333469584235225286194054663473142012270706617176785777171979533188333214,
            1840744048624105910643219898045720983721578678497332183620210608870771520428,
            1841468163899786031326478332778390379437790825175417193342722484846779021254,
            2067495670976205098764660180349761956048670396529357275034251308004251812337,
            2626029273709025986737972716837368602804873056382736239609387606052064777483,
            35662983904324473556784321433742355673919459609991497869064947581573605213,
            939264815538636404868613581007660018292525309738904680704194264712457416182,
            3484574930961736989664942188883108092438748751949346381905457844186350207426,
            3580048882468394033937551852372878823136190873819763988833294012611256758963,
            535130915424476150448515718641550596663199412470635261848163955898521604708,
            2271584321127153837246825077589892035121713046033950436032204804949113174510,
            1953647702596059347974005781581482230410119794405549371984139599906493378562,
            3251132224526161045054163551524576883198931297397291595900475295243123590544,
            2994767088600299178846560015186263018483469415333576300586300606044707289913,
            669936668101485812454615745803638645034347930248784595325126930169754482407,
            479252663440310072350536361921773284814713879396442819498583155224533830404,
            2772149549831446861522530106296178020106039525341670490796071445598026090535,
            1168095051658602970512479413689565228133059840972106807001703195332031377312
        ];
        // assert!(vector::length(&ctx) == 322, 1);
        assert!(fallback(ctx) == 0x05e8d33e084cfc2c21b89b4dac503f8cfedf475f16f6f9c3a8686b860bfbbbd9, 1);
    }
}