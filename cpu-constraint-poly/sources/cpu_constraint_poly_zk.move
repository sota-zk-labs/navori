module cpu_addr::cpu_constraint_poly {

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


    public fun fallback(ctx: &vector<u256>): u256 {
        let ctx = *ctx;
        let res = 0;

        let remain = 598 - vector::length(&ctx);

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
        let trace_generator = *borrow(&ctx, 42);
        let oods_point = *borrow(&ctx, 43);
        let interaction_elements = *borrow(&ctx, 44);
        let composition_alpha = *borrow(&ctx, 50);
        let oods_values = *borrow(&ctx, 51);
        let cpu__decode__opcode_range_check__bit_0 = *borrow(&ctx, 322);
        let cpu__decode__opcode_range_check__bit_2 = *borrow(&ctx, 323);
        let cpu__decode__opcode_range_check__bit_4 = *borrow(&ctx, 324);
        let cpu__decode__opcode_range_check__bit_3 = *borrow(&ctx, 325);
        let cpu__decode__flag_op1_base_op0_0 = *borrow(&ctx, 326);
        let cpu__decode__opcode_range_check__bit_5 = *borrow(&ctx, 327);
        let cpu__decode__opcode_range_check__bit_6 = *borrow(&ctx, 328);
        let cpu__decode__opcode_range_check__bit_9 = *borrow(&ctx, 329);
        let cpu__decode__flag_res_op1_0 = *borrow(&ctx, 330);
        let cpu__decode__opcode_range_check__bit_7 = *borrow(&ctx, 331);
        let cpu__decode__opcode_range_check__bit_8 = *borrow(&ctx, 332);
        let cpu__decode__flag_pc_update_regular_0 = *borrow(&ctx, 333);
        let cpu__decode__opcode_range_check__bit_12 = *borrow(&ctx, 334);
        let cpu__decode__opcode_range_check__bit_13 = *borrow(&ctx, 335);
        let cpu__decode__fp_update_regular_0 = *borrow(&ctx, 336);
        let cpu__decode__opcode_range_check__bit_1 = *borrow(&ctx, 337);
        let npc_reg_0 = *borrow(&ctx, 338);
        let cpu__decode__opcode_range_check__bit_10 = *borrow(&ctx, 339);
        let cpu__decode__opcode_range_check__bit_11 = *borrow(&ctx, 340);
        let cpu__decode__opcode_range_check__bit_14 = *borrow(&ctx, 341);
        let memory__address_diff_0 = *borrow(&ctx, 342);
        let range_check16__diff_0 = *borrow(&ctx, 343);
        let pedersen__hash0__ec_subset_sum__bit_0 = *borrow(&ctx, 344);
        let pedersen__hash0__ec_subset_sum__bit_neg_0 = *borrow(&ctx, 345);
        let range_check_builtin__value0_0 = *borrow(&ctx, 346);
        let range_check_builtin__value1_0 = *borrow(&ctx, 347);
        let range_check_builtin__value2_0 = *borrow(&ctx, 348);
        let range_check_builtin__value3_0 = *borrow(&ctx, 349);
        let range_check_builtin__value4_0 = *borrow(&ctx, 350);
        let range_check_builtin__value5_0 = *borrow(&ctx, 351);
        let range_check_builtin__value6_0 = *borrow(&ctx, 352);
        let range_check_builtin__value7_0 = *borrow(&ctx, 353);
        let ecdsa__signature0__doubling_key__x_squared = *borrow(&ctx, 354);
        let ecdsa__signature0__exponentiate_generator__bit_0 = *borrow(&ctx, 355);
        let ecdsa__signature0__exponentiate_generator__bit_neg_0 = *borrow(&ctx, 356);
        let ecdsa__signature0__exponentiate_key__bit_0 = *borrow(&ctx, 357);
        let ecdsa__signature0__exponentiate_key__bit_neg_0 = *borrow(&ctx, 358);
        let bitwise__sum_var_0_0 = *borrow(&ctx, 359);
        let bitwise__sum_var_8_0 = *borrow(&ctx, 360);
        let ec_op__doubling_q__x_squared_0 = *borrow(&ctx, 361);
        let ec_op__ec_subset_sum__bit_0 = *borrow(&ctx, 362);
        let ec_op__ec_subset_sum__bit_neg_0 = *borrow(&ctx, 363);
        let poseidon__poseidon__full_rounds_state0_cubed_0 = *borrow(&ctx, 364);
        let poseidon__poseidon__full_rounds_state1_cubed_0 = *borrow(&ctx, 365);
        let poseidon__poseidon__full_rounds_state2_cubed_0 = *borrow(&ctx, 366);
        let poseidon__poseidon__full_rounds_state0_cubed_7 = *borrow(&ctx, 367);
        let poseidon__poseidon__full_rounds_state1_cubed_7 = *borrow(&ctx, 368);
        let poseidon__poseidon__full_rounds_state2_cubed_7 = *borrow(&ctx, 369);
        let poseidon__poseidon__full_rounds_state0_cubed_3 = *borrow(&ctx, 370);
        let poseidon__poseidon__full_rounds_state1_cubed_3 = *borrow(&ctx, 371);
        let poseidon__poseidon__full_rounds_state2_cubed_3 = *borrow(&ctx, 372);
        let poseidon__poseidon__partial_rounds_state0_cubed_0 = *borrow(&ctx, 373);
        let poseidon__poseidon__partial_rounds_state0_cubed_1 = *borrow(&ctx, 374);
        let poseidon__poseidon__partial_rounds_state0_cubed_2 = *borrow(&ctx, 375);
        let poseidon__poseidon__partial_rounds_state1_cubed_0 = *borrow(&ctx, 376);
        let poseidon__poseidon__partial_rounds_state1_cubed_1 = *borrow(&ctx, 377);
        let poseidon__poseidon__partial_rounds_state1_cubed_2 = *borrow(&ctx, 378);
        let poseidon__poseidon__partial_rounds_state1_cubed_19 = *borrow(&ctx, 379);
        let poseidon__poseidon__partial_rounds_state1_cubed_20 = *borrow(&ctx, 380);
        let poseidon__poseidon__partial_rounds_state1_cubed_21 = *borrow(&ctx, 381);
        let expmods = *borrow(&ctx, 382);
        let domains = *borrow(&ctx, 436);
        let denominator_invs = *borrow(&ctx, 474);
        let denominators = *borrow(&ctx, 500);
        let expmod_context = *borrow(&ctx, 526);


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
            let composition_alpha = /*composition_alpha*/ *borrow(&ctx, 41);


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


    #[test_only]
    use aptos_std::debug;

    #[test]
    fun test_fallback() {
        let ctx: vector<u256> = vector[
            3197217402377420549807301481158349892858971871383958510776677383324152463094,
            2253879008760025657453121132867989323563526513843283036322009523071045420572,
            2310412858702653362915880132536764937085309291628714610535637671570908301621,
            126657135114259205810665710096094000119312649163758177838032753629533589712,
            3585153049555662050453331834571057439379833908772600683912362019117580275051,
            1900411239845897696228062510898864380999791093864132646112988887271406490608,
            3436211370341291831757572430396366066456882724956853684419537539619589314461,
            67108864,
            65536,
            32768,
            731,
            1,
            2266515,
            5,
            3232402799020273123701672899620163879959024531795856118904701543579107478288,
            438963245466416667030274468984203196494549069586215159473149318689786606805,
            237091730132628179595235854248170298673273730422057097434751404289728973511,
            2357368800805230664654205636909556797949827786540246625647507229095350308130,
            1,
            0,
            65535,
            2057101974348072098895286686097740874644021284243895364547569106336505195612,
            1,
            0,
            103819182728899869565882727309406307775952474882936402905235507144116663626,
            829863683768294307140114148203146716537258780650685506485473402189848958363,
            3270498057890308734753746647964206995416464406782194412141429358700681652838,
            2089986280348253421170679821480865132823066470938446095505822317253594081284,
            1713931329540660377023406109199410414810705867260802078187082345529207694986,
            2275839,
            2374143,
            2898431,
            5519871,
            1740032260176861730069282301706899931803609121779848595553493302998775290819,
            1955765603506422831269466731145883520413367464641297033809395717401241253218,
            3232402799020273123701672899620163879959024531795856118904701543579107478288,
            438963245466416667030274468984203196494549069586215159473149318689786606805,
            2357368800805230664654205636909556797949827786540246625647507229095350308130,
            2057101974348072098895286686097740874644021284243895364547569106336505195612,
            103819182728899869565882727309406307775952474882936402905235507144116663626,
            829863683768294307140114148203146716537258780650685506485473402189848958363,
            3334892972819470717353039876663887397028904306209984841245893150173491288,
            3548947510507586517675900568239060198226108205794571959894920328866856445573,
            712427633099186256597047841283370005520810437757362091195695622900735252569,
            2029649921833934921784626980805058858076500080714603032361181641534946701867,
            160555420258854248089873048749694648598400411684329932268041614982221387666,
            223527843589458402271174547521155257728975697045588134434496836581764527900,
            814940761437210685471668812440764745370613916570816610913208530164415043493,
            1993290625982870565372910987309909097344508658728739320510722835781774169273,
            2272147017812579606347180553081347576119538165411450980680288020507267462901,
            211139281063722280838328049680277733523493347251951347839538190670624209095,
            3444651648461867043858455623706248487274940089497255388317645657091938967647,
            87129861544957347793038446981198088048655915251532716161733530893163993171,
            664232891671426511901835086752872209002947785119558773051770994448651539220,
            326362128304758465073016159714982312842881567873333789162469070374876828580,
            2441904163698353036460352145221944831848470628538118758495716186977383881751,
            2681380276974810150866768597111301499173409974540739657092214906566435166243,
            2501718132621277256046203544042695455023326484987057801940426714923833643620,
            17696682845535337224570325747887485927381007680513814900187347175742637380,
            1838709828518648883521242106686653884204839827924527955895312237462803150938,
            2382094083916273823869432778086786693952806493654763628775100189043106532137,
            1596672803944313529923426304757581291633326723383150553887983837117672248799,
            787024873543905010025819948572150004486020584933289785162320523370109986629,
            1115069916731685144330688748322545059445387488612736488895270111051073591159,
            3295548627554471911525566542782083975717390705012405626122291097413020145851,
            1044252291803837767115471168300286725035496483820492609975206329687026399827,
            705453234213411887034200109493350047607992234703130841732281674399378177645,
            1531070214898993178570339706939895482098662495362453444175047921069262454378,
            3029320690401909606174723023464519687193895376403331172496560875069197640287,
            3216783136314992621596507560725163780054364082257822626149235666091281860524,
            1285816602797393089922112759086798665553256735844994493092403633623663753695,
            565864424862514084442660391069731686938893218508932377401418685197507267652,
            837972989780537566386904452249311037063642478871035512711190441399228634558,
            158676038194185278001594288640310640432703522799672161544737468718014704300,
            2661352563210185743148393218096461976504321451299937014444567780537084865395,
            273196362064076793984876358839454613098639675536736095488614814502268636041,
            2157555245004112834716159616200076252030703902099681571279488180500286243034,
            2303243855634721574579672732226436541048746989312377914462570800546327285010,
            2849766913738765272324647937846941303746142327044885763230110302544975841377,
            501760108747994476062646534621438823950520003998410297763295832244602254004,
            132761094188370146666991734017175241152622330372694929658177674577146938837,
            3405752159210470593219570921096773605700808403979093898820990617286575274527,
            238353794166812802458343182838358907018390454172928663435521389720674510104,
            497429770447516113100430303580445744971387802775040962777513418301569202174,
            308272361007210190630136338338633856093371179725166786784556586721205599980,
            3361290998515397140351446816022356738649271298482542466604092394467283149413,
            552645066139080647252095892262343742776058820265553294004791139603457233862,
            3562522345136070306047082255579360508831583202350984569643332989051200279698,
            708873269884547149891534309366008267180444961692643734434085484031214616168,
            2855995613834990655154798125514326958500109948634629223094964290009965592903,
            3400670554467412434357015053934507139522518035561944396303796946350761166028,
            652530355806014330701310733437750058655004738290871636448963301364405750673,
            1005620991030225487476906776541635101031047893045990615716134366908704784785,
            3067931102052040793959375250507492914834703343095615798610189942398936963913,
            1366928844352318053837943451152298450000262682293794125255951293869693797364,
            3243191164140085924556648433809931503810013174218229126528149238085533749322,
            2347069970609071138902453601741794739944720004429235728003209212921536050006,
            1541025629837553497702037789163031511392569432705502753624743166413078698680,
            3485103300321495519229545878245328664002060022626169515119662475140726229266,
            2711975106671396967165344511584824910706702449175010712143310732286411571942,
            2068919339923520396966846487911385773613667020847213981899497860323964780617,
            1083354048358815964548425653066764853811691069478618025835795844984945769435,
            1124864435660620675406873398665194722406967512884428495888619128963454800240,
            2868087554638908323154006244825879340940952601340503073323761313294404574849,
            2342678015735582754697771933889942868355265597719664477105777986287204754022,
            3474483632228758181937486801249112057343145736998740311782034115529751794757,
            31201692442061647039716910679411954365320304605239472546780182039189945692,
            1212840480246206696235770909654684807995618705861373671551293455584138331829,
            1898464141551994368036004892485324330704719266229696305699458067756270134417,
            657487080482464123041777966620784237783056907835081551669814010772229565628,
            2985242906942949007305331158222461006101781404214658938414372693858150475058,
            2819515060999088611162432179430520888258375146299073462713120822295090399321,
            2950784660646704495333396141720907011629421796865153858929342304736509400158,
            2302835862943186314228723778278426911530993505895764052172100659650380480278,
            926690961112950472956447522388202939905997847053526299632076337151118715416,
            34373083556969879777456879556753368970979166779552946546540214004729037825,
            2002719898484053562336671466809556625109609097929618698273227612196748439587,
            1840519106802627693427391424881131056515476324199296541642993500541426913397,
            3463042798780391435325495679887312579514133973159365906066977990831758306607,
            1459572508849044237841124867719491584099765684483213705577940992200066898602,
            3526901276518843093090567381168332599590025023496589650509817726916659004501,
            970011309380434567781242208249627446852582740387127887650755858968321419188,
            1617512889855765841473677708779964707501382785379813378119060985433543878387,
            2557019374503580175311963327376668824519650579047032349119499978139436150247,
            46856359499492385952986417299785986741351684297588203068424205442933284583,
            1396722419965945535392800692584031409876195255542377178347088516948459643128,
            2130712495667970637270824792250864708407165912130379654007189433211755466209,
            915046473634192115030950277622446733045663172270182246762679931459553365015,
            147626856306593467134093601725457010181525246088471867247598980938405301915,
            847257011535103065167163722165706338495374813012743849020770627484535545331,
            1686825470597288950215896636746830197633755989415330648253910715740307248531,
            783620294062261459910427888244425506194750089533308638754725582709409746618,
            2528825238541814192807374103076921939772030565844763430927162319143277329052,
            2918745970952349225981563115885027825637722544554825359210159293205472016447,
            3018503161046998656327886570483651035999513720673499136455794622618199577026,
            2736151855557415351434256703143136706620497820314547810375775399527769918735,
            3470660422431183249015648540601754662936754964800977221372013128809655202277,
            2906239157190553063763537124530272555589091814437233211368589200812218450182,
            1502211803160940966478584201516892778664209796418783967981781651783002425988,
            813348725118567341926270913370268807221422478290745517629846627074543660898,
            219274034390323733709277493310058217195352716537557257367798018983640306456,
            1464161924454163335713919495314079757766789426167725204608821622554184687946,
            655507783248751148991081054048600887545202889309484743566590723437711233122,
            2430061940428814172953430777160569473181453532210165529789849009034477250840,
            3493003465176367910044057472223792371162131945253252182670909140270678147268,
            2973105169848528321641465044286480990753720528677186828258616391529394495389,
            853188831200091507013438796760615135941739399626146807955862246099843524978,
            1589594603423788188917486815731669793500158238778197897697887574906312765047,
            1068050092341779183894331547665262540515110864267904346370087550417074730816,
            2128751411674014359863099700016634162370006201660696718760913935015289336158,
            384935837206753318830463791865575679046140119820669433756848289429604384692,
            726570947810898029073689261366662576734138282309572087682823380577444799574,
            3261226432113843892097970428776909332487970694816584189703410878906039187627,
            2199967878346940806272973109580737755706323899816699122974955313035122307001,
            124965664923479667916341650758838076066521835114474297701300463914054338794,
            1340206160429593290175828288741727352235682214798840607479286152551208617571,
            1798374238499158581089361409202818993444670951454226091296573047370524079333,
            421650568764506837788929473562633181394557130692144724498497904999685210339,
            2156746992266944830923682319883717226602377362662078524693492594911278576092,
            960573838276918475819967424344163848118571285784954911430561433304486215997,
            2030488069828876147834787029893849202751237234936148681728752305094239794813,
            13945806494149454568860357508751917124255380163307690158420641446674861483,
            158221745741736583481292000326631212195947748141973753377107392215799674893,
            760649456072976804480389360226505244639823326578392060624440749361134269223,
            1244298301514977119415351963833848548672097338446643076926597264877177655472,
            1983125121141353075338617034220201465511088558493860913660254694684591293924,
            3433058322556997385808326427813866018635459529882716341969670911542846840643,
            2293616198249979611069302091009206703997133870296215063542153845343129162792,
            2979495737227865788684520645322098297212125062796289269874390219133768106590,
            2140797709697576205199434180840349046716558172944923299190420328303214325118,
            1851741961550619300002960626894738067478001474944185903250687964383742617354,
            2740114491412907767283267258442306685847732613760644464759977549849853456628,
            2754305301900734920986875948591072228538417853269302910280476072703057843210,
            3583499118688568867547567711198248902784617926020114792133080935522162962620,
            879088762041316272903276884696391426573773145887622157886407231456710882706,
            299942595713014973125270746155169585038203084564211560736137343065738512595,
            165740224907666484184165788524923491720258267007155555806278818566115109135,
            1062971607155957327538963172874878060177387676926472086184811835209411140733,
            1661520415101280729838792053222900019793779692950482354181969847988636612785,
            626752279474411338732550399492446514134676045334113892280675119296335458741,
            1914507326026450874779039863357614639814115937793290577417121529270341260744,
            987571013202154973546550036645064438099083417826355490737121739032610262962,
            3472093544034254813838586212151141413014714000283617761947975784985027077773,
            1437731377581722799463248300808692713621768562751691635893471932719743841905,
            2380727941980047749376255611080021911457181554423995910962638198968309775327,
            2459686040895053851619188830276783484129744555924178203258627207075981351729,
            1332827597626204962024573756749133242513179457254936548626088601166894992240,
            773359759136053650597437225702989413120609486073645920672108941830553746406,
            2484080095441419615538308637595856104262898872138472637717781970142680197752,
            3194083049803751608385391901944495860779870146289210021530966133327101038179,
            990743446496718147467697361294276118796959529836559289624697367411008631077,
            2780903918919813181591877406952730301905704956676136226710904127127599815322,
            620474515902095668865943764551107769238288746131540583481741076648585447125,
            1121530778520052553749251062335945117881316502960114601272346797197790421943,
            901178635501879554434872566229218741289984791525580283181733804266312813700,
            697391553371173863612550837240975344486488087320374970390037710298455477450,
            2732307669188945325854114737389183042776536788824793713083886974792219744825,
            2338628250610829325669301343722609515984329057819038032426812465160222807290,
            1429140985201337381712728749775448040490918734845987139226695593114441573328,
            2860060702814074443660565773475913617234905426744329206115136383804386020203,
            483761982439919894593388324202635209682397085661100709298092604086067195689,
            3113468192755088194475224473019300595084072203063888222429649604149846025470,
            1077237170346378479795457115355809389727744650233565858480133501275088050662,
            2683497072801868375153287445648142781364035758349044840956609769445678442383,
            527483451218087147407715216140631811828341128654551875110825221318920104903,
            1537989283075453157533482844764000181696146779535383168322256458047971836078,
            27936153261266018801330581262564421469987165709417602493291468898528910365,
            3278370496702299748674269236276661667852606967584853254966229280508098255632,
            226539669921314036857477019419899705041368189885143891208790040279718766785,
            1269511949921446270848196740903796241152745874572591626633347824746107129459,
            2741219968241427520279634590872536162959212579693297461284641477437622950727,
            3348586724986155054541592424092249779115716097100649887613403667075885421595,
            3317459154804030694905016290382297989943643905616618784628793304843764356620,
            249580235095900926615027717784383999922955983492659811672291564149726388275,
            928341035809801979316176889920034751866243941699253344561869896690986171637,
            2888812570833472291390949249128741821436320961302192051463465109572910631803,
            1466646577263945838484048654299189047507271456871685225813565340698949066048,
            1465300258149816604277918231169105856210290953684520748742892771474398387887,
            2260757620146831758778715572294855187364447009334995256514971407581410380432,
            223025586369753385457385233015607294673592519423150561323025051013835831691,
            1160668707298726209394818609124852354377254156290464939706007183173515754674,
            1913035609632647259670559371462489875703230935143759876685426779813670146701,
            2823544174680341776302925909127028983985215137140561157167066308765272561056,
            2692886551010028841752933091884592069989881181623557755492431518826525645197,
            1185072949316073117873709937271588433975419892166069499005792857528489590476,
            1865326701797580211402422109276905438067881238227113708412457704289085166238,
            3450414845209671749805014579205318673554387752313497838860328093680389622609,
            2457543442938337013542413450972978791539180091531413851905977846232996021993,
            1861725585888135483002525476594161578735500150375327798504349048494360186762,
            1957220960100107711477854975523598424361803880361037445720526835303658634738,
            3399568337988807213951242524668118338825478388222090656781935919416776791060,
            692223117400285147740375257026254459594884842532003256636493640218447068094,
            1775505314517370329558999185057719044151070126138922957483837039931931456262,
            1326389350710615116391365680256163199973980758823363951013032037682388997786,
        ];
        debug::print(&fallback(&ctx));
    }
}
