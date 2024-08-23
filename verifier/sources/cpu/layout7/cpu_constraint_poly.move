module verifier_addr::cpu_constraint_poly {

    use std::vector;
    use std::vector::{push_back, borrow, borrow_mut};

    const EPRODUCT_INVERSE_ZERO: u64 = 0x0001;

    const PRIME: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;

    public fun fmul(a: u256, b: u256): u256 {
        0
    }

    public fun fexp(a: u256, b: u256): u256 {
        0
    }

    // The Memory map during the execution of this contract is as follows:
    // [0x0, 0x20) - pedersen__points__x
    // [0x20, 0x40) - pedersen__points__y
    // [0x40, 0x60) - poseidon__poseidon__full_round_key0
    // [0x60, 0x80) - poseidon__poseidon__full_round_key1
    // [0x80, 0xa0) - poseidon__poseidon__full_round_key2
    // [0xa0, 0xc0) - poseidon__poseidon__partial_round_key0
    // [0xc0, 0xe0) - poseidon__poseidon__partial_round_key1
    // [0xe0, 0x100) - trace_length
    // [0x100, 0x120) - offset_size
    // [0x120, 0x140) - half_offset_size
    // [0x140, 0x160) - initial_ap
    // [0x160, 0x180) - initial_pc
    // [0x180, 0x1a0) - final_ap
    // [0x1a0, 0x1c0) - final_pc
    // [0x1c0, 0x1e0) - memory__multi_column_perm__perm__interaction_elm
    // [0x1e0, 0x200) - memory__multi_column_perm__hash_interaction_elm0
    // [0x200, 0x220) - memory__multi_column_perm__perm__public_memory_prod
    // [0x220, 0x240) - range_check16__perm__interaction_elm
    // [0x240, 0x260) - range_check16__perm__public_memory_prod
    // [0x260, 0x280) - range_check_min
    // [0x280, 0x2a0) - range_check_max
    // [0x2a0, 0x2c0) - diluted_check__permutation__interaction_elm
    // [0x2c0, 0x2e0) - diluted_check__permutation__public_memory_prod
    // [0x2e0, 0x300) - diluted_check__first_elm
    // [0x300, 0x320) - diluted_check__interaction_z
    // [0x320, 0x340) - diluted_check__interaction_alpha
    // [0x340, 0x360) - diluted_check__final_cum_val
    // [0x360, 0x380) - pedersen__shift_point__x
    // [0x380, 0x3a0) - pedersen__shift_point__y
    // [0x3a0, 0x3c0) - initial_pedersen_addr
    // [0x3c0, 0x3e0) - initial_range_check_addr
    // [0x3e0, 0x400) - initial_bitwise_addr
    // [0x400, 0x420) - initial_poseidon_addr
    // [0x420, 0x440) - trace_generator
    // [0x440, 0x460) - oods_point
    // [0x460, 0x520) - interaction_elements
    // [0x520, 0x540) - composition_alpha
    // [0x540, 0x1d40) - oods_values
    // [0x1d40, 0x1d60) - cpu__decode__opcode_range_check__bit_0
    // [0x1d60, 0x1d80) - cpu__decode__opcode_range_check__bit_2
    // [0x1d80, 0x1da0) - cpu__decode__opcode_range_check__bit_4
    // [0x1da0, 0x1dc0) - cpu__decode__opcode_range_check__bit_3
    // [0x1dc0, 0x1de0) - cpu__decode__flag_op1_base_op0_0
    // [0x1de0, 0x1e00) - cpu__decode__opcode_range_check__bit_5
    // [0x1e00, 0x1e20) - cpu__decode__opcode_range_check__bit_6
    // [0x1e20, 0x1e40) - cpu__decode__opcode_range_check__bit_9
    // [0x1e40, 0x1e60) - cpu__decode__flag_res_op1_0
    // [0x1e60, 0x1e80) - cpu__decode__opcode_range_check__bit_7
    // [0x1e80, 0x1ea0) - cpu__decode__opcode_range_check__bit_8
    // [0x1ea0, 0x1ec0) - cpu__decode__flag_pc_update_regular_0
    // [0x1ec0, 0x1ee0) - cpu__decode__opcode_range_check__bit_12
    // [0x1ee0, 0x1f00) - cpu__decode__opcode_range_check__bit_13
    // [0x1f00, 0x1f20) - cpu__decode__fp_update_regular_0
    // [0x1f20, 0x1f40) - cpu__decode__opcode_range_check__bit_1
    // [0x1f40, 0x1f60) - npc_reg_0
    // [0x1f60, 0x1f80) - cpu__decode__opcode_range_check__bit_10
    // [0x1f80, 0x1fa0) - cpu__decode__opcode_range_check__bit_11
    // [0x1fa0, 0x1fc0) - cpu__decode__opcode_range_check__bit_14
    // [0x1fc0, 0x1fe0) - memory__address_diff_0
    // [0x1fe0, 0x2000) - range_check16__diff_0
    // [0x2000, 0x2020) - pedersen__hash0__ec_subset_sum__bit_0
    // [0x2020, 0x2040) - pedersen__hash0__ec_subset_sum__bit_neg_0
    // [0x2040, 0x2060) - range_check_builtin__value0_0
    // [0x2060, 0x2080) - range_check_builtin__value1_0
    // [0x2080, 0x20a0) - range_check_builtin__value2_0
    // [0x20a0, 0x20c0) - range_check_builtin__value3_0
    // [0x20c0, 0x20e0) - range_check_builtin__value4_0
    // [0x20e0, 0x2100) - range_check_builtin__value5_0
    // [0x2100, 0x2120) - range_check_builtin__value6_0
    // [0x2120, 0x2140) - range_check_builtin__value7_0
    // [0x2140, 0x2160) - bitwise__sum_var_0_0
    // [0x2160, 0x2180) - bitwise__sum_var_8_0
    // [0x2180, 0x21a0) - poseidon__poseidon__full_rounds_state0_cubed_0
    // [0x21a0, 0x21c0) - poseidon__poseidon__full_rounds_state1_cubed_0
    // [0x21c0, 0x21e0) - poseidon__poseidon__full_rounds_state2_cubed_0
    // [0x21e0, 0x2200) - poseidon__poseidon__full_rounds_state0_cubed_7
    // [0x2200, 0x2220) - poseidon__poseidon__full_rounds_state1_cubed_7
    // [0x2220, 0x2240) - poseidon__poseidon__full_rounds_state2_cubed_7
    // [0x2240, 0x2260) - poseidon__poseidon__full_rounds_state0_cubed_3
    // [0x2260, 0x2280) - poseidon__poseidon__full_rounds_state1_cubed_3
    // [0x2280, 0x22a0) - poseidon__poseidon__full_rounds_state2_cubed_3
    // [0x22a0, 0x22c0) - poseidon__poseidon__partial_rounds_state0_cubed_0
    // [0x22c0, 0x22e0) - poseidon__poseidon__partial_rounds_state0_cubed_1
    // [0x22e0, 0x2300) - poseidon__poseidon__partial_rounds_state0_cubed_2
    // [0x2300, 0x2320) - poseidon__poseidon__partial_rounds_state1_cubed_0
    // [0x2320, 0x2340) - poseidon__poseidon__partial_rounds_state1_cubed_1
    // [0x2340, 0x2360) - poseidon__poseidon__partial_rounds_state1_cubed_2
    // [0x2360, 0x2380) - poseidon__poseidon__partial_rounds_state1_cubed_19
    // [0x2380, 0x23a0) - poseidon__poseidon__partial_rounds_state1_cubed_20
    // [0x23a0, 0x23c0) - poseidon__poseidon__partial_rounds_state1_cubed_21
    // [0x23c0, 0x29c0) - expmods
    // [0x29c0, 0x2d40) - domains
    // [0x2d40, 0x2f80) - denominator_invs
    // [0x2f80, 0x31c0) - denominators
    // [0x31c0, 0x3280) - expmod_context


    public fun fallback(ctx: &vector<u256>): u256 {
        let ctx = *ctx;
        let res = 0;

        let remain = 404 - vector::length(&ctx);

        for (i in 0..remain) {
            push_back(&mut ctx, 0);
        };

        let pedersen__points__x = *borrow(&ctx, 0);
        let pedersen__points__y = *borrow(&ctx, 1);
        let poseidon__poseidon__full_round_key0 = *borrow(&ctx, 2);
        let poseidon__poseidon__full_round_key1 = *borrow(&ctx, 3);
        let poseidon__poseidon__full_round_key2 = *borrow(&ctx, 4);
        let poseidon__poseidon__partial_round_key0 = *borrow(&ctx, 5);
        let poseidon__poseidon__partial_round_key1 = *borrow(&ctx, 6);
        let trace_length = *borrow(&ctx, 7);
        let offset_size = *borrow(&ctx, 8);
        let half_offset_size = *borrow(&ctx, 9);
        let initial_ap = *borrow(&ctx, 10);
        let initial_pc = *borrow(&ctx, 11);
        let final_ap = *borrow(&ctx, 12);
        let final_pc = *borrow(&ctx, 13);
        let memory__multi_column_perm__perm__interaction_elm = *borrow(&ctx, 14);
        let memory__multi_column_perm__hash_interaction_elm0 = *borrow(&ctx, 15);
        let memory__multi_column_perm__perm__public_memory_prod = *borrow(&ctx, 16);
        let range_check16__perm__interaction_elm = *borrow(&ctx, 17);
        let range_check16__perm__public_memory_prod = *borrow(&ctx, 18);
        let range_check_min = *borrow(&ctx, 19);
        let range_check_max = *borrow(&ctx, 20);
        let diluted_check__permutation__interaction_elm = *borrow(&ctx, 21);
        let diluted_check__permutation__public_memory_prod = *borrow(&ctx, 22);
        let diluted_check__first_elm = *borrow(&ctx, 23);
        let diluted_check__interaction_z = *borrow(&ctx, 24);
        let diluted_check__interaction_alpha = *borrow(&ctx, 25);
        let diluted_check__final_cum_val = *borrow(&ctx, 26);
        let pedersen__shift_point__x = *borrow(&ctx, 27);
        let pedersen__shift_point__y = *borrow(&ctx, 28);
        let initial_pedersen_addr = *borrow(&ctx, 29);
        let initial_range_check_addr = *borrow(&ctx, 30);
        let initial_bitwise_addr = *borrow(&ctx, 31);
        let initial_poseidon_addr = *borrow(&ctx, 32);
        let trace_generator = *borrow(&ctx, 33);
        let oods_point = *borrow(&ctx, 34);
        let interaction_elements = *borrow(&ctx, 35);
        let composition_alpha = *borrow(&ctx, 41);
        let oods_values = *borrow(&ctx, 42);
        let cpu__decode__opcode_range_check__bit_0 = *borrow(&ctx, 234);
        let cpu__decode__opcode_range_check__bit_2 = *borrow(&ctx, 235);
        let cpu__decode__opcode_range_check__bit_4 = *borrow(&ctx, 236);
        let cpu__decode__opcode_range_check__bit_3 = *borrow(&ctx, 237);
        let cpu__decode__flag_op1_base_op0_0 = *borrow(&ctx, 238);
        let cpu__decode__opcode_range_check__bit_5 = *borrow(&ctx, 239);
        let cpu__decode__opcode_range_check__bit_6 = *borrow(&ctx, 240);
        let cpu__decode__opcode_range_check__bit_9 = *borrow(&ctx, 241);
        let cpu__decode__flag_res_op1_0 = *borrow(&ctx, 242);
        let cpu__decode__opcode_range_check__bit_7 = *borrow(&ctx, 243);
        let cpu__decode__opcode_range_check__bit_8 = *borrow(&ctx, 244);
        let cpu__decode__flag_pc_update_regular_0 = *borrow(&ctx, 245);
        let cpu__decode__opcode_range_check__bit_12 = *borrow(&ctx, 246);
        let cpu__decode__opcode_range_check__bit_13 = *borrow(&ctx, 247);
        let cpu__decode__fp_update_regular_0 = *borrow(&ctx, 248);
        let cpu__decode__opcode_range_check__bit_1 = *borrow(&ctx, 249);
        let npc_reg_0 = *borrow(&ctx, 250);
        let cpu__decode__opcode_range_check__bit_10 = *borrow(&ctx, 251);
        let cpu__decode__opcode_range_check__bit_11 = *borrow(&ctx, 252);
        let cpu__decode__opcode_range_check__bit_14 = *borrow(&ctx, 253);
        let memory__address_diff_0 = *borrow(&ctx, 254);
        let range_check16__diff_0 = *borrow(&ctx, 255);
        let pedersen__hash0__ec_subset_sum__bit_0 = *borrow(&ctx, 256);
        let pedersen__hash0__ec_subset_sum__bit_neg_0 = *borrow(&ctx, 257);
        let range_check_builtin__value0_0 = *borrow(&ctx, 258);
        let range_check_builtin__value1_0 = *borrow(&ctx, 259);
        let range_check_builtin__value2_0 = *borrow(&ctx, 260);
        let range_check_builtin__value3_0 = *borrow(&ctx, 261);
        let range_check_builtin__value4_0 = *borrow(&ctx, 262);
        let range_check_builtin__value5_0 = *borrow(&ctx, 263);
        let range_check_builtin__value6_0 = *borrow(&ctx, 264);
        let range_check_builtin__value7_0 = *borrow(&ctx, 265);
        let bitwise__sum_var_0_0 = *borrow(&ctx, 266);
        let bitwise__sum_var_8_0 = *borrow(&ctx, 267);
        let poseidon__poseidon__full_rounds_state0_cubed_0 = *borrow(&ctx, 268);
        let poseidon__poseidon__full_rounds_state1_cubed_0 = *borrow(&ctx, 269);
        let poseidon__poseidon__full_rounds_state2_cubed_0 = *borrow(&ctx, 270);
        let poseidon__poseidon__full_rounds_state0_cubed_7 = *borrow(&ctx, 271);
        let poseidon__poseidon__full_rounds_state1_cubed_7 = *borrow(&ctx, 272);
        let poseidon__poseidon__full_rounds_state2_cubed_7 = *borrow(&ctx, 273);
        let poseidon__poseidon__full_rounds_state0_cubed_3 = *borrow(&ctx, 274);
        let poseidon__poseidon__full_rounds_state1_cubed_3 = *borrow(&ctx, 275);
        let poseidon__poseidon__full_rounds_state2_cubed_3 = *borrow(&ctx, 276);
        let poseidon__poseidon__partial_rounds_state0_cubed_0 = *borrow(&ctx, 277);
        let poseidon__poseidon__partial_rounds_state0_cubed_1 = *borrow(&ctx, 278);
        let poseidon__poseidon__partial_rounds_state0_cubed_2 = *borrow(&ctx, 279);
        let poseidon__poseidon__partial_rounds_state1_cubed_0 = *borrow(&ctx, 280);
        let poseidon__poseidon__partial_rounds_state1_cubed_1 = *borrow(&ctx, 281);
        let poseidon__poseidon__partial_rounds_state1_cubed_2 = *borrow(&ctx, 282);
        let poseidon__poseidon__partial_rounds_state1_cubed_19 = *borrow(&ctx, 283);
        let poseidon__poseidon__partial_rounds_state1_cubed_20 = *borrow(&ctx, 284);
        let poseidon__poseidon__partial_rounds_state1_cubed_21 = *borrow(&ctx, 285);
        let expmods = *borrow(&ctx, 286);
        let domains = *borrow(&ctx, 334);
        let denominator_invs = *borrow(&ctx, 362);
        let denominators = *borrow(&ctx, 380);
        let expmod_context = *borrow(&ctx, 398);


        let point = oods_point;

        {
            // compute expmods
            // expmods[0] = point^(trace_length / 2048)
            {
                let val = fexp(/*point*/ point, (/*trace_length*/ trace_length / 2048));
                *borrow_mut(&mut ctx, 286) = val;
            };
            // expmods[1] = point^(trace_length / 1024)
            {
                let val = fexp(/*point*/ point, (/*trace_length*/ trace_length / 1024));
                *borrow_mut(&mut ctx, 287) = val;
            };
            // expmods[2] = point^(trace_length / 128)
            {
                let val = fexp(/*point*/ point, (/*trace_length*/ trace_length / 128));
                *borrow_mut(&mut ctx, 288) = val;
            };
            // expmods[3] = point^(trace_length / 64)
            {
                let val = fexp(/*point*/ point, (/*trace_length*/ trace_length / 64));
                *borrow_mut(&mut ctx, 289) = val;
            };
            // expmods[4] = point^(trace_length / 32)
            {
                let val = fexp(/*point*/ point, (/*trace_length*/ trace_length / 32));
                *borrow_mut(&mut ctx, 290) = val;
            };
            // expmods[5] = point^(trace_length / 16)
            {
                let val = fexp(/*point*/ point, (/*trace_length*/ trace_length / 16));
                *borrow_mut(&mut ctx, 291) = val;
            };
            // expmods[6] = point^(trace_length / 4)
            {
                let val = fexp(/*point*/ point, (/*trace_length*/ trace_length / 4));
                *borrow_mut(&mut ctx, 292) = val;
            };
            // expmods[7] = point^(trace_length / 2)
            {
                let val = fexp(/*point*/ point, (/*trace_length*/ trace_length / 2));
                *borrow_mut(&mut ctx, 293) = val;
            };
            // expmods[8] = point^trace_length
            {
                let val = fexp(/*point*/ point, /*trace_length*/ trace_length);
                *borrow_mut(&mut ctx, 294) = val;
            };
            // expmods[9] = trace_generator^(trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 64));
                *borrow_mut(&mut ctx, 295) = val;
            };
            // expmods[10] = trace_generator^(trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 32));
                *borrow_mut(&mut ctx, 296) = val;
            };
            // expmods[11] = trace_generator^(3 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(3, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 297) = val;
            };
            // expmods[12] = trace_generator^(trace_length / 16)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 16));
                *borrow_mut(&mut ctx, 298) = val;
            };
            // expmods[13] = trace_generator^(5 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(5, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 299) = val;
            };
            // expmods[14] = trace_generator^(3 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(3, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 300) = val;
            };
            // expmods[15] = trace_generator^(7 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(7, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 301) = val;
            };
            // expmods[16] = trace_generator^(trace_length / 8)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 8));
                *borrow_mut(&mut ctx, 302) = val;
            };
            // expmods[17] = trace_generator^(9 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(9, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 303) = val;
            };
            // expmods[18] = trace_generator^(5 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(5, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 304) = val;
            };
            // expmods[19] = trace_generator^(11 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(11, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 305) = val;
            };
            // expmods[20] = trace_generator^(3 * trace_length / 16)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(3, /*trace_length*/ trace_length) / 16));
                *borrow_mut(&mut ctx, 306) = val;
            };
            // expmods[21] = trace_generator^(13 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(13, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 307) = val;
            };
            // expmods[22] = trace_generator^(7 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(7, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 308) = val;
            };
            // expmods[23] = trace_generator^(15 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(15, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 309) = val;
            };
            // expmods[24] = trace_generator^(trace_length / 2)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 2));
                *borrow_mut(&mut ctx, 310) = val;
            };
            // expmods[25] = trace_generator^(19 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(19, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 311) = val;
            };
            // expmods[26] = trace_generator^(5 * trace_length / 8)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(5, /*trace_length*/ trace_length) / 8));
                *borrow_mut(&mut ctx, 312) = val;
            };
            // expmods[27] = trace_generator^(21 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(21, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 313) = val;
            };
            // expmods[28] = trace_generator^(11 * trace_length / 16)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(11, /*trace_length*/ trace_length) / 16));
                *borrow_mut(&mut ctx, 314) = val;
            };
            // expmods[29] = trace_generator^(23 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(23, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 315) = val;
            };
            // expmods[30] = trace_generator^(3 * trace_length / 4)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(3, /*trace_length*/ trace_length) / 4));
                *borrow_mut(&mut ctx, 316) = val;
            };
            // expmods[31] = trace_generator^(25 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(25, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 317) = val;
            };
            // expmods[32] = trace_generator^(13 * trace_length / 16)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(13, /*trace_length*/ trace_length) / 16));
                *borrow_mut(&mut ctx, 318) = val;
            };
            // expmods[33] = trace_generator^(27 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(27, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 319) = val;
            };
            // expmods[34] = trace_generator^(7 * trace_length / 8)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(7, /*trace_length*/ trace_length) / 8));
                *borrow_mut(&mut ctx, 320) = val;
            };
            // expmods[35] = trace_generator^(29 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(29, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 321) = val;
            };
            // expmods[36] = trace_generator^(15 * trace_length / 16)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(15, /*trace_length*/ trace_length) / 16));
                *borrow_mut(&mut ctx, 322) = val;
            };
            // expmods[37] = trace_generator^(61 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(61, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 323) = val;
            };
            // expmods[38] = trace_generator^(31 * trace_length / 32)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(31, /*trace_length*/ trace_length) / 32));
                *borrow_mut(&mut ctx, 324) = val;
            };
            // expmods[39] = trace_generator^(63 * trace_length / 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(63, /*trace_length*/ trace_length) / 64));
                *borrow_mut(&mut ctx, 325) = val;
            };
            // expmods[40] = trace_generator^(255 * trace_length / 256)
            {
                let val = fexp(/*trace_generator*/ trace_generator, (fmul(255, /*trace_length*/ trace_length) / 256));
                *borrow_mut(&mut ctx, 326) = val;
            };
            // expmods[41] = trace_generator^(trace_length - 16)
            {
                let val = fexp(/*trace_generator*/ trace_generator, ((/*trace_length*/ trace_length - 16) % PRIME));
                *borrow_mut(&mut ctx, 327) = val;
            };
            // expmods[42] = trace_generator^(trace_length - 2)
            {
                let val = fexp(/*trace_generator*/ trace_generator, ((/*trace_length*/ trace_length - 2) % PRIME));
                *borrow_mut(&mut ctx, 328) = val;
            };
            // expmods[43] = trace_generator^(trace_length - 4)
            {
                let val = fexp(/*trace_generator*/ trace_generator, ((/*trace_length*/ trace_length - 4) % PRIME));
                *borrow_mut(&mut ctx, 329) = val;
            };
            // expmods[44] = trace_generator^(trace_length - 1)
            {
                let val = fexp(/*trace_generator*/ trace_generator, ((/*trace_length*/ trace_length - 1) % PRIME));
                *borrow_mut(&mut ctx, 330) = val;
            };
            // expmods[45] = trace_generator^(trace_length - 2048)
            {
                let val = fexp(/*trace_generator*/ trace_generator, ((/*trace_length*/ trace_length - 2048) % PRIME));
                *borrow_mut(&mut ctx, 331) = val;
            };
            // expmods[46] = trace_generator^(trace_length - 128)
            {
                let val = fexp(/*trace_generator*/ trace_generator, ((/*trace_length*/ trace_length - 128) % PRIME));
                *borrow_mut(&mut ctx, 332) = val;
            };
            // expmods[47] = trace_generator^(trace_length - 64)
            {
                let val = fexp(/*trace_generator*/ trace_generator, ((/*trace_length*/ trace_length - 64) % PRIME));
                *borrow_mut(&mut ctx, 333) = val;
            };

        };

        {
            // compute domains
            // domains[0] = point^trace_length - 1
            {
                let val = ((/*(point^trace_length)*/ *borrow(&ctx, 294) - 1) % PRIME);
                *borrow_mut(&mut ctx, 334) = val;
            };
            // domains[1] = point^(trace_length / 2) - 1
            {
                let val = ((/*(point^(trace_length/2))*/ *borrow(&ctx, 293) - 1) % PRIME);
                *borrow_mut(&mut ctx, 335) = val;
            };
            // domains[2] = point^(trace_length / 4) - 1
            {
                let val = ((/*(point^(trace_length/4))*/ *borrow(&ctx, 292) - 1) % PRIME);
                *borrow_mut(&mut ctx, 336) = val;
            };
            // domains[3] = point^(trace_length / 16) - trace_generator^(15 * trace_length / 16)
            {
                let val = ((/*(point^(trace_length/16))*/ *borrow(&ctx, 291) - /*(trace_generator^((15*trace_length)/16))*/ *borrow(&ctx, 322)) % PRIME);
                *borrow_mut(&mut ctx, 337) = val;
            };
            // domains[4] = point^(trace_length / 16) - 1
            {
                let val = ((/*(point^(trace_length/16))*/ *borrow(&ctx, 291) - 1) % PRIME);
                *borrow_mut(&mut ctx, 338) = val;
            };
            // domains[5] = point^(trace_length / 32) - 1
            {
                let val = ((/*(point^(trace_length/32))*/ *borrow(&ctx, 290) - 1) % PRIME);
                *borrow_mut(&mut ctx, 339) = val;
            };
            // domains[6] = point^(trace_length / 64) - 1
            {
                let val = ((/*(point^(trace_length/64))*/ *borrow(&ctx, 289) - 1) % PRIME);
                *borrow_mut(&mut ctx, 340) = val;
            };
            // domains[7] = point^(trace_length / 64) - trace_generator^(3 * trace_length / 4)
            {
                let val = ((/*(point^(trace_length/64))*/ *borrow(&ctx, 289) - /*(trace_generator^((3*trace_length)/4))*/ *borrow(&ctx, 316)) % PRIME);
                *borrow_mut(&mut ctx, 341) = val;
            };
            // domains[8] = point^(trace_length / 128) - 1
            {
                let val = ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - 1) % PRIME);
                *borrow_mut(&mut ctx, 342) = val;
            };
            // domains[9] = point^(trace_length / 128) - trace_generator^(3 * trace_length / 4)
            {
                let val = ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((3*trace_length)/4))*/ *borrow(&ctx, 316)) % PRIME);
                *borrow_mut(&mut ctx, 343) = val;
            };
            // domains[10] = (point^(trace_length / 128) - trace_generator^(trace_length / 64)) * (point^(trace_length / 128) - trace_generator^(trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(3 * trace_length / 64)) * (point^(trace_length / 128) - trace_generator^(trace_length / 16)) * (point^(trace_length / 128) - trace_generator^(5 * trace_length / 64)) * (point^(trace_length / 128) - trace_generator^(3 * trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(7 * trace_length / 64)) * (point^(trace_length / 128) - trace_generator^(trace_length / 8)) * (point^(trace_length / 128) - trace_generator^(9 * trace_length / 64)) * (point^(trace_length / 128) - trace_generator^(5 * trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(11 * trace_length / 64)) * (point^(trace_length / 128) - trace_generator^(3 * trace_length / 16)) * (point^(trace_length / 128) - trace_generator^(13 * trace_length / 64)) * (point^(trace_length / 128) - trace_generator^(7 * trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(15 * trace_length / 64)) * domain8
            {
                let val = fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^(trace_length/64))*/ *borrow(&ctx, 295)) % PRIME), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^(trace_length/32))*/ *borrow(&ctx, 296)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((3*trace_length)/64))*/ *borrow(&ctx, 297)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^(trace_length/16))*/ *borrow(&ctx, 298)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((5*trace_length)/64))*/ *borrow(&ctx, 299)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((3*trace_length)/32))*/ *borrow(&ctx, 300)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((7*trace_length)/64))*/ *borrow(&ctx, 301)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^(trace_length/8))*/ *borrow(&ctx, 302)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((9*trace_length)/64))*/ *borrow(&ctx, 303)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((5*trace_length)/32))*/ *borrow(&ctx, 304)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((11*trace_length)/64))*/ *borrow(&ctx, 305)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((3*trace_length)/16))*/ *borrow(&ctx, 306)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((13*trace_length)/64))*/ *borrow(&ctx, 307)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((7*trace_length)/32))*/ *borrow(&ctx, 308)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((15*trace_length)/64))*/ *borrow(&ctx, 309)) % PRIME)), /*domain8*/ *borrow(&ctx, 342));
                *borrow_mut(&mut ctx, 344) = val;
            };
            // domains[11] = point^(trace_length / 128) - trace_generator^(31 * trace_length / 32)
            {
                let val = ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((31*trace_length)/32))*/ *borrow(&ctx, 324)) % PRIME);
                *borrow_mut(&mut ctx, 345) = val;
            };
            // domains[12] = (point^(trace_length / 128) - trace_generator^(11 * trace_length / 16)) * (point^(trace_length / 128) - trace_generator^(23 * trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(25 * trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(13 * trace_length / 16)) * (point^(trace_length / 128) - trace_generator^(27 * trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(7 * trace_length / 8)) * (point^(trace_length / 128) - trace_generator^(29 * trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(15 * trace_length / 16)) * domain9 * domain11
            {
                let val = fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((11*trace_length)/16))*/ *borrow(&ctx, 314)) % PRIME), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((23*trace_length)/32))*/ *borrow(&ctx, 315)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((25*trace_length)/32))*/ *borrow(&ctx, 317)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((13*trace_length)/16))*/ *borrow(&ctx, 318)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((27*trace_length)/32))*/ *borrow(&ctx, 319)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((7*trace_length)/8))*/ *borrow(&ctx, 320)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((29*trace_length)/32))*/ *borrow(&ctx, 321)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((15*trace_length)/16))*/ *borrow(&ctx, 322)) % PRIME)), /*domain9*/ *borrow(&ctx, 343)), /*domain11*/ *borrow(&ctx, 345));
                *borrow_mut(&mut ctx, 346) = val;
            };
            // domains[13] = (point^(trace_length / 128) - trace_generator^(61 * trace_length / 64)) * (point^(trace_length / 128) - trace_generator^(63 * trace_length / 64)) * domain11
            {
                let val = fmul(fmul(((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((61*trace_length)/64))*/ *borrow(&ctx, 323)) % PRIME), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((63*trace_length)/64))*/ *borrow(&ctx, 325)) % PRIME)), /*domain11*/ *borrow(&ctx, 345));
                *borrow_mut(&mut ctx, 347) = val;
            };
            // domains[14] = (point^(trace_length / 128) - trace_generator^(19 * trace_length / 32)) * (point^(trace_length / 128) - trace_generator^(5 * trace_length / 8)) * (point^(trace_length / 128) - trace_generator^(21 * trace_length / 32)) * domain12
            {
                let val = fmul(fmul(fmul(((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((19*trace_length)/32))*/ *borrow(&ctx, 311)) % PRIME), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((5*trace_length)/8))*/ *borrow(&ctx, 312)) % PRIME)), ((/*(point^(trace_length/128))*/ *borrow(&ctx, 288) - /*(trace_generator^((21*trace_length)/32))*/ *borrow(&ctx, 313)) % PRIME)), /*domain12*/ *borrow(&ctx, 346));
                *borrow_mut(&mut ctx, 348) = val;
            };
            // domains[15] = point^(trace_length / 1024) - 1
            {
                let val = ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 287) - 1) % PRIME);
                *borrow_mut(&mut ctx, 349) = val;
            };
            // domains[16] = point^(trace_length / 1024) - trace_generator^(255 * trace_length / 256)
            {
                let val = ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 287) - /*(trace_generator^((255*trace_length)/256))*/ *borrow(&ctx, 326)) % PRIME);
                *borrow_mut(&mut ctx, 350) = val;
            };
            // domains[17] = point^(trace_length / 1024) - trace_generator^(63 * trace_length / 64)
            {
                let val = ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 287) - /*(trace_generator^((63*trace_length)/64))*/ *borrow(&ctx, 325)) % PRIME);
                *borrow_mut(&mut ctx, 351) = val;
            };
            // domains[18] = point^(trace_length / 2048) - trace_generator^(trace_length / 2)
            {
                let val = ((/*(point^(trace_length/2048))*/ *borrow(&ctx, 286) - /*(trace_generator^(trace_length/2))*/ *borrow(&ctx, 310)) % PRIME);
                *borrow_mut(&mut ctx, 352) = val;
            };
            // domains[19] = point^(trace_length / 2048) - 1
            {
                let val = ((/*(point^(trace_length/2048))*/ *borrow(&ctx, 286) - 1) % PRIME);
                *borrow_mut(&mut ctx, 353) = val;
            };
            // domains[20] = point - trace_generator^(trace_length - 16)
            {
                let val = ((/*point*/ point - /*(trace_generator^(trace_length-16))*/ *borrow(&ctx, 327)) % PRIME);
                *borrow_mut(&mut ctx, 354) = val;
            };
            // domains[21] = point - 1
            {
                let val = ((/*point*/ point - 1) % PRIME);
                *borrow_mut(&mut ctx, 355) = val;
            };
            // domains[22] = point - trace_generator^(trace_length - 2)
            {
                let val = ((/*point*/ point - /*(trace_generator^(trace_length-2))*/ *borrow(&ctx, 328)) % PRIME);
                *borrow_mut(&mut ctx, 356) = val;
            };
            // domains[23] = point - trace_generator^(trace_length - 4)
            {
                let val = ((/*point*/ point - /*(trace_generator^(trace_length-4))*/ *borrow(&ctx, 329)) % PRIME);
                *borrow_mut(&mut ctx, 357) = val;
            };
            // domains[24] = point - trace_generator^(trace_length - 1)
            {
                let val = ((/*point*/ point - /*(trace_generator^(trace_length-1))*/ *borrow(&ctx, 330)) % PRIME);
                *borrow_mut(&mut ctx, 358) = val;
            };
            // domains[25] = point - trace_generator^(trace_length - 2048)
            {
                let val = ((/*point*/ point - /*(trace_generator^(trace_length-2048))*/ *borrow(&ctx, 331)) % PRIME);
                *borrow_mut(&mut ctx, 359) = val;
            };
            // domains[26] = point - trace_generator^(trace_length - 128)
            {
                let val = ((/*point*/ point - /*(trace_generator^(trace_length-128))*/ *borrow(&ctx, 332)) % PRIME);
                *borrow_mut(&mut ctx, 360) = val;
            };
            // domains[27] = point - trace_generator^(trace_length - 64)
            {
                let val = ((/*point*/ point - /*(trace_generator^(trace_length-64))*/ *borrow(&ctx, 333)) % PRIME);
                *borrow_mut(&mut ctx, 361) = val;
            };


        };

        {
            // compute denominators
            // denominators[0] = domains[0]
            {
                let val = /*domains[0]*/ *borrow(&ctx, 334);
                *borrow_mut(&mut ctx, 380) = val;
            };
            // denominators[1] = domains[3]
            {
                let val = /*domains[3]*/ *borrow(&ctx, 337);
                *borrow_mut(&mut ctx, 381) = val;
            };
            // denominators[2] = domains[4]
            {
                let val = /*domains[4]*/ *borrow(&ctx, 338);
                *borrow_mut(&mut ctx, 382) = val;
            };
            // denominators[3] = domains[20]
            {
                let val = /*domains[20]*/ *borrow(&ctx, 354);
                *borrow_mut(&mut ctx, 383) = val;
            };
            // denominators[4] = domains[21]
            {
                let val = /*domains[21]*/ *borrow(&ctx, 355);
                *borrow_mut(&mut ctx, 384) = val;
            };
            // denominators[5] = domains[1]
            {
                let val = /*domains[1]*/ *borrow(&ctx, 335);
                *borrow_mut(&mut ctx, 385) = val;
            };
            // denominators[6] = domains[22]
            {
                let val = /*domains[22]*/ *borrow(&ctx, 356);
                *borrow_mut(&mut ctx, 386) = val;
            };
            // denominators[7] = domains[2]
            {
                let val = /*domains[2]*/ *borrow(&ctx, 336);
                *borrow_mut(&mut ctx, 387) = val;
            };
            // denominators[8] = domains[23]
            {
                let val = /*domains[23]*/ *borrow(&ctx, 357);
                *borrow_mut(&mut ctx, 388) = val;
            };
            // denominators[9] = domains[24]
            {
                let val = /*domains[24]*/ *borrow(&ctx, 358);
                *borrow_mut(&mut ctx, 389) = val;
            };
            // denominators[10] = domains[15]
            {
                let val = /*domains[15]*/ *borrow(&ctx, 349);
                *borrow_mut(&mut ctx, 390) = val;
            };
            // denominators[11] = domains[16]
            {
                let val = /*domains[16]*/ *borrow(&ctx, 350);
                *borrow_mut(&mut ctx, 391) = val;
            };
            // denominators[12] = domains[17]
            {
                let val = /*domains[17]*/ *borrow(&ctx, 351);
                *borrow_mut(&mut ctx, 392) = val;
            };
            // denominators[13] = domains[19]
            {
                let val = /*domains[19]*/ *borrow(&ctx, 353);
                *borrow_mut(&mut ctx, 393) = val;
            };
            // denominators[14] = domains[8]
            {
                let val = /*domains[8]*/ *borrow(&ctx, 342);
                *borrow_mut(&mut ctx, 394) = val;
            };
            // denominators[15] = domains[5]
            {
                let val = /*domains[5]*/ *borrow(&ctx, 339);
                *borrow_mut(&mut ctx, 395) = val;
            };
            // denominators[16] = domains[10]
            {
                let val = /*domains[10]*/ *borrow(&ctx, 344);
                *borrow_mut(&mut ctx, 396) = val;
            };
            // denominators[17] = domains[6]
            {
                let val = /*domains[6]*/ *borrow(&ctx, 340);
                *borrow_mut(&mut ctx, 397) = val;
            };

        };

        {
            // compute denominator_invs

            // Start by computing the cumulative product.
            // Let (d_0, d_1, d_2, ..., d_{n-1}) be the values in denominators. After this loop
            // denominatorInvs will be (1, d_0, d_0 * d_1, ...) and prod will contain the value of
            // d_0 * ... * d_{n-1}.
            // Compute the offset between the partialProducts array and the input values array.
            let productsToValuesOffset = 18;
            let prod = 1u256;
            let partialProductEndPtr = 380;
            let partialProductPtr = 362;
            while (partialProductPtr < partialProductEndPtr) {
                partialProductPtr = partialProductPtr + 1;
                *vector::borrow_mut(&mut ctx, partialProductPtr) = prod;
                // prod *= d_{i}.
                prod = fmul(prod, *borrow(&ctx, partialProductPtr + productsToValuesOffset));
            };

            let firstPartialProductPtr = 362;
            // Compute the inverse of the product.
            let prodInv = fexp(prod, PRIME - 2);

            assert!(prodInv != 0, EPRODUCT_INVERSE_ZERO);

            let currentPartialProductPtr = 380;

            // Compute the inverses.
            // Loop over denominator_invs in reverse order.
            // currentPartialProductPtr is initialized to one past the end.
            while (currentPartialProductPtr > firstPartialProductPtr) {
                currentPartialProductPtr = currentPartialProductPtr - 1;
                // Store 1/d_{i} = (d_0 * ... * d_{i-1}) * 1/(d_0 * ... * d_{i}).
                *borrow_mut(&mut ctx, currentPartialProductPtr) = fmul(*borrow(&ctx, currentPartialProductPtr), prodInv);
                // Update prodInv to be 1/(d_0 * ... * d_{i-1}) by multiplying by d_i.
                prodInv = fmul(prodInv, *borrow(&ctx, currentPartialProductPtr + productsToValuesOffset));
            };

        };

        let pedersen__points__x = *borrow(&ctx, 0);
        let pedersen__points__y = *borrow(&ctx, 1);
        let poseidon__poseidon__full_round_key0 = *borrow(&ctx, 2);
        let poseidon__poseidon__full_round_key1 = *borrow(&ctx, 3);
        let poseidon__poseidon__full_round_key2 = *borrow(&ctx, 4);
        let poseidon__poseidon__partial_round_key0 = *borrow(&ctx, 5);
        let poseidon__poseidon__partial_round_key1 = *borrow(&ctx, 6);
        let trace_length = *borrow(&ctx, 7);
        let offset_size = *borrow(&ctx, 8);
        let half_offset_size = *borrow(&ctx, 9);
        let initial_ap = *borrow(&ctx, 10);
        let initial_pc = *borrow(&ctx, 11);
        let final_ap = *borrow(&ctx, 12);
        let final_pc = *borrow(&ctx, 13);
        let memory__multi_column_perm__perm__interaction_elm = *borrow(&ctx, 14);
        let memory__multi_column_perm__hash_interaction_elm0 = *borrow(&ctx, 15);
        let memory__multi_column_perm__perm__public_memory_prod = *borrow(&ctx, 16);
        let range_check16__perm__interaction_elm = *borrow(&ctx, 17);
        let range_check16__perm__public_memory_prod = *borrow(&ctx, 18);
        let range_check_min = *borrow(&ctx, 19);
        let range_check_max = *borrow(&ctx, 20);
        let diluted_check__permutation__interaction_elm = *borrow(&ctx, 21);
        let diluted_check__permutation__public_memory_prod = *borrow(&ctx, 22);
        let diluted_check__first_elm = *borrow(&ctx, 23);
        let diluted_check__interaction_z = *borrow(&ctx, 24);
        let diluted_check__interaction_alpha = *borrow(&ctx, 25);
        let diluted_check__final_cum_val = *borrow(&ctx, 26);
        let pedersen__shift_point__x = *borrow(&ctx, 27);
        let pedersen__shift_point__y = *borrow(&ctx, 28);
        let initial_pedersen_addr = *borrow(&ctx, 29);
        let initial_range_check_addr = *borrow(&ctx, 30);
        let initial_bitwise_addr = *borrow(&ctx, 31);
        let initial_poseidon_addr = *borrow(&ctx, 32);
        let trace_generator = *borrow(&ctx, 33);
        let oods_point = *borrow(&ctx, 34);
        let interaction_elements = *borrow(&ctx, 35);
        let composition_alpha = *borrow(&ctx, 41);
        let oods_values = *borrow(&ctx, 42);
        let cpu__decode__opcode_range_check__bit_0 = *borrow(&ctx, 234);
        let cpu__decode__opcode_range_check__bit_2 = *borrow(&ctx, 235);
        let cpu__decode__opcode_range_check__bit_4 = *borrow(&ctx, 236);
        let cpu__decode__opcode_range_check__bit_3 = *borrow(&ctx, 237);
        let cpu__decode__flag_op1_base_op0_0 = *borrow(&ctx, 238);
        let cpu__decode__opcode_range_check__bit_5 = *borrow(&ctx, 239);
        let cpu__decode__opcode_range_check__bit_6 = *borrow(&ctx, 240);
        let cpu__decode__opcode_range_check__bit_9 = *borrow(&ctx, 241);
        let cpu__decode__flag_res_op1_0 = *borrow(&ctx, 242);
        let cpu__decode__opcode_range_check__bit_7 = *borrow(&ctx, 243);
        let cpu__decode__opcode_range_check__bit_8 = *borrow(&ctx, 244);
        let cpu__decode__flag_pc_update_regular_0 = *borrow(&ctx, 245);
        let cpu__decode__opcode_range_check__bit_12 = *borrow(&ctx, 246);
        let cpu__decode__opcode_range_check__bit_13 = *borrow(&ctx, 247);
        let cpu__decode__fp_update_regular_0 = *borrow(&ctx, 248);
        let cpu__decode__opcode_range_check__bit_1 = *borrow(&ctx, 249);
        let npc_reg_0 = *borrow(&ctx, 250);
        let cpu__decode__opcode_range_check__bit_10 = *borrow(&ctx, 251);
        let cpu__decode__opcode_range_check__bit_11 = *borrow(&ctx, 252);
        let cpu__decode__opcode_range_check__bit_14 = *borrow(&ctx, 253);
        let memory__address_diff_0 = *borrow(&ctx, 254);
        let range_check16__diff_0 = *borrow(&ctx, 255);
        let pedersen__hash0__ec_subset_sum__bit_0 = *borrow(&ctx, 256);
        let pedersen__hash0__ec_subset_sum__bit_neg_0 = *borrow(&ctx, 257);
        let range_check_builtin__value0_0 = *borrow(&ctx, 258);
        let range_check_builtin__value1_0 = *borrow(&ctx, 259);
        let range_check_builtin__value2_0 = *borrow(&ctx, 260);
        let range_check_builtin__value3_0 = *borrow(&ctx, 261);
        let range_check_builtin__value4_0 = *borrow(&ctx, 262);
        let range_check_builtin__value5_0 = *borrow(&ctx, 263);
        let range_check_builtin__value6_0 = *borrow(&ctx, 264);
        let range_check_builtin__value7_0 = *borrow(&ctx, 265);
        let bitwise__sum_var_0_0 = *borrow(&ctx, 266);
        let bitwise__sum_var_8_0 = *borrow(&ctx, 267);
        let poseidon__poseidon__full_rounds_state0_cubed_0 = *borrow(&ctx, 268);
        let poseidon__poseidon__full_rounds_state1_cubed_0 = *borrow(&ctx, 269);
        let poseidon__poseidon__full_rounds_state2_cubed_0 = *borrow(&ctx, 270);
        let poseidon__poseidon__full_rounds_state0_cubed_7 = *borrow(&ctx, 271);
        let poseidon__poseidon__full_rounds_state1_cubed_7 = *borrow(&ctx, 272);
        let poseidon__poseidon__full_rounds_state2_cubed_7 = *borrow(&ctx, 273);
        let poseidon__poseidon__full_rounds_state0_cubed_3 = *borrow(&ctx, 274);
        let poseidon__poseidon__full_rounds_state1_cubed_3 = *borrow(&ctx, 275);
        let poseidon__poseidon__full_rounds_state2_cubed_3 = *borrow(&ctx, 276);
        let poseidon__poseidon__partial_rounds_state0_cubed_0 = *borrow(&ctx, 277);
        let poseidon__poseidon__partial_rounds_state0_cubed_1 = *borrow(&ctx, 278);
        let poseidon__poseidon__partial_rounds_state0_cubed_2 = *borrow(&ctx, 279);
        let poseidon__poseidon__partial_rounds_state1_cubed_0 = *borrow(&ctx, 280);
        let poseidon__poseidon__partial_rounds_state1_cubed_1 = *borrow(&ctx, 281);
        let poseidon__poseidon__partial_rounds_state1_cubed_2 = *borrow(&ctx, 282);
        let poseidon__poseidon__partial_rounds_state1_cubed_19 = *borrow(&ctx, 283);
        let poseidon__poseidon__partial_rounds_state1_cubed_20 = *borrow(&ctx, 284);
        let poseidon__poseidon__partial_rounds_state1_cubed_21 = *borrow(&ctx, 285);
        let expmods = *borrow(&ctx, 286);
        let domains = *borrow(&ctx, 334);
        let denominator_invs = *borrow(&ctx, 362);
        let denominators = *borrow(&ctx, 380);
        let expmod_context = *borrow(&ctx, 398);



        {
            // cpu/decode/opcode_range_check/bit_0 = column0_row0 - (column0_row1 + column0_row1)
            {
                let val = ((/*column0_row0*/ *borrow(&ctx, 42) - ((/*column0_row1*/ *borrow(&ctx, 43) + /*column0_row1*/ *borrow(&ctx, 43)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 234) = val;
            };
            // cpu/decode/opcode_range_check/bit_2 = column0_row2 - (column0_row3 + column0_row3)
            {
                let val = ((/*column0_row2*/ *borrow(&ctx, 44) - ((/*column0_row3*/ *borrow(&ctx, 45) + /*column0_row3*/ *borrow(&ctx, 45)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 235) = val;
            };
            // cpu/decode/opcode_range_check/bit_4 = column0_row4 - (column0_row5 + column0_row5)
            {
                let val = ((/*column0_row4*/ *borrow(&ctx, 46) - ((/*column0_row5*/ *borrow(&ctx, 47) + /*column0_row5*/ *borrow(&ctx, 47)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 236) = val;
            };
            // cpu/decode/opcode_range_check/bit_3 = column0_row3 - (column0_row4 + column0_row4)
            {
                let val = ((/*column0_row3*/ *borrow(&ctx, 45) - ((/*column0_row4*/ *borrow(&ctx, 46) + /*column0_row4*/ *borrow(&ctx, 46)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 237) = val;
            };
            // cpu/decode/flag_op1_base_op0_0 = 1 - (cpu__decode__opcode_range_check__bit_2 + cpu__decode__opcode_range_check__bit_4 + cpu__decode__opcode_range_check__bit_3)
            {
                let val = ((1 - ((((/*cpu__decode__opcode_range_check__bit_2*/ cpu__decode__opcode_range_check__bit_2 + /*cpu__decode__opcode_range_check__bit_4*/ cpu__decode__opcode_range_check__bit_4) % PRIME) + /*cpu__decode__opcode_range_check__bit_3*/ cpu__decode__opcode_range_check__bit_3) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 238) = val;
            };
            // cpu/decode/opcode_range_check/bit_5 = column0_row5 - (column0_row6 + column0_row6)
            {
                let val = ((/*column0_row5*/ *borrow(&ctx, 47) - ((/*column0_row6*/ *borrow(&ctx, 48) + /*column0_row6*/ *borrow(&ctx, 48)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 239) = val;
            };
            // cpu/decode/opcode_range_check/bit_6 = column0_row6 - (column0_row7 + column0_row7)
            {
                let val = ((/*column0_row6*/ *borrow(&ctx, 48) - ((/*column0_row7*/ *borrow(&ctx, 49) + /*column0_row7*/ *borrow(&ctx, 49)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 240) = val;
            };
            // cpu/decode/opcode_range_check/bit_9 = column0_row9 - (column0_row10 + column0_row10)
            {
                let val = ((/*column0_row9*/ *borrow(&ctx, 51) - ((/*column0_row10*/ *borrow(&ctx, 52) + /*column0_row10*/ *borrow(&ctx, 52)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 241) = val;
            };
            // cpu/decode/flag_res_op1_0 = 1 - (cpu__decode__opcode_range_check__bit_5 + cpu__decode__opcode_range_check__bit_6 + cpu__decode__opcode_range_check__bit_9)
            {
                let val = ((1 - ((((/*cpu__decode__opcode_range_check__bit_5*/ cpu__decode__opcode_range_check__bit_5 + /*cpu__decode__opcode_range_check__bit_6*/ cpu__decode__opcode_range_check__bit_6) % PRIME) + /*cpu__decode__opcode_range_check__bit_9*/ cpu__decode__opcode_range_check__bit_9) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 242) = val;
            };
            // cpu/decode/opcode_range_check/bit_7 = column0_row7 - (column0_row8 + column0_row8)
            {
                let val = ((/*column0_row7*/ *borrow(&ctx, 49) - ((/*column0_row8*/ *borrow(&ctx, 50) + /*column0_row8*/ *borrow(&ctx, 50)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 243) = val;
            };
            // cpu/decode/opcode_range_check/bit_8 = column0_row8 - (column0_row9 + column0_row9)
            {
                let val = ((/*column0_row8*/ *borrow(&ctx, 50) - ((/*column0_row9*/ *borrow(&ctx, 51) + /*column0_row9*/ *borrow(&ctx, 51)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 244) = val;
            };
            // cpu/decode/flag_pc_update_regular_0 = 1 - (cpu__decode__opcode_range_check__bit_7 + cpu__decode__opcode_range_check__bit_8 + cpu__decode__opcode_range_check__bit_9)
            {
                let val = ((1 - ((((/*cpu__decode__opcode_range_check__bit_7*/ cpu__decode__opcode_range_check__bit_7 + /*cpu__decode__opcode_range_check__bit_8*/ cpu__decode__opcode_range_check__bit_8) % PRIME) + /*cpu__decode__opcode_range_check__bit_9*/ cpu__decode__opcode_range_check__bit_9) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 245) = val;
            };
            // cpu/decode/opcode_range_check/bit_12 = column0_row12 - (column0_row13 + column0_row13)
            {
                let val = ((/*column0_row12*/ *borrow(&ctx, 54) - ((/*column0_row13*/ *borrow(&ctx, 55) + /*column0_row13*/ *borrow(&ctx, 55)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 246) = val;
            };
            // cpu/decode/opcode_range_check/bit_13 = column0_row13 - (column0_row14 + column0_row14)
            {
                let val = ((/*column0_row13*/ *borrow(&ctx, 55) - ((/*column0_row14*/ *borrow(&ctx, 56) + /*column0_row14*/ *borrow(&ctx, 56)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 247) = val;
            };
            // cpu/decode/fp_update_regular_0 = 1 - (cpu__decode__opcode_range_check__bit_12 + cpu__decode__opcode_range_check__bit_13)
            {
                let val = ((1 - ((/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12 + /*cpu__decode__opcode_range_check__bit_13*/ cpu__decode__opcode_range_check__bit_13) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 248) = val;
            };
            // cpu/decode/opcode_range_check/bit_1 = column0_row1 - (column0_row2 + column0_row2)
            {
                let val = ((/*column0_row1*/ *borrow(&ctx, 43) - ((/*column0_row2*/ *borrow(&ctx, 44) + /*column0_row2*/ *borrow(&ctx, 44)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 249) = val;
            };
            // npc_reg_0 = column3_row0 + cpu__decode__opcode_range_check__bit_2 + 1
            {
                let val = ((((/*column3_row0*/ *borrow(&ctx, 91) + /*cpu__decode__opcode_range_check__bit_2*/ cpu__decode__opcode_range_check__bit_2) % PRIME) + 1) % PRIME);
                *borrow_mut(&mut ctx, 250) = val;
            };
            // cpu/decode/opcode_range_check/bit_10 = column0_row10 - (column0_row11 + column0_row11)
            {
                let val = ((/*column0_row10*/ *borrow(&ctx, 52) - ((/*column0_row11*/ *borrow(&ctx, 53) + /*column0_row11*/ *borrow(&ctx, 53)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 251) = val;
            };
            // cpu/decode/opcode_range_check/bit_11 = column0_row11 - (column0_row12 + column0_row12)
            {
                let val = ((/*column0_row11*/ *borrow(&ctx, 53) - ((/*column0_row12*/ *borrow(&ctx, 54) + /*column0_row12*/ *borrow(&ctx, 54)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 252) = val;
            };
            // cpu/decode/opcode_range_check/bit_14 = column0_row14 - (column0_row15 + column0_row15)
            {
                let val = ((/*column0_row14*/ *borrow(&ctx, 56) - ((/*column0_row15*/ *borrow(&ctx, 57) + /*column0_row15*/ *borrow(&ctx, 57)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 253) = val;
            };
            // memory/address_diff_0 = column4_row2 - column4_row0
            {
                let val = ((/*column4_row2*/ *borrow(&ctx, 135) - /*column4_row0*/ *borrow(&ctx, 133)) % PRIME);
                *borrow_mut(&mut ctx, 254) = val;
            };
            // range_check16/diff_0 = column6_row6 - column6_row2
            {
                let val = ((/*column6_row6*/ *borrow(&ctx, 153) - /*column6_row2*/ *borrow(&ctx, 149)) % PRIME);
                *borrow_mut(&mut ctx, 255) = val;
            };
            // pedersen/hash0/ec_subset_sum/bit_0 = column7_row0 - (column7_row4 + column7_row4)
            {
                let val = ((/*column7_row0*/ *borrow(&ctx, 169) - ((/*column7_row4*/ *borrow(&ctx, 173) + /*column7_row4*/ *borrow(&ctx, 173)) % PRIME)) % PRIME);
                *borrow_mut(&mut ctx, 256) = val;
            };
            // pedersen/hash0/ec_subset_sum/bit_neg_0 = 1 - pedersen__hash0__ec_subset_sum__bit_0
            {
                let val = ((1 - /*pedersen__hash0__ec_subset_sum__bit_0*/ pedersen__hash0__ec_subset_sum__bit_0) % PRIME);
                *borrow_mut(&mut ctx, 257) = val;
            };
            // range_check_builtin/value0_0 = column6_row12
            {
                let val = /*column6_row12*/ *borrow(&ctx, 156);
                *borrow_mut(&mut ctx, 258) = val;
            };
            // range_check_builtin/value1_0 = range_check_builtin__value0_0 * offset_size + column6_row28
            {
                let val = ((fmul(/*range_check_builtin__value0_0*/ range_check_builtin__value0_0, /*offset_size*/ offset_size) + /*column6_row28*/ *borrow(&ctx, 157)) % PRIME);
                *borrow_mut(&mut ctx, 259) = val;
            };
            // range_check_builtin/value2_0 = range_check_builtin__value1_0 * offset_size + column6_row44
            {
                let val = ((fmul(/*range_check_builtin__value1_0*/ range_check_builtin__value1_0, /*offset_size*/ offset_size) + /*column6_row44*/ *borrow(&ctx, 158)) % PRIME);
                *borrow_mut(&mut ctx, 260) = val;
            };
            // range_check_builtin/value3_0 = range_check_builtin__value2_0 * offset_size + column6_row60
            {
                let val = ((fmul(/*range_check_builtin__value2_0*/ range_check_builtin__value2_0, /*offset_size*/ offset_size) + /*column6_row60*/ *borrow(&ctx, 159)) % PRIME);
                *borrow_mut(&mut ctx, 261) = val;
            };
            // range_check_builtin/value4_0 = range_check_builtin__value3_0 * offset_size + column6_row76
            {
                let val = ((fmul(/*range_check_builtin__value3_0*/ range_check_builtin__value3_0, /*offset_size*/ offset_size) + /*column6_row76*/ *borrow(&ctx, 160)) % PRIME);
                *borrow_mut(&mut ctx, 262) = val;
            };
            // range_check_builtin/value5_0 = range_check_builtin__value4_0 * offset_size + column6_row92
            {
                let val = ((fmul(/*range_check_builtin__value4_0*/ range_check_builtin__value4_0, /*offset_size*/ offset_size) + /*column6_row92*/ *borrow(&ctx, 161)) % PRIME);
                *borrow_mut(&mut ctx, 263) = val;
            };
            // range_check_builtin/value6_0 = range_check_builtin__value5_0 * offset_size + column6_row108
            {
                let val = ((fmul(/*range_check_builtin__value5_0*/ range_check_builtin__value5_0, /*offset_size*/ offset_size) + /*column6_row108*/ *borrow(&ctx, 162)) % PRIME);
                *borrow_mut(&mut ctx, 264) = val;
            };
            // range_check_builtin/value7_0 = range_check_builtin__value6_0 * offset_size + column6_row124
            {
                let val = ((fmul(/*range_check_builtin__value6_0*/ range_check_builtin__value6_0, /*offset_size*/ offset_size) + /*column6_row124*/ *borrow(&ctx, 163)) % PRIME);
                *borrow_mut(&mut ctx, 265) = val;
            };
            // bitwise/sum_var_0_0 = column1_row0 + column1_row2 * 2 + column1_row4 * 4 + column1_row6 * 8 + column1_row8 * 18446744073709551616 + column1_row10 * 36893488147419103232 + column1_row12 * 73786976294838206464 + column1_row14 * 147573952589676412928
            {
                let val = ((((((((((((((/*column1_row0*/ *borrow(&ctx, 58) + fmul(/*column1_row2*/ *borrow(&ctx, 60), 2)) % PRIME) + fmul(/*column1_row4*/ *borrow(&ctx, 61), 4)) % PRIME) + fmul(/*column1_row6*/ *borrow(&ctx, 62), 8)) % PRIME) + fmul(/*column1_row8*/ *borrow(&ctx, 63), 18446744073709551616)) % PRIME) + fmul(/*column1_row10*/ *borrow(&ctx, 64), 36893488147419103232)) % PRIME) + fmul(/*column1_row12*/ *borrow(&ctx, 65), 73786976294838206464)) % PRIME) + fmul(/*column1_row14*/ *borrow(&ctx, 66), 147573952589676412928)) % PRIME);
                *borrow_mut(&mut ctx, 266) = val;
            };
            // bitwise/sum_var_8_0 = column1_row16 * 340282366920938463463374607431768211456 + column1_row18 * 680564733841876926926749214863536422912 + column1_row20 * 1361129467683753853853498429727072845824 + column1_row22 * 2722258935367507707706996859454145691648 + column1_row24 * 6277101735386680763835789423207666416102355444464034512896 + column1_row26 * 12554203470773361527671578846415332832204710888928069025792 + column1_row28 * 25108406941546723055343157692830665664409421777856138051584 + column1_row30 * 50216813883093446110686315385661331328818843555712276103168
            {
                let val = ((((((((((((((fmul(/*column1_row16*/ *borrow(&ctx, 67), 340282366920938463463374607431768211456) + fmul(/*column1_row18*/ *borrow(&ctx, 68), 680564733841876926926749214863536422912)) % PRIME) + fmul(/*column1_row20*/ *borrow(&ctx, 69), 1361129467683753853853498429727072845824)) % PRIME) + fmul(/*column1_row22*/ *borrow(&ctx, 70), 2722258935367507707706996859454145691648)) % PRIME) + fmul(/*column1_row24*/ *borrow(&ctx, 71), 6277101735386680763835789423207666416102355444464034512896)) % PRIME) + fmul(/*column1_row26*/ *borrow(&ctx, 72), 12554203470773361527671578846415332832204710888928069025792)) % PRIME) + fmul(/*column1_row28*/ *borrow(&ctx, 73), 25108406941546723055343157692830665664409421777856138051584)) % PRIME) + fmul(/*column1_row30*/ *borrow(&ctx, 74), 50216813883093446110686315385661331328818843555712276103168)) % PRIME);
                *borrow_mut(&mut ctx, 267) = val;
            };
            // poseidon/poseidon/full_rounds_state0_cubed_0 = column8_row6 * column8_row9
            {
                let val = fmul(/*column8_row6*/ *borrow(&ctx, 199), /*column8_row9*/ *borrow(&ctx, 201));
                *borrow_mut(&mut ctx, 268) = val;
            };
            // poseidon/poseidon/full_rounds_state1_cubed_0 = column8_row14 * column8_row5
            {
                let val = fmul(/*column8_row14*/ *borrow(&ctx, 205), /*column8_row5*/ *borrow(&ctx, 198));
                *borrow_mut(&mut ctx, 269) = val;
            };
            // poseidon/poseidon/full_rounds_state2_cubed_0 = column8_row1 * column8_row13
            {
                let val = fmul(/*column8_row1*/ *borrow(&ctx, 195), /*column8_row13*/ *borrow(&ctx, 204));
                *borrow_mut(&mut ctx, 270) = val;
            };
            // poseidon/poseidon/full_rounds_state0_cubed_7 = column8_row118 * column8_row121
            {
                let val = fmul(/*column8_row118*/ *borrow(&ctx, 222), /*column8_row121*/ *borrow(&ctx, 223));
                *borrow_mut(&mut ctx, 271) = val;
            };
            // poseidon/poseidon/full_rounds_state1_cubed_7 = column8_row126 * column8_row117
            {
                let val = fmul(/*column8_row126*/ *borrow(&ctx, 225), /*column8_row117*/ *borrow(&ctx, 221));
                *borrow_mut(&mut ctx, 272) = val;
            };
            // poseidon/poseidon/full_rounds_state2_cubed_7 = column8_row113 * column8_row125
            {
                let val = fmul(/*column8_row113*/ *borrow(&ctx, 220), /*column8_row125*/ *borrow(&ctx, 224));
                *borrow_mut(&mut ctx, 273) = val;
            };
            // poseidon/poseidon/full_rounds_state0_cubed_3 = column8_row54 * column8_row57
            {
                let val = fmul(/*column8_row54*/ *borrow(&ctx, 213), /*column8_row57*/ *borrow(&ctx, 214));
                *borrow_mut(&mut ctx, 274) = val;
            };
            // poseidon/poseidon/full_rounds_state1_cubed_3 = column8_row62 * column8_row53
            {
                let val = fmul(/*column8_row62*/ *borrow(&ctx, 216), /*column8_row53*/ *borrow(&ctx, 212));
                *borrow_mut(&mut ctx, 275) = val;
            };
            // poseidon/poseidon/full_rounds_state2_cubed_3 = column8_row49 * column8_row61
            {
                let val = fmul(/*column8_row49*/ *borrow(&ctx, 211), /*column8_row61*/ *borrow(&ctx, 215));
                *borrow_mut(&mut ctx, 276) = val;
            };
            // poseidon/poseidon/partial_rounds_state0_cubed_0 = column5_row0 * column5_row1
            {
                let val = fmul(/*column5_row0*/ *borrow(&ctx, 137), /*column5_row1*/ *borrow(&ctx, 138));
                *borrow_mut(&mut ctx, 277) = val;
            };
            // poseidon/poseidon/partial_rounds_state0_cubed_1 = column5_row2 * column5_row3
            {
                let val = fmul(/*column5_row2*/ *borrow(&ctx, 139), /*column5_row3*/ *borrow(&ctx, 140));
                *borrow_mut(&mut ctx, 278) = val;
            };
            // poseidon/poseidon/partial_rounds_state0_cubed_2 = column5_row4 * column5_row5
            {
                let val = fmul(/*column5_row4*/ *borrow(&ctx, 141), /*column5_row5*/ *borrow(&ctx, 142));
                *borrow_mut(&mut ctx, 279) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_0 = column7_row1 * column7_row3
            {
                let val = fmul(/*column7_row1*/ *borrow(&ctx, 170), /*column7_row3*/ *borrow(&ctx, 172));
                *borrow_mut(&mut ctx, 280) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_1 = column7_row5 * column7_row7
            {
                let val = fmul(/*column7_row5*/ *borrow(&ctx, 174), /*column7_row7*/ *borrow(&ctx, 175));
                *borrow_mut(&mut ctx, 281) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_2 = column7_row9 * column7_row11
            {
                let val = fmul(/*column7_row9*/ *borrow(&ctx, 176), /*column7_row11*/ *borrow(&ctx, 177));
                *borrow_mut(&mut ctx, 282) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_19 = column7_row77 * column7_row79
            {
                let val = fmul(/*column7_row77*/ *borrow(&ctx, 179), /*column7_row79*/ *borrow(&ctx, 180));
                *borrow_mut(&mut ctx, 283) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_20 = column7_row81 * column7_row83
            {
                let val = fmul(/*column7_row81*/ *borrow(&ctx, 181), /*column7_row83*/ *borrow(&ctx, 182));
                *borrow_mut(&mut ctx, 284) = val;
            };
            // poseidon/poseidon/partial_rounds_state1_cubed_21 = column7_row85 * column7_row87
            {
                let val = fmul(/*column7_row85*/ *borrow(&ctx, 183), /*column7_row87*/ *borrow(&ctx, 184));
                *borrow_mut(&mut ctx, 285) = val;
            };


            // compute compositions

            let composition_alpha_pow = 1u256;
            let composition_alpha = /*composition_alpha*/ *borrow(&ctx, 41);


            //Constraint expression for cpu/decode/opcode_range_check/bit: cpu__decode__opcode_range_check__bit_0 * cpu__decode__opcode_range_check__bit_0 - cpu__decode__opcode_range_check__bit_0
            {
                let val =((fmul(/*cpu__decode__opcode_range_check__bit_0*/ cpu__decode__opcode_range_check__bit_0, /*cpu__decode__opcode_range_check__bit_0*/ cpu__decode__opcode_range_check__bit_0) - /*cpu__decode__opcode_range_check__bit_0*/ cpu__decode__opcode_range_check__bit_0) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 381));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 362));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/opcode_range_check/zero: column0_row0
            {
                let val =/*column0_row0*/ *borrow(&ctx, 42);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 363));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/opcode_range_check_input: column3_row1 - (((column0_row0 * offset_size + column6_row4) * offset_size + column6_row8) * offset_size + column6_row0)
            {
                let val =((/*column3_row1*/ *borrow(&ctx, 92) - ((fmul(((fmul(((fmul(/*column0_row0*/ *borrow(&ctx, 42), /*offset_size*/ offset_size) + /*column6_row4*/ *borrow(&ctx, 151)) % PRIME), /*offset_size*/ offset_size) + /*column6_row8*/ *borrow(&ctx, 155)) % PRIME), /*offset_size*/ offset_size) + /*column6_row0*/ *borrow(&ctx, 147)) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/flag_op1_base_op0_bit: cpu__decode__flag_op1_base_op0_0 * cpu__decode__flag_op1_base_op0_0 - cpu__decode__flag_op1_base_op0_0
            {
                let val =((fmul(/*cpu__decode__flag_op1_base_op0_0*/ cpu__decode__flag_op1_base_op0_0, /*cpu__decode__flag_op1_base_op0_0*/ cpu__decode__flag_op1_base_op0_0) - /*cpu__decode__flag_op1_base_op0_0*/ cpu__decode__flag_op1_base_op0_0) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/flag_res_op1_bit: cpu__decode__flag_res_op1_0 * cpu__decode__flag_res_op1_0 - cpu__decode__flag_res_op1_0
            {
                let val =((fmul(/*cpu__decode__flag_res_op1_0*/ cpu__decode__flag_res_op1_0, /*cpu__decode__flag_res_op1_0*/ cpu__decode__flag_res_op1_0) - /*cpu__decode__flag_res_op1_0*/ cpu__decode__flag_res_op1_0) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/flag_pc_update_regular_bit: cpu__decode__flag_pc_update_regular_0 * cpu__decode__flag_pc_update_regular_0 - cpu__decode__flag_pc_update_regular_0
            {
                let val =((fmul(/*cpu__decode__flag_pc_update_regular_0*/ cpu__decode__flag_pc_update_regular_0, /*cpu__decode__flag_pc_update_regular_0*/ cpu__decode__flag_pc_update_regular_0) - /*cpu__decode__flag_pc_update_regular_0*/ cpu__decode__flag_pc_update_regular_0) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/decode/fp_update_regular_bit: cpu__decode__fp_update_regular_0 * cpu__decode__fp_update_regular_0 - cpu__decode__fp_update_regular_0
            {
                let val =((fmul(/*cpu__decode__fp_update_regular_0*/ cpu__decode__fp_update_regular_0, /*cpu__decode__fp_update_regular_0*/ cpu__decode__fp_update_regular_0) - /*cpu__decode__fp_update_regular_0*/ cpu__decode__fp_update_regular_0) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/mem_dst_addr: column3_row8 + half_offset_size - (cpu__decode__opcode_range_check__bit_0 * column8_row8 + (1 - cpu__decode__opcode_range_check__bit_0) * column8_row0 + column6_row0)
            {
                let val =((((/*column3_row8*/ *borrow(&ctx, 99) + /*half_offset_size*/ half_offset_size) % PRIME) - ((((fmul(/*cpu__decode__opcode_range_check__bit_0*/ cpu__decode__opcode_range_check__bit_0, /*column8_row8*/ *borrow(&ctx, 200)) + fmul(((1 - /*cpu__decode__opcode_range_check__bit_0*/ cpu__decode__opcode_range_check__bit_0) % PRIME), /*column8_row0*/ *borrow(&ctx, 194))) % PRIME) + /*column6_row0*/ *borrow(&ctx, 147)) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/mem0_addr: column3_row4 + half_offset_size - (cpu__decode__opcode_range_check__bit_1 * column8_row8 + (1 - cpu__decode__opcode_range_check__bit_1) * column8_row0 + column6_row8)
            {
                let val =((((/*column3_row4*/ *borrow(&ctx, 95) + /*half_offset_size*/ half_offset_size) % PRIME) - ((((fmul(/*cpu__decode__opcode_range_check__bit_1*/ cpu__decode__opcode_range_check__bit_1, /*column8_row8*/ *borrow(&ctx, 200)) + fmul(((1 - /*cpu__decode__opcode_range_check__bit_1*/ cpu__decode__opcode_range_check__bit_1) % PRIME), /*column8_row0*/ *borrow(&ctx, 194))) % PRIME) + /*column6_row8*/ *borrow(&ctx, 155)) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/mem1_addr: column3_row12 + half_offset_size - (cpu__decode__opcode_range_check__bit_2 * column3_row0 + cpu__decode__opcode_range_check__bit_4 * column8_row0 + cpu__decode__opcode_range_check__bit_3 * column8_row8 + cpu__decode__flag_op1_base_op0_0 * column3_row5 + column6_row4)
            {
                let val =((((/*column3_row12*/ *borrow(&ctx, 103) + /*half_offset_size*/ half_offset_size) % PRIME) - ((((((((fmul(/*cpu__decode__opcode_range_check__bit_2*/ cpu__decode__opcode_range_check__bit_2, /*column3_row0*/ *borrow(&ctx, 91)) + fmul(/*cpu__decode__opcode_range_check__bit_4*/ cpu__decode__opcode_range_check__bit_4, /*column8_row0*/ *borrow(&ctx, 194))) % PRIME) + fmul(/*cpu__decode__opcode_range_check__bit_3*/ cpu__decode__opcode_range_check__bit_3, /*column8_row8*/ *borrow(&ctx, 200))) % PRIME) + fmul(/*cpu__decode__flag_op1_base_op0_0*/ cpu__decode__flag_op1_base_op0_0, /*column3_row5*/ *borrow(&ctx, 96))) % PRIME) + /*column6_row4*/ *borrow(&ctx, 151)) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/ops_mul: column8_row4 - column3_row5 * column3_row13
            {
                let val =((/*column8_row4*/ *borrow(&ctx, 197) - fmul(/*column3_row5*/ *borrow(&ctx, 96), /*column3_row13*/ *borrow(&ctx, 104))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/operands/res: (1 - cpu__decode__opcode_range_check__bit_9) * column8_row12 - (cpu__decode__opcode_range_check__bit_5 * (column3_row5 + column3_row13) + cpu__decode__opcode_range_check__bit_6 * column8_row4 + cpu__decode__flag_res_op1_0 * column3_row13)
            {
                let val =((fmul(((1 - /*cpu__decode__opcode_range_check__bit_9*/ cpu__decode__opcode_range_check__bit_9) % PRIME), /*column8_row12*/ *borrow(&ctx, 203)) - ((((fmul(/*cpu__decode__opcode_range_check__bit_5*/ cpu__decode__opcode_range_check__bit_5, ((/*column3_row5*/ *borrow(&ctx, 96) + /*column3_row13*/ *borrow(&ctx, 104)) % PRIME)) + fmul(/*cpu__decode__opcode_range_check__bit_6*/ cpu__decode__opcode_range_check__bit_6, /*column8_row4*/ *borrow(&ctx, 197))) % PRIME) + fmul(/*cpu__decode__flag_res_op1_0*/ cpu__decode__flag_res_op1_0, /*column3_row13*/ *borrow(&ctx, 104))) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_pc/tmp0: column8_row2 - cpu__decode__opcode_range_check__bit_9 * column3_row9
            {
                let val =((/*column8_row2*/ *borrow(&ctx, 196) - fmul(/*cpu__decode__opcode_range_check__bit_9*/ cpu__decode__opcode_range_check__bit_9, /*column3_row9*/ *borrow(&ctx, 100))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 383));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_pc/tmp1: column8_row10 - column8_row2 * column8_row12
            {
                let val =((/*column8_row10*/ *borrow(&ctx, 202) - fmul(/*column8_row2*/ *borrow(&ctx, 196), /*column8_row12*/ *borrow(&ctx, 203))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 383));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_pc/pc_cond_negative: (1 - cpu__decode__opcode_range_check__bit_9) * column3_row16 + column8_row2 * (column3_row16 - (column3_row0 + column3_row13)) - (cpu__decode__flag_pc_update_regular_0 * npc_reg_0 + cpu__decode__opcode_range_check__bit_7 * column8_row12 + cpu__decode__opcode_range_check__bit_8 * (column3_row0 + column8_row12))
            {
                let val =((((fmul(((1 - /*cpu__decode__opcode_range_check__bit_9*/ cpu__decode__opcode_range_check__bit_9) % PRIME), /*column3_row16*/ *borrow(&ctx, 105)) + fmul(/*column8_row2*/ *borrow(&ctx, 196), ((/*column3_row16*/ *borrow(&ctx, 105) - ((/*column3_row0*/ *borrow(&ctx, 91) + /*column3_row13*/ *borrow(&ctx, 104)) % PRIME)) % PRIME))) % PRIME) - ((((fmul(/*cpu__decode__flag_pc_update_regular_0*/ cpu__decode__flag_pc_update_regular_0, /*npc_reg_0*/ npc_reg_0) + fmul(/*cpu__decode__opcode_range_check__bit_7*/ cpu__decode__opcode_range_check__bit_7, /*column8_row12*/ *borrow(&ctx, 203))) % PRIME) + fmul(/*cpu__decode__opcode_range_check__bit_8*/ cpu__decode__opcode_range_check__bit_8, ((/*column3_row0*/ *borrow(&ctx, 91) + /*column8_row12*/ *borrow(&ctx, 203)) % PRIME))) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 383));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_pc/pc_cond_positive: (column8_row10 - cpu__decode__opcode_range_check__bit_9) * (column3_row16 - npc_reg_0)
            {
                let val =fmul(((/*column8_row10*/ *borrow(&ctx, 202) - /*cpu__decode__opcode_range_check__bit_9*/ cpu__decode__opcode_range_check__bit_9) % PRIME), ((/*column3_row16*/ *borrow(&ctx, 105) - /*npc_reg_0*/ npc_reg_0) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 383));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_ap/ap_update: column8_row16 - (column8_row0 + cpu__decode__opcode_range_check__bit_10 * column8_row12 + cpu__decode__opcode_range_check__bit_11 + cpu__decode__opcode_range_check__bit_12 * 2)
            {
                let val =((/*column8_row16*/ *borrow(&ctx, 206) - ((((((/*column8_row0*/ *borrow(&ctx, 194) + fmul(/*cpu__decode__opcode_range_check__bit_10*/ cpu__decode__opcode_range_check__bit_10, /*column8_row12*/ *borrow(&ctx, 203))) % PRIME) + /*cpu__decode__opcode_range_check__bit_11*/ cpu__decode__opcode_range_check__bit_11) % PRIME) + fmul(/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12, 2)) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 383));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/update_registers/update_fp/fp_update: column8_row24 - (cpu__decode__fp_update_regular_0 * column8_row8 + cpu__decode__opcode_range_check__bit_13 * column3_row9 + cpu__decode__opcode_range_check__bit_12 * (column8_row0 + 2))
            {
                let val =((/*column8_row24*/ *borrow(&ctx, 209) - ((((fmul(/*cpu__decode__fp_update_regular_0*/ cpu__decode__fp_update_regular_0, /*column8_row8*/ *borrow(&ctx, 200)) + fmul(/*cpu__decode__opcode_range_check__bit_13*/ cpu__decode__opcode_range_check__bit_13, /*column3_row9*/ *borrow(&ctx, 100))) % PRIME) + fmul(/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12, ((/*column8_row0*/ *borrow(&ctx, 194) + 2) % PRIME))) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 383));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/push_fp: cpu__decode__opcode_range_check__bit_12 * (column3_row9 - column8_row8)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12, ((/*column3_row9*/ *borrow(&ctx, 100) - /*column8_row8*/ *borrow(&ctx, 200)) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/push_pc: cpu__decode__opcode_range_check__bit_12 * (column3_row5 - npc_reg_0)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12, ((/*column3_row5*/ *borrow(&ctx, 96) - /*npc_reg_0*/ npc_reg_0) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/off0: cpu__decode__opcode_range_check__bit_12 * (column6_row0 - half_offset_size)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12, ((/*column6_row0*/ *borrow(&ctx, 147) - /*half_offset_size*/ half_offset_size) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/off1: cpu__decode__opcode_range_check__bit_12 * (column6_row8 - (half_offset_size + 1))
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12, ((/*column6_row8*/ *borrow(&ctx, 155) - ((/*half_offset_size*/ half_offset_size + 1) % PRIME)) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/call/flags: cpu__decode__opcode_range_check__bit_12 * (cpu__decode__opcode_range_check__bit_12 + cpu__decode__opcode_range_check__bit_12 + 1 + 1 - (cpu__decode__opcode_range_check__bit_0 + cpu__decode__opcode_range_check__bit_1 + 4))
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12, ((((((((/*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12 + /*cpu__decode__opcode_range_check__bit_12*/ cpu__decode__opcode_range_check__bit_12) % PRIME) + 1) % PRIME) + 1) % PRIME) - ((((/*cpu__decode__opcode_range_check__bit_0*/ cpu__decode__opcode_range_check__bit_0 + /*cpu__decode__opcode_range_check__bit_1*/ cpu__decode__opcode_range_check__bit_1) % PRIME) + 4) % PRIME)) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/ret/off0: cpu__decode__opcode_range_check__bit_13 * (column6_row0 + 2 - half_offset_size)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_13*/ cpu__decode__opcode_range_check__bit_13, ((((/*column6_row0*/ *borrow(&ctx, 147) + 2) % PRIME) - /*half_offset_size*/ half_offset_size) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/ret/off2: cpu__decode__opcode_range_check__bit_13 * (column6_row4 + 1 - half_offset_size)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_13*/ cpu__decode__opcode_range_check__bit_13, ((((/*column6_row4*/ *borrow(&ctx, 151) + 1) % PRIME) - /*half_offset_size*/ half_offset_size) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/ret/flags: cpu__decode__opcode_range_check__bit_13 * (cpu__decode__opcode_range_check__bit_7 + cpu__decode__opcode_range_check__bit_0 + cpu__decode__opcode_range_check__bit_3 + cpu__decode__flag_res_op1_0 - 4)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_13*/ cpu__decode__opcode_range_check__bit_13, ((((((((/*cpu__decode__opcode_range_check__bit_7*/ cpu__decode__opcode_range_check__bit_7 + /*cpu__decode__opcode_range_check__bit_0*/ cpu__decode__opcode_range_check__bit_0) % PRIME) + /*cpu__decode__opcode_range_check__bit_3*/ cpu__decode__opcode_range_check__bit_3) % PRIME) + /*cpu__decode__flag_res_op1_0*/ cpu__decode__flag_res_op1_0) % PRIME) - 4) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for cpu/opcodes/assert_eq/assert_eq: cpu__decode__opcode_range_check__bit_14 * (column3_row9 - column8_row12)
            {
                let val =fmul(/*cpu__decode__opcode_range_check__bit_14*/ cpu__decode__opcode_range_check__bit_14, ((/*column3_row9*/ *borrow(&ctx, 100) - /*column8_row12*/ *borrow(&ctx, 203)) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for initial_ap: column8_row0 - initial_ap
            {
                let val =((/*column8_row0*/ *borrow(&ctx, 194) - /*initial_ap*/ initial_ap) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for initial_fp: column8_row8 - initial_ap
            {
                let val =((/*column8_row8*/ *borrow(&ctx, 200) - /*initial_ap*/ initial_ap) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for initial_pc: column3_row0 - initial_pc
            {
                let val =((/*column3_row0*/ *borrow(&ctx, 91) - /*initial_pc*/ initial_pc) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for final_ap: column8_row0 - final_ap
            {
                let val =((/*column8_row0*/ *borrow(&ctx, 194) - /*final_ap*/ final_ap) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 365));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for final_fp: column8_row8 - initial_ap
            {
                let val =((/*column8_row8*/ *borrow(&ctx, 200) - /*initial_ap*/ initial_ap) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 365));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for final_pc: column3_row0 - final_pc
            {
                let val =((/*column3_row0*/ *borrow(&ctx, 91) - /*final_pc*/ final_pc) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 365));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/multi_column_perm/perm/init0: (memory__multi_column_perm__perm__interaction_elm - (column4_row0 + memory__multi_column_perm__hash_interaction_elm0 * column4_row1)) * column11_inter1_row0 + column3_row0 + memory__multi_column_perm__hash_interaction_elm0 * column3_row1 - memory__multi_column_perm__perm__interaction_elm
            {
                let val =((((((fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm - ((/*column4_row0*/ *borrow(&ctx, 133) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column4_row1*/ *borrow(&ctx, 134))) % PRIME)) % PRIME), /*column11_inter1_row0*/ *borrow(&ctx, 230)) + /*column3_row0*/ *borrow(&ctx, 91)) % PRIME) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column3_row1*/ *borrow(&ctx, 92))) % PRIME) - /*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/multi_column_perm/perm/step0: (memory__multi_column_perm__perm__interaction_elm - (column4_row2 + memory__multi_column_perm__hash_interaction_elm0 * column4_row3)) * column11_inter1_row2 - (memory__multi_column_perm__perm__interaction_elm - (column3_row2 + memory__multi_column_perm__hash_interaction_elm0 * column3_row3)) * column11_inter1_row0
            {
                let val =((fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm - ((/*column4_row2*/ *borrow(&ctx, 135) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column4_row3*/ *borrow(&ctx, 136))) % PRIME)) % PRIME), /*column11_inter1_row2*/ *borrow(&ctx, 232)) - fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm - ((/*column3_row2*/ *borrow(&ctx, 93) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column3_row3*/ *borrow(&ctx, 94))) % PRIME)) % PRIME), /*column11_inter1_row0*/ *borrow(&ctx, 230))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 386));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 367));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/multi_column_perm/perm/last: column11_inter1_row0 - memory__multi_column_perm__perm__public_memory_prod
            {
                let val =((/*column11_inter1_row0*/ *borrow(&ctx, 230) - /*memory__multi_column_perm__perm__public_memory_prod*/ memory__multi_column_perm__perm__public_memory_prod) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 368));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/diff_is_bit: memory__address_diff_0 * memory__address_diff_0 - memory__address_diff_0
            {
                let val =((fmul(/*memory__address_diff_0*/ memory__address_diff_0, /*memory__address_diff_0*/ memory__address_diff_0) - /*memory__address_diff_0*/ memory__address_diff_0) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 386));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 367));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/is_func: (memory__address_diff_0 - 1) * (column4_row1 - column4_row3)
            {
                let val =fmul(((/*memory__address_diff_0*/ memory__address_diff_0 - 1) % PRIME), ((/*column4_row1*/ *borrow(&ctx, 134) - /*column4_row3*/ *borrow(&ctx, 136)) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 386));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 367));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for memory/initial_addr: column4_row0 - 1
            {
                let val =((/*column4_row0*/ *borrow(&ctx, 133) - 1) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for public_memory_addr_zero: column3_row2
            {
                let val =/*column3_row2*/ *borrow(&ctx, 93);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for public_memory_value_zero: column3_row3
            {
                let val =/*column3_row3*/ *borrow(&ctx, 94);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/perm/init0: (range_check16__perm__interaction_elm - column6_row2) * column11_inter1_row1 + column6_row0 - range_check16__perm__interaction_elm
            {
                let val =((((fmul(((/*range_check16__perm__interaction_elm*/ range_check16__perm__interaction_elm - /*column6_row2*/ *borrow(&ctx, 149)) % PRIME), /*column11_inter1_row1*/ *borrow(&ctx, 231)) + /*column6_row0*/ *borrow(&ctx, 147)) % PRIME) - /*range_check16__perm__interaction_elm*/ range_check16__perm__interaction_elm) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/perm/step0: (range_check16__perm__interaction_elm - column6_row6) * column11_inter1_row5 - (range_check16__perm__interaction_elm - column6_row4) * column11_inter1_row1
            {
                let val =((fmul(((/*range_check16__perm__interaction_elm*/ range_check16__perm__interaction_elm - /*column6_row6*/ *borrow(&ctx, 153)) % PRIME), /*column11_inter1_row5*/ *borrow(&ctx, 233)) - fmul(((/*range_check16__perm__interaction_elm*/ range_check16__perm__interaction_elm - /*column6_row4*/ *borrow(&ctx, 151)) % PRIME), /*column11_inter1_row1*/ *borrow(&ctx, 231))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 388));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/perm/last: column11_inter1_row1 - range_check16__perm__public_memory_prod
            {
                let val =((/*column11_inter1_row1*/ *borrow(&ctx, 231) - /*range_check16__perm__public_memory_prod*/ range_check16__perm__public_memory_prod) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 370));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/diff_is_bit: range_check16__diff_0 * range_check16__diff_0 - range_check16__diff_0
            {
                let val =((fmul(/*range_check16__diff_0*/ range_check16__diff_0, /*range_check16__diff_0*/ range_check16__diff_0) - /*range_check16__diff_0*/ range_check16__diff_0) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 388));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/minimum: column6_row2 - range_check_min
            {
                let val =((/*column6_row2*/ *borrow(&ctx, 149) - /*range_check_min*/ range_check_min) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check16/maximum: column6_row2 - range_check_max
            {
                let val =((/*column6_row2*/ *borrow(&ctx, 149) - /*range_check_max*/ range_check_max) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 370));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/permutation/init0: (diluted_check__permutation__interaction_elm - column2_row0) * column10_inter1_row0 + column1_row0 - diluted_check__permutation__interaction_elm
            {
                let val =((((fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm - /*column2_row0*/ *borrow(&ctx, 89)) % PRIME), /*column10_inter1_row0*/ *borrow(&ctx, 228)) + /*column1_row0*/ *borrow(&ctx, 58)) % PRIME) - /*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/permutation/step0: (diluted_check__permutation__interaction_elm - column2_row1) * column10_inter1_row1 - (diluted_check__permutation__interaction_elm - column1_row1) * column10_inter1_row0
            {
                let val =((fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm - /*column2_row1*/ *borrow(&ctx, 90)) % PRIME), /*column10_inter1_row1*/ *borrow(&ctx, 229)) - fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm - /*column1_row1*/ *borrow(&ctx, 59)) % PRIME), /*column10_inter1_row0*/ *borrow(&ctx, 228))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 389));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 362));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/permutation/last: column10_inter1_row0 - diluted_check__permutation__public_memory_prod
            {
                let val =((/*column10_inter1_row0*/ *borrow(&ctx, 228) - /*diluted_check__permutation__public_memory_prod*/ diluted_check__permutation__public_memory_prod) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 371));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/init: column9_inter1_row0 - 1
            {
                let val =((/*column9_inter1_row0*/ *borrow(&ctx, 226) - 1) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/first_element: column2_row0 - diluted_check__first_elm
            {
                let val =((/*column2_row0*/ *borrow(&ctx, 89) - /*diluted_check__first_elm*/ diluted_check__first_elm) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/step: column9_inter1_row1 - (column9_inter1_row0 * (1 + diluted_check__interaction_z * (column2_row1 - column2_row0)) + diluted_check__interaction_alpha * (column2_row1 - column2_row0) * (column2_row1 - column2_row0))
            {
                let val =((/*column9_inter1_row1*/ *borrow(&ctx, 227) - ((fmul(/*column9_inter1_row0*/ *borrow(&ctx, 226), ((1 + fmul(/*diluted_check__interaction_z*/ diluted_check__interaction_z, ((/*column2_row1*/ *borrow(&ctx, 90) - /*column2_row0*/ *borrow(&ctx, 89)) % PRIME))) % PRIME)) + fmul(fmul(/*diluted_check__interaction_alpha*/ diluted_check__interaction_alpha, ((/*column2_row1*/ *borrow(&ctx, 90) - /*column2_row0*/ *borrow(&ctx, 89)) % PRIME)), ((/*column2_row1*/ *borrow(&ctx, 90) - /*column2_row0*/ *borrow(&ctx, 89)) % PRIME))) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 389));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 362));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for diluted_check/last: column9_inter1_row0 - diluted_check__final_cum_val
            {
                let val =((/*column9_inter1_row0*/ *borrow(&ctx, 226) - /*diluted_check__final_cum_val*/ diluted_check__final_cum_val) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 371));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/last_one_is_zero: column7_row89 * pedersen__hash0__ec_subset_sum__bit_0
            {
                let val =fmul(/*column7_row89*/ *borrow(&ctx, 185), /*pedersen__hash0__ec_subset_sum__bit_0*/ pedersen__hash0__ec_subset_sum__bit_0);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 372));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones0: column7_row89 * (column7_row4 - 3138550867693340381917894711603833208051177722232017256448 * column7_row768)
            {
                let val =fmul(/*column7_row89*/ *borrow(&ctx, 185), ((/*column7_row4*/ *borrow(&ctx, 173) - fmul(3138550867693340381917894711603833208051177722232017256448, /*column7_row768*/ *borrow(&ctx, 186))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 372));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit192: column7_row89 - column7_row1022 * (column7_row768 - (column7_row772 + column7_row772))
            {
                let val =((/*column7_row89*/ *borrow(&ctx, 185) - fmul(/*column7_row1022*/ *borrow(&ctx, 192), ((/*column7_row768*/ *borrow(&ctx, 186) - ((/*column7_row772*/ *borrow(&ctx, 187) + /*column7_row772*/ *borrow(&ctx, 187)) % PRIME)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 372));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones192: column7_row1022 * (column7_row772 - 8 * column7_row784)
            {
                let val =fmul(/*column7_row1022*/ *borrow(&ctx, 192), ((/*column7_row772*/ *borrow(&ctx, 187) - fmul(8, /*column7_row784*/ *borrow(&ctx, 188))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 372));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit196: column7_row1022 - (column7_row1004 - (column7_row1008 + column7_row1008)) * (column7_row784 - (column7_row788 + column7_row788))
            {
                let val =((/*column7_row1022*/ *borrow(&ctx, 192) - fmul(((/*column7_row1004*/ *borrow(&ctx, 190) - ((/*column7_row1008*/ *borrow(&ctx, 191) + /*column7_row1008*/ *borrow(&ctx, 191)) % PRIME)) % PRIME), ((/*column7_row784*/ *borrow(&ctx, 188) - ((/*column7_row788*/ *borrow(&ctx, 189) + /*column7_row788*/ *borrow(&ctx, 189)) % PRIME)) % PRIME))) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 372));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones196: (column7_row1004 - (column7_row1008 + column7_row1008)) * (column7_row788 - 18014398509481984 * column7_row1004)
            {
                let val =fmul(((/*column7_row1004*/ *borrow(&ctx, 190) - ((/*column7_row1008*/ *borrow(&ctx, 191) + /*column7_row1008*/ *borrow(&ctx, 191)) % PRIME)) % PRIME), ((/*column7_row788*/ *borrow(&ctx, 189) - fmul(18014398509481984, /*column7_row1004*/ *borrow(&ctx, 190))) % PRIME));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 372));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/booleanity_test: pedersen__hash0__ec_subset_sum__bit_0 * (pedersen__hash0__ec_subset_sum__bit_0 - 1)
            {
                let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ pedersen__hash0__ec_subset_sum__bit_0, ((/*pedersen__hash0__ec_subset_sum__bit_0*/ pedersen__hash0__ec_subset_sum__bit_0 - 1) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 391));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/bit_extraction_end: column7_row0
            {
                let val =/*column7_row0*/ *borrow(&ctx, 169);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 374));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/zeros_tail: column7_row0
            {
                let val =/*column7_row0*/ *borrow(&ctx, 169);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 373));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/add_points/slope: pedersen__hash0__ec_subset_sum__bit_0 * (column6_row3 - pedersen__points__y) - column7_row2 * (column6_row1 - pedersen__points__x)
            {
                let val =((fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ pedersen__hash0__ec_subset_sum__bit_0, ((/*column6_row3*/ *borrow(&ctx, 150) - /*pedersen__points__y*/ pedersen__points__y) % PRIME)) - fmul(/*column7_row2*/ *borrow(&ctx, 171), ((/*column6_row1*/ *borrow(&ctx, 148) - /*pedersen__points__x*/ pedersen__points__x) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 391));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/add_points/x: column7_row2 * column7_row2 - pedersen__hash0__ec_subset_sum__bit_0 * (column6_row1 + pedersen__points__x + column6_row5)
            {
                let val =((fmul(/*column7_row2*/ *borrow(&ctx, 171), /*column7_row2*/ *borrow(&ctx, 171)) - fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ pedersen__hash0__ec_subset_sum__bit_0, ((((/*column6_row1*/ *borrow(&ctx, 148) + /*pedersen__points__x*/ pedersen__points__x) % PRIME) + /*column6_row5*/ *borrow(&ctx, 152)) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 391));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/add_points/y: pedersen__hash0__ec_subset_sum__bit_0 * (column6_row3 + column6_row7) - column7_row2 * (column6_row1 - column6_row5)
            {
                let val =((fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ pedersen__hash0__ec_subset_sum__bit_0, ((/*column6_row3*/ *borrow(&ctx, 150) + /*column6_row7*/ *borrow(&ctx, 154)) % PRIME)) - fmul(/*column7_row2*/ *borrow(&ctx, 171), ((/*column6_row1*/ *borrow(&ctx, 148) - /*column6_row5*/ *borrow(&ctx, 152)) % PRIME))) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 391));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/copy_point/x: pedersen__hash0__ec_subset_sum__bit_neg_0 * (column6_row5 - column6_row1)
            {
                let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_neg_0*/ pedersen__hash0__ec_subset_sum__bit_neg_0, ((/*column6_row5*/ *borrow(&ctx, 152) - /*column6_row1*/ *borrow(&ctx, 148)) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 391));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/ec_subset_sum/copy_point/y: pedersen__hash0__ec_subset_sum__bit_neg_0 * (column6_row7 - column6_row3)
            {
                let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_neg_0*/ pedersen__hash0__ec_subset_sum__bit_neg_0, ((/*column6_row7*/ *borrow(&ctx, 154) - /*column6_row3*/ *borrow(&ctx, 150)) % PRIME));
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 391));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/copy_point/x: column6_row1025 - column6_row1021
            {
                let val =((/*column6_row1025*/ *borrow(&ctx, 166) - /*column6_row1021*/ *borrow(&ctx, 164)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 352));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 372));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/copy_point/y: column6_row1027 - column6_row1023
            {
                let val =((/*column6_row1027*/ *borrow(&ctx, 167) - /*column6_row1023*/ *borrow(&ctx, 165)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 352));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 372));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/init/x: column6_row1 - pedersen__shift_point.x
            {
                let val =((/*column6_row1*/ *borrow(&ctx, 148) - /*pedersen__shift_point__x*/ pedersen__shift_point__x) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 375));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/hash0/init/y: column6_row3 - pedersen__shift_point.y
            {
                let val =((/*column6_row3*/ *borrow(&ctx, 150) - /*pedersen__shift_point__y*/ pedersen__shift_point__y) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 375));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/input0_value0: column3_row11 - column7_row0
            {
                let val =((/*column3_row11*/ *borrow(&ctx, 102) - /*column7_row0*/ *borrow(&ctx, 169)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 375));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/input0_addr: column3_row2058 - (column3_row522 + 1)
            {
                let val =((/*column3_row2058*/ *borrow(&ctx, 132) - ((/*column3_row522*/ *borrow(&ctx, 128) + 1) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 359));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 375));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/init_addr: column3_row10 - initial_pedersen_addr
            {
                let val =((/*column3_row10*/ *borrow(&ctx, 101) - /*initial_pedersen_addr*/ initial_pedersen_addr) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/input1_value0: column3_row1035 - column7_row1024
            {
                let val =((/*column3_row1035*/ *borrow(&ctx, 131) - /*column7_row1024*/ *borrow(&ctx, 193)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 375));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/input1_addr: column3_row1034 - (column3_row10 + 1)
            {
                let val =((/*column3_row1034*/ *borrow(&ctx, 130) - ((/*column3_row10*/ *borrow(&ctx, 101) + 1) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 375));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/output_value0: column3_row523 - column6_row2045
            {
                let val =((/*column3_row523*/ *borrow(&ctx, 129) - /*column6_row2045*/ *borrow(&ctx, 168)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 375));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for pedersen/output_addr: column3_row522 - (column3_row1034 + 1)
            {
                let val =((/*column3_row522*/ *borrow(&ctx, 128) - ((/*column3_row1034*/ *borrow(&ctx, 130) + 1) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 375));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check_builtin/value: range_check_builtin__value7_0 - column3_row75
            {
                let val =((/*range_check_builtin__value7_0*/ range_check_builtin__value7_0 - /*column3_row75*/ *borrow(&ctx, 118)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check_builtin/addr_step: column3_row202 - (column3_row74 + 1)
            {
                let val =((/*column3_row202*/ *borrow(&ctx, 127) - ((/*column3_row74*/ *borrow(&ctx, 117) + 1) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 360));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for range_check_builtin/init_addr: column3_row74 - initial_range_check_addr
            {
                let val =((/*column3_row74*/ *borrow(&ctx, 117) - /*initial_range_check_addr*/ initial_range_check_addr) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/init_var_pool_addr: column3_row26 - initial_bitwise_addr
            {
                let val =((/*column3_row26*/ *borrow(&ctx, 108) - /*initial_bitwise_addr*/ initial_bitwise_addr) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/step_var_pool_addr: column3_row58 - (column3_row26 + 1)
            {
                let val =((/*column3_row58*/ *borrow(&ctx, 114) - ((/*column3_row26*/ *borrow(&ctx, 108) + 1) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 343));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 377));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/x_or_y_addr: column3_row42 - (column3_row122 + 1)
            {
                let val =((/*column3_row42*/ *borrow(&ctx, 112) - ((/*column3_row122*/ *borrow(&ctx, 124) + 1) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/next_var_pool_addr: column3_row154 - (column3_row42 + 1)
            {
                let val =((/*column3_row154*/ *borrow(&ctx, 126) - ((/*column3_row42*/ *borrow(&ctx, 112) + 1) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 360));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/partition: bitwise__sum_var_0_0 + bitwise__sum_var_8_0 - column3_row27
            {
                let val =((((/*bitwise__sum_var_0_0*/ bitwise__sum_var_0_0 + /*bitwise__sum_var_8_0*/ bitwise__sum_var_8_0) % PRIME) - /*column3_row27*/ *borrow(&ctx, 109)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 377));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/or_is_and_plus_xor: column3_row43 - (column3_row91 + column3_row123)
            {
                let val =((/*column3_row43*/ *borrow(&ctx, 113) - ((/*column3_row91*/ *borrow(&ctx, 121) + /*column3_row123*/ *borrow(&ctx, 125)) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/addition_is_xor_with_and: column1_row0 + column1_row32 - (column1_row96 + column1_row64 + column1_row64)
            {
                let val =((((/*column1_row0*/ *borrow(&ctx, 58) + /*column1_row32*/ *borrow(&ctx, 75)) % PRIME) - ((((/*column1_row96*/ *borrow(&ctx, 83) + /*column1_row64*/ *borrow(&ctx, 77)) % PRIME) + /*column1_row64*/ *borrow(&ctx, 77)) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 378));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/unique_unpacking192: (column1_row88 + column1_row120) * 16 - column1_row1
            {
                let val =((fmul(((/*column1_row88*/ *borrow(&ctx, 79) + /*column1_row120*/ *borrow(&ctx, 85)) % PRIME), 16) - /*column1_row1*/ *borrow(&ctx, 59)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/unique_unpacking193: (column1_row90 + column1_row122) * 16 - column1_row65
            {
                let val =((fmul(((/*column1_row90*/ *borrow(&ctx, 80) + /*column1_row122*/ *borrow(&ctx, 86)) % PRIME), 16) - /*column1_row65*/ *borrow(&ctx, 78)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/unique_unpacking194: (column1_row92 + column1_row124) * 16 - column1_row33
            {
                let val =((fmul(((/*column1_row92*/ *borrow(&ctx, 81) + /*column1_row124*/ *borrow(&ctx, 87)) % PRIME), 16) - /*column1_row33*/ *borrow(&ctx, 76)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for bitwise/unique_unpacking195: (column1_row94 + column1_row126) * 256 - column1_row97
            {
                let val =((fmul(((/*column1_row94*/ *borrow(&ctx, 82) + /*column1_row126*/ *borrow(&ctx, 88)) % PRIME), 256) - /*column1_row97*/ *borrow(&ctx, 84)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_0/init_input_output_addr: column3_row6 - initial_poseidon_addr
            {
                let val =((/*column3_row6*/ *borrow(&ctx, 97) - /*initial_poseidon_addr*/ initial_poseidon_addr) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_0/addr_input_output_step: column3_row70 - (column3_row6 + 3)
            {
                let val =((/*column3_row70*/ *borrow(&ctx, 115) - ((/*column3_row6*/ *borrow(&ctx, 97) + 3) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 361));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 379));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_1/init_input_output_addr: column3_row38 - (initial_poseidon_addr + 1)
            {
                let val =((/*column3_row38*/ *borrow(&ctx, 110) - ((/*initial_poseidon_addr*/ initial_poseidon_addr + 1) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_1/addr_input_output_step: column3_row102 - (column3_row38 + 3)
            {
                let val =((/*column3_row102*/ *borrow(&ctx, 122) - ((/*column3_row38*/ *borrow(&ctx, 110) + 3) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 361));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 379));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_2/init_input_output_addr: column3_row22 - (initial_poseidon_addr + 2)
            {
                let val =((/*column3_row22*/ *borrow(&ctx, 106) - ((/*initial_poseidon_addr*/ initial_poseidon_addr + 2) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 366));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/param_2/addr_input_output_step: column3_row86 - (column3_row22 + 3)
            {
                let val =((/*column3_row86*/ *borrow(&ctx, 119) - ((/*column3_row22*/ *borrow(&ctx, 106) + 3) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 361));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 379));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_rounds_state0_squaring: column8_row6 * column8_row6 - column8_row9
            {
                let val =((fmul(/*column8_row6*/ *borrow(&ctx, 199), /*column8_row6*/ *borrow(&ctx, 199)) - /*column8_row9*/ *borrow(&ctx, 201)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_rounds_state1_squaring: column8_row14 * column8_row14 - column8_row5
            {
                let val =((fmul(/*column8_row14*/ *borrow(&ctx, 205), /*column8_row14*/ *borrow(&ctx, 205)) - /*column8_row5*/ *borrow(&ctx, 198)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_rounds_state2_squaring: column8_row1 * column8_row1 - column8_row13
            {
                let val =((fmul(/*column8_row1*/ *borrow(&ctx, 195), /*column8_row1*/ *borrow(&ctx, 195)) - /*column8_row13*/ *borrow(&ctx, 204)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/partial_rounds_state0_squaring: column5_row0 * column5_row0 - column5_row1
            {
                let val =((fmul(/*column5_row0*/ *borrow(&ctx, 137), /*column5_row0*/ *borrow(&ctx, 137)) - /*column5_row1*/ *borrow(&ctx, 138)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 367));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/partial_rounds_state1_squaring: column7_row1 * column7_row1 - column7_row3
            {
                let val =((fmul(/*column7_row1*/ *borrow(&ctx, 170), /*column7_row1*/ *borrow(&ctx, 170)) - /*column7_row3*/ *borrow(&ctx, 172)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 346));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/add_first_round_key0: column3_row7 + 2950795762459345168613727575620414179244544320470208355568817838579231751791 - column8_row6
            {
                let val =((((/*column3_row7*/ *borrow(&ctx, 98) + 2950795762459345168613727575620414179244544320470208355568817838579231751791) % PRIME) - /*column8_row6*/ *borrow(&ctx, 199)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/add_first_round_key1: column3_row39 + 1587446564224215276866294500450702039420286416111469274423465069420553242820 - column8_row14
            {
                let val =((((/*column3_row39*/ *borrow(&ctx, 111) + 1587446564224215276866294500450702039420286416111469274423465069420553242820) % PRIME) - /*column8_row14*/ *borrow(&ctx, 205)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/add_first_round_key2: column3_row23 + 1645965921169490687904413452218868659025437693527479459426157555728339600137 - column8_row1
            {
                let val =((((/*column3_row23*/ *borrow(&ctx, 107) + 1645965921169490687904413452218868659025437693527479459426157555728339600137) % PRIME) - /*column8_row1*/ *borrow(&ctx, 195)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_round0: column8_row22 - (poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state1_cubed_0 + poseidon__poseidon__full_rounds_state2_cubed_0 + poseidon__poseidon__full_round_key0)
            {
                let val =((/*column8_row22*/ *borrow(&ctx, 208) - ((((((((((/*poseidon__poseidon__full_rounds_state0_cubed_0*/ poseidon__poseidon__full_rounds_state0_cubed_0 + /*poseidon__poseidon__full_rounds_state0_cubed_0*/ poseidon__poseidon__full_rounds_state0_cubed_0) % PRIME) + /*poseidon__poseidon__full_rounds_state0_cubed_0*/ poseidon__poseidon__full_rounds_state0_cubed_0) % PRIME) + /*poseidon__poseidon__full_rounds_state1_cubed_0*/ poseidon__poseidon__full_rounds_state1_cubed_0) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_0*/ poseidon__poseidon__full_rounds_state2_cubed_0) % PRIME) + /*poseidon__poseidon__full_round_key0*/ poseidon__poseidon__full_round_key0) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 341));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_round1: column8_row30 + poseidon__poseidon__full_rounds_state1_cubed_0 - (poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state2_cubed_0 + poseidon__poseidon__full_round_key1)
            {
                let val =((((/*column8_row30*/ *borrow(&ctx, 210) + /*poseidon__poseidon__full_rounds_state1_cubed_0*/ poseidon__poseidon__full_rounds_state1_cubed_0) % PRIME) - ((((/*poseidon__poseidon__full_rounds_state0_cubed_0*/ poseidon__poseidon__full_rounds_state0_cubed_0 + /*poseidon__poseidon__full_rounds_state2_cubed_0*/ poseidon__poseidon__full_rounds_state2_cubed_0) % PRIME) + /*poseidon__poseidon__full_round_key1*/ poseidon__poseidon__full_round_key1) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 341));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/full_round2: column8_row17 + poseidon__poseidon__full_rounds_state2_cubed_0 + poseidon__poseidon__full_rounds_state2_cubed_0 - (poseidon__poseidon__full_rounds_state0_cubed_0 + poseidon__poseidon__full_rounds_state1_cubed_0 + poseidon__poseidon__full_round_key2)
            {
                let val =((((((/*column8_row17*/ *borrow(&ctx, 207) + /*poseidon__poseidon__full_rounds_state2_cubed_0*/ poseidon__poseidon__full_rounds_state2_cubed_0) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_0*/ poseidon__poseidon__full_rounds_state2_cubed_0) % PRIME) - ((((/*poseidon__poseidon__full_rounds_state0_cubed_0*/ poseidon__poseidon__full_rounds_state0_cubed_0 + /*poseidon__poseidon__full_rounds_state1_cubed_0*/ poseidon__poseidon__full_rounds_state1_cubed_0) % PRIME) + /*poseidon__poseidon__full_round_key2*/ poseidon__poseidon__full_round_key2) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 341));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 364));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/last_full_round0: column3_row71 - (poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state1_cubed_7 + poseidon__poseidon__full_rounds_state2_cubed_7)
            {
                let val =((/*column3_row71*/ *borrow(&ctx, 116) - ((((((((/*poseidon__poseidon__full_rounds_state0_cubed_7*/ poseidon__poseidon__full_rounds_state0_cubed_7 + /*poseidon__poseidon__full_rounds_state0_cubed_7*/ poseidon__poseidon__full_rounds_state0_cubed_7) % PRIME) + /*poseidon__poseidon__full_rounds_state0_cubed_7*/ poseidon__poseidon__full_rounds_state0_cubed_7) % PRIME) + /*poseidon__poseidon__full_rounds_state1_cubed_7*/ poseidon__poseidon__full_rounds_state1_cubed_7) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_7*/ poseidon__poseidon__full_rounds_state2_cubed_7) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/last_full_round1: column3_row103 + poseidon__poseidon__full_rounds_state1_cubed_7 - (poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state2_cubed_7)
            {
                let val =((((/*column3_row103*/ *borrow(&ctx, 123) + /*poseidon__poseidon__full_rounds_state1_cubed_7*/ poseidon__poseidon__full_rounds_state1_cubed_7) % PRIME) - ((/*poseidon__poseidon__full_rounds_state0_cubed_7*/ poseidon__poseidon__full_rounds_state0_cubed_7 + /*poseidon__poseidon__full_rounds_state2_cubed_7*/ poseidon__poseidon__full_rounds_state2_cubed_7) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/last_full_round2: column3_row87 + poseidon__poseidon__full_rounds_state2_cubed_7 + poseidon__poseidon__full_rounds_state2_cubed_7 - (poseidon__poseidon__full_rounds_state0_cubed_7 + poseidon__poseidon__full_rounds_state1_cubed_7)
            {
                let val =((((((/*column3_row87*/ *borrow(&ctx, 120) + /*poseidon__poseidon__full_rounds_state2_cubed_7*/ poseidon__poseidon__full_rounds_state2_cubed_7) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_7*/ poseidon__poseidon__full_rounds_state2_cubed_7) % PRIME) - ((/*poseidon__poseidon__full_rounds_state0_cubed_7*/ poseidon__poseidon__full_rounds_state0_cubed_7 + /*poseidon__poseidon__full_rounds_state1_cubed_7*/ poseidon__poseidon__full_rounds_state1_cubed_7) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/copy_partial_rounds0_i0: column5_row122 - column7_row1
            {
                let val =((/*column5_row122*/ *borrow(&ctx, 144) - /*column7_row1*/ *borrow(&ctx, 170)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/copy_partial_rounds0_i1: column5_row124 - column7_row5
            {
                let val =((/*column5_row124*/ *borrow(&ctx, 145) - /*column7_row5*/ *borrow(&ctx, 174)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/copy_partial_rounds0_i2: column5_row126 - column7_row9
            {
                let val =((/*column5_row126*/ *borrow(&ctx, 146) - /*column7_row9*/ *borrow(&ctx, 176)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_full_to_partial0: column5_row0 + poseidon__poseidon__full_rounds_state2_cubed_3 + poseidon__poseidon__full_rounds_state2_cubed_3 - (poseidon__poseidon__full_rounds_state0_cubed_3 + poseidon__poseidon__full_rounds_state1_cubed_3 + 2121140748740143694053732746913428481442990369183417228688865837805149503386)
            {
                let val =((((((/*column5_row0*/ *borrow(&ctx, 137) + /*poseidon__poseidon__full_rounds_state2_cubed_3*/ poseidon__poseidon__full_rounds_state2_cubed_3) % PRIME) + /*poseidon__poseidon__full_rounds_state2_cubed_3*/ poseidon__poseidon__full_rounds_state2_cubed_3) % PRIME) - ((((/*poseidon__poseidon__full_rounds_state0_cubed_3*/ poseidon__poseidon__full_rounds_state0_cubed_3 + /*poseidon__poseidon__full_rounds_state1_cubed_3*/ poseidon__poseidon__full_rounds_state1_cubed_3) % PRIME) + 2121140748740143694053732746913428481442990369183417228688865837805149503386) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_full_to_partial1: column5_row2 - (3618502788666131213697322783095070105623107215331596699973092056135872020477 * poseidon__poseidon__full_rounds_state1_cubed_3 + 10 * poseidon__poseidon__full_rounds_state2_cubed_3 + 4 * column5_row0 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state0_cubed_0 + 2006642341318481906727563724340978325665491359415674592697055778067937914672)
            {
                let val =((/*column5_row2*/ *borrow(&ctx, 139) - ((((((((fmul(3618502788666131213697322783095070105623107215331596699973092056135872020477, /*poseidon__poseidon__full_rounds_state1_cubed_3*/ poseidon__poseidon__full_rounds_state1_cubed_3) + fmul(10, /*poseidon__poseidon__full_rounds_state2_cubed_3*/ poseidon__poseidon__full_rounds_state2_cubed_3)) % PRIME) + fmul(4, /*column5_row0*/ *borrow(&ctx, 137))) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state0_cubed_0*/ poseidon__poseidon__partial_rounds_state0_cubed_0)) % PRIME) + 2006642341318481906727563724340978325665491359415674592697055778067937914672) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_full_to_partial2: column5_row4 - (8 * poseidon__poseidon__full_rounds_state2_cubed_3 + 4 * column5_row0 + 6 * poseidon__poseidon__partial_rounds_state0_cubed_0 + column5_row2 + column5_row2 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state0_cubed_1 + 427751140904099001132521606468025610873158555767197326325930641757709538586)
            {
                let val =((/*column5_row4*/ *borrow(&ctx, 141) - ((((((((((((fmul(8, /*poseidon__poseidon__full_rounds_state2_cubed_3*/ poseidon__poseidon__full_rounds_state2_cubed_3) + fmul(4, /*column5_row0*/ *borrow(&ctx, 137))) % PRIME) + fmul(6, /*poseidon__poseidon__partial_rounds_state0_cubed_0*/ poseidon__poseidon__partial_rounds_state0_cubed_0)) % PRIME) + /*column5_row2*/ *borrow(&ctx, 139)) % PRIME) + /*column5_row2*/ *borrow(&ctx, 139)) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state0_cubed_1*/ poseidon__poseidon__partial_rounds_state0_cubed_1)) % PRIME) + 427751140904099001132521606468025610873158555767197326325930641757709538586) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/partial_round0: column5_row6 - (8 * poseidon__poseidon__partial_rounds_state0_cubed_0 + 4 * column5_row2 + 6 * poseidon__poseidon__partial_rounds_state0_cubed_1 + column5_row4 + column5_row4 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state0_cubed_2 + poseidon__poseidon__partial_round_key0)
            {
                let val =((/*column5_row6*/ *borrow(&ctx, 143) - ((((((((((((fmul(8, /*poseidon__poseidon__partial_rounds_state0_cubed_0*/ poseidon__poseidon__partial_rounds_state0_cubed_0) + fmul(4, /*column5_row2*/ *borrow(&ctx, 139))) % PRIME) + fmul(6, /*poseidon__poseidon__partial_rounds_state0_cubed_1*/ poseidon__poseidon__partial_rounds_state0_cubed_1)) % PRIME) + /*column5_row4*/ *borrow(&ctx, 141)) % PRIME) + /*column5_row4*/ *borrow(&ctx, 141)) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state0_cubed_2*/ poseidon__poseidon__partial_rounds_state0_cubed_2)) % PRIME) + /*poseidon__poseidon__partial_round_key0*/ poseidon__poseidon__partial_round_key0) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 347));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 367));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/partial_round1: column7_row13 - (8 * poseidon__poseidon__partial_rounds_state1_cubed_0 + 4 * column7_row5 + 6 * poseidon__poseidon__partial_rounds_state1_cubed_1 + column7_row9 + column7_row9 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state1_cubed_2 + poseidon__poseidon__partial_round_key1)
            {
                let val =((/*column7_row13*/ *borrow(&ctx, 178) - ((((((((((((fmul(8, /*poseidon__poseidon__partial_rounds_state1_cubed_0*/ poseidon__poseidon__partial_rounds_state1_cubed_0) + fmul(4, /*column7_row5*/ *borrow(&ctx, 174))) % PRIME) + fmul(6, /*poseidon__poseidon__partial_rounds_state1_cubed_1*/ poseidon__poseidon__partial_rounds_state1_cubed_1)) % PRIME) + /*column7_row9*/ *borrow(&ctx, 176)) % PRIME) + /*column7_row9*/ *borrow(&ctx, 176)) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state1_cubed_2*/ poseidon__poseidon__partial_rounds_state1_cubed_2)) % PRIME) + /*poseidon__poseidon__partial_round_key1*/ poseidon__poseidon__partial_round_key1) % PRIME)) % PRIME);
                // Numerator
                // val *= numerator
                val = fmul(val, *borrow(&ctx, 348));

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 369));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_partial_to_full0: column8_row70 - (16 * poseidon__poseidon__partial_rounds_state1_cubed_19 + 8 * column7_row81 + 16 * poseidon__poseidon__partial_rounds_state1_cubed_20 + 6 * column7_row85 + poseidon__poseidon__partial_rounds_state1_cubed_21 + 560279373700919169769089400651532183647886248799764942664266404650165812023)
            {
                let val =((/*column8_row70*/ *borrow(&ctx, 218) - ((((((((((fmul(16, /*poseidon__poseidon__partial_rounds_state1_cubed_19*/ poseidon__poseidon__partial_rounds_state1_cubed_19) + fmul(8, /*column7_row81*/ *borrow(&ctx, 181))) % PRIME) + fmul(16, /*poseidon__poseidon__partial_rounds_state1_cubed_20*/ poseidon__poseidon__partial_rounds_state1_cubed_20)) % PRIME) + fmul(6, /*column7_row85*/ *borrow(&ctx, 183))) % PRIME) + /*poseidon__poseidon__partial_rounds_state1_cubed_21*/ poseidon__poseidon__partial_rounds_state1_cubed_21) % PRIME) + 560279373700919169769089400651532183647886248799764942664266404650165812023) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_partial_to_full1: column8_row78 - (4 * poseidon__poseidon__partial_rounds_state1_cubed_20 + column7_row85 + column7_row85 + poseidon__poseidon__partial_rounds_state1_cubed_21 + 1401754474293352309994371631695783042590401941592571735921592823982231996415)
            {
                let val =((/*column8_row78*/ *borrow(&ctx, 219) - ((((((((fmul(4, /*poseidon__poseidon__partial_rounds_state1_cubed_20*/ poseidon__poseidon__partial_rounds_state1_cubed_20) + /*column7_row85*/ *borrow(&ctx, 183)) % PRIME) + /*column7_row85*/ *borrow(&ctx, 183)) % PRIME) + /*poseidon__poseidon__partial_rounds_state1_cubed_21*/ poseidon__poseidon__partial_rounds_state1_cubed_21) % PRIME) + 1401754474293352309994371631695783042590401941592571735921592823982231996415) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

            //Constraint expression for poseidon/poseidon/margin_partial_to_full2: column8_row65 - (8 * poseidon__poseidon__partial_rounds_state1_cubed_19 + 4 * column7_row81 + 6 * poseidon__poseidon__partial_rounds_state1_cubed_20 + column7_row85 + column7_row85 + 3618502788666131213697322783095070105623107215331596699973092056135872020479 * poseidon__poseidon__partial_rounds_state1_cubed_21 + 1246177936547655338400308396717835700699368047388302793172818304164989556526)
            {
                let val =((/*column8_row65*/ *borrow(&ctx, 217) - ((((((((((((fmul(8, /*poseidon__poseidon__partial_rounds_state1_cubed_19*/ poseidon__poseidon__partial_rounds_state1_cubed_19) + fmul(4, /*column7_row81*/ *borrow(&ctx, 181))) % PRIME) + fmul(6, /*poseidon__poseidon__partial_rounds_state1_cubed_20*/ poseidon__poseidon__partial_rounds_state1_cubed_20)) % PRIME) + /*column7_row85*/ *borrow(&ctx, 183)) % PRIME) + /*column7_row85*/ *borrow(&ctx, 183)) % PRIME) + fmul(3618502788666131213697322783095070105623107215331596699973092056135872020479, /*poseidon__poseidon__partial_rounds_state1_cubed_21*/ poseidon__poseidon__partial_rounds_state1_cubed_21)) % PRIME) + 1246177936547655338400308396717835700699368047388302793172818304164989556526) % PRIME)) % PRIME);

                // Denominator
                // val *= denominator inverse
                val = fmul(val, *borrow(&ctx, 376));

                res = (res + fmul(val, composition_alpha_pow)) % PRIME;
                composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

            };

        };
        res
    }
}
