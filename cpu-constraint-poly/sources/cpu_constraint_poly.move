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
    // [0x80, 0xa0) - trace_length
    // [0xa0, 0xc0) - offset_size
    // [0xc0, 0xe0) - half_offset_size
    // [0xe0, 0x100) - initial_ap
    // [0x100, 0x120) - initial_pc
    // [0x120, 0x140) - final_ap
    // [0x140, 0x160) - final_pc
    // [0x160, 0x180) - memory__multi_column_perm__perm__interaction_elm
    // [0x180, 0x1a0) - memory__multi_column_perm__hash_interaction_elm0
    // [0x1a0, 0x1c0) - memory__multi_column_perm__perm__public_memory_prod
    // [0x1c0, 0x1e0) - rc16__perm__interaction_elm
    // [0x1e0, 0x200) - rc16__perm__public_memory_prod
    // [0x200, 0x220) - rc_min
    // [0x220, 0x240) - rc_max
    // [0x240, 0x260) - diluted_check__permutation__interaction_elm
    // [0x260, 0x280) - diluted_check__permutation__public_memory_prod
    // [0x280, 0x2a0) - diluted_check__first_elm
    // [0x2a0, 0x2c0) - diluted_check__interaction_z
    // [0x2c0, 0x2e0) - diluted_check__interaction_alpha
    // [0x2e0, 0x300) - diluted_check__final_cum_val
    // [0x300, 0x320) - pedersen__shift_point__x
    // [0x320, 0x340) - pedersen__shift_point__y
    // [0x340, 0x360) - initial_pedersen_addr
    // [0x360, 0x380) - initial_rc_addr
    // [0x380, 0x3a0) - ecdsa__sig_config__alpha
    // [0x3a0, 0x3c0) - ecdsa__sig_config__shift_point__x
    // [0x3c0, 0x3e0) - ecdsa__sig_config__shift_point__y
    // [0x3e0, 0x400) - ecdsa__sig_config__beta
    // [0x400, 0x420) - initial_ecdsa_addr
    // [0x420, 0x440) - initial_bitwise_addr
    // [0x440, 0x460) - initial_ec_op_addr
    // [0x460, 0x480) - ec_op__curve_config__alpha
    // [0x480, 0x4a0) - trace_generator
    // [0x4a0, 0x4c0) - oods_point
    // [0x4c0, 0x580) - interaction_elements
    // [0x580, 0x1a60) - coefficients
    // [0x1a60, 0x34e0) - oods_values
    // [0x34e0, 0x3500) - cpu__decode__opcode_rc__bit_0
    // [0x3500, 0x3520) - cpu__decode__opcode_rc__bit_2
    // [0x3520, 0x3540) - cpu__decode__opcode_rc__bit_4
    // [0x3540, 0x3560) - cpu__decode__opcode_rc__bit_3
    // [0x3560, 0x3580) - cpu__decode__flag_op1_base_op0_0
    // [0x3580, 0x35a0) - cpu__decode__opcode_rc__bit_5
    // [0x35a0, 0x35c0) - cpu__decode__opcode_rc__bit_6
    // [0x35c0, 0x35e0) - cpu__decode__opcode_rc__bit_9
    // [0x35e0, 0x3600) - cpu__decode__flag_res_op1_0
    // [0x3600, 0x3620) - cpu__decode__opcode_rc__bit_7
    // [0x3620, 0x3640) - cpu__decode__opcode_rc__bit_8
    // [0x3640, 0x3660) - cpu__decode__flag_pc_update_regular_0
    // [0x3660, 0x3680) - cpu__decode__opcode_rc__bit_12
    // [0x3680, 0x36a0) - cpu__decode__opcode_rc__bit_13
    // [0x36a0, 0x36c0) - cpu__decode__fp_update_regular_0
    // [0x36c0, 0x36e0) - cpu__decode__opcode_rc__bit_1
    // [0x36e0, 0x3700) - npc_reg_0
    // [0x3700, 0x3720) - cpu__decode__opcode_rc__bit_10
    // [0x3720, 0x3740) - cpu__decode__opcode_rc__bit_11
    // [0x3740, 0x3760) - cpu__decode__opcode_rc__bit_14
    // [0x3760, 0x3780) - memory__address_diff_0
    // [0x3780, 0x37a0) - rc16__diff_0
    // [0x37a0, 0x37c0) - pedersen__hash0__ec_subset_sum__bit_0
    // [0x37c0, 0x37e0) - pedersen__hash0__ec_subset_sum__bit_neg_0
    // [0x37e0, 0x3800) - rc_builtin__value0_0
    // [0x3800, 0x3820) - rc_builtin__value1_0
    // [0x3820, 0x3840) - rc_builtin__value2_0
    // [0x3840, 0x3860) - rc_builtin__value3_0
    // [0x3860, 0x3880) - rc_builtin__value4_0
    // [0x3880, 0x38a0) - rc_builtin__value5_0
    // [0x38a0, 0x38c0) - rc_builtin__value6_0
    // [0x38c0, 0x38e0) - rc_builtin__value7_0
    // [0x38e0, 0x3900) - ecdsa__signature0__doubling_key__x_squared
    // [0x3900, 0x3920) - ecdsa__signature0__exponentiate_generator__bit_0
    // [0x3920, 0x3940) - ecdsa__signature0__exponentiate_generator__bit_neg_0
    // [0x3940, 0x3960) - ecdsa__signature0__exponentiate_key__bit_0
    // [0x3960, 0x3980) - ecdsa__signature0__exponentiate_key__bit_neg_0
    // [0x3980, 0x39a0) - bitwise__sum_var_0_0
    // [0x39a0, 0x39c0) - bitwise__sum_var_8_0
    // [0x39c0, 0x39e0) - ec_op__doubling_q__x_squared_0
    // [0x39e0, 0x3a00) - ec_op__ec_subset_sum__bit_0
    // [0x3a00, 0x3a20) - ec_op__ec_subset_sum__bit_neg_0
    // [0x3a20, 0x3f60) - expmods
    // [0x3f60, 0x4380) - domains
    // [0x4380, 0x46c0) - denominator_invs
    // [0x46c0, 0x4a00) - denominators
    // [0x4a00, 0x4ac0) - expmod_context


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
    let trace_length = *borrow(&ctx, 4);
    let offset_size = *borrow(&ctx, 5);
    let half_offset_size = *borrow(&ctx, 6);
    let initial_ap = *borrow(&ctx, 7);
    let initial_pc = *borrow(&ctx, 8);
    let final_ap = *borrow(&ctx, 9);
    let final_pc = *borrow(&ctx, 10);
    let memory__multi_column_perm__perm__interaction_elm = *borrow(&ctx, 11);
    let memory__multi_column_perm__hash_interaction_elm0 = *borrow(&ctx, 12);
    let memory__multi_column_perm__perm__public_memory_prod = *borrow(&ctx, 13);
    let rc16__perm__interaction_elm = *borrow(&ctx, 14);
    let rc16__perm__public_memory_prod = *borrow(&ctx, 15);
    let rc_min = *borrow(&ctx, 16);
    let rc_max = *borrow(&ctx, 17);
    let diluted_check__permutation__interaction_elm = *borrow(&ctx, 18);
    let diluted_check__permutation__public_memory_prod = *borrow(&ctx, 19);
    let diluted_check__first_elm = *borrow(&ctx, 20);
    let diluted_check__interaction_z = *borrow(&ctx, 21);
    let diluted_check__interaction_alpha = *borrow(&ctx, 22);
    let diluted_check__final_cum_val = *borrow(&ctx, 23);
    let pedersen__shift_point__x = *borrow(&ctx, 24);
    let pedersen__shift_point__y = *borrow(&ctx, 25);
    let initial_pedersen_addr = *borrow(&ctx, 26);
    let initial_rc_addr = *borrow(&ctx, 27);
    let ecdsa__sig_config__alpha = *borrow(&ctx, 28);
    let ecdsa__sig_config__shift_point__x = *borrow(&ctx, 29);
    let ecdsa__sig_config__shift_point__y = *borrow(&ctx, 30);
    let ecdsa__sig_config__beta = *borrow(&ctx, 31);
    let initial_ecdsa_addr = *borrow(&ctx, 32);
    let initial_bitwise_addr = *borrow(&ctx, 33);
    let initial_ec_op_addr = *borrow(&ctx, 34);
    let ec_op__curve_config__alpha = *borrow(&ctx, 35);
    let trace_generator = *borrow(&ctx, 36);
    let oods_point = *borrow(&ctx, 37);
    let interaction_elements = *borrow(&ctx, 38);
    let coefficients = *borrow(&ctx, 44);
    let oods_values = *borrow(&ctx, 211);
    let cpu__decode__opcode_rc__bit_0 = *borrow(&ctx, 423);
    let cpu__decode__opcode_rc__bit_2 = *borrow(&ctx, 424);
    let cpu__decode__opcode_rc__bit_4 = *borrow(&ctx, 425);
    let cpu__decode__opcode_rc__bit_3 = *borrow(&ctx, 426);
    let cpu__decode__flag_op1_base_op0_0 = *borrow(&ctx, 427);
    let cpu__decode__opcode_rc__bit_5 = *borrow(&ctx, 428);
    let cpu__decode__opcode_rc__bit_6 = *borrow(&ctx, 429);
    let cpu__decode__opcode_rc__bit_9 = *borrow(&ctx, 430);
    let cpu__decode__flag_res_op1_0 = *borrow(&ctx, 431);
    let cpu__decode__opcode_rc__bit_7 = *borrow(&ctx, 432);
    let cpu__decode__opcode_rc__bit_8 = *borrow(&ctx, 433);
    let cpu__decode__flag_pc_update_regular_0 = *borrow(&ctx, 434);
    let cpu__decode__opcode_rc__bit_12 = *borrow(&ctx, 435);
    let cpu__decode__opcode_rc__bit_13 = *borrow(&ctx, 436);
    let cpu__decode__fp_update_regular_0 = *borrow(&ctx, 437);
    let cpu__decode__opcode_rc__bit_1 = *borrow(&ctx, 438);
    let npc_reg_0 = *borrow(&ctx, 439);
    let cpu__decode__opcode_rc__bit_10 = *borrow(&ctx, 440);
    let cpu__decode__opcode_rc__bit_11 = *borrow(&ctx, 441);
    let cpu__decode__opcode_rc__bit_14 = *borrow(&ctx, 442);
    let memory__address_diff_0 = *borrow(&ctx, 443);
    let rc16__diff_0 = *borrow(&ctx, 444);
    let pedersen__hash0__ec_subset_sum__bit_0 = *borrow(&ctx, 445);
    let pedersen__hash0__ec_subset_sum__bit_neg_0 = *borrow(&ctx, 446);
    let rc_builtin__value0_0 = *borrow(&ctx, 447);
    let rc_builtin__value1_0 = *borrow(&ctx, 448);
    let rc_builtin__value2_0 = *borrow(&ctx, 449);
    let rc_builtin__value3_0 = *borrow(&ctx, 450);
    let rc_builtin__value4_0 = *borrow(&ctx, 451);
    let rc_builtin__value5_0 = *borrow(&ctx, 452);
    let rc_builtin__value6_0 = *borrow(&ctx, 453);
    let rc_builtin__value7_0 = *borrow(&ctx, 454);
    let ecdsa__signature0__doubling_key__x_squared = *borrow(&ctx, 455);
    let ecdsa__signature0__exponentiate_generator__bit_0 = *borrow(&ctx, 456);
    let ecdsa__signature0__exponentiate_generator__bit_neg_0 = *borrow(&ctx, 457);
    let ecdsa__signature0__exponentiate_key__bit_0 = *borrow(&ctx, 458);
    let ecdsa__signature0__exponentiate_key__bit_neg_0 = *borrow(&ctx, 459);
    let bitwise__sum_var_0_0 = *borrow(&ctx, 460);
    let bitwise__sum_var_8_0 = *borrow(&ctx, 461);
    let ec_op__doubling_q__x_squared_0 = *borrow(&ctx, 462);
    let ec_op__ec_subset_sum__bit_0 = *borrow(&ctx, 463);
    let ec_op__ec_subset_sum__bit_neg_0 = *borrow(&ctx, 464);
    let expmods = *borrow(&ctx, 465);
    let domains = *borrow(&ctx, 507);
    let denominator_invs = *borrow(&ctx, 540);
    let denominators = *borrow(&ctx, 566);
    let expmod_context = *borrow(&ctx, 592);


        let point = oods_point;

        {
            // compute expmods
            // expmods[0] = point^(trace_length / 32768)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 32768));
*borrow_mut(&mut ctx, 465) = val;
};
// expmods[1] = point^(trace_length / 16384)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 16384));
*borrow_mut(&mut ctx, 466) = val;
};
// expmods[2] = point^(trace_length / 1024)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 1024));
*borrow_mut(&mut ctx, 467) = val;
};
// expmods[3] = point^(trace_length / 512)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 512));
*borrow_mut(&mut ctx, 468) = val;
};
// expmods[4] = point^(trace_length / 256)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 256));
*borrow_mut(&mut ctx, 469) = val;
};
// expmods[5] = point^(trace_length / 128)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 128));
*borrow_mut(&mut ctx, 470) = val;
};
// expmods[6] = point^(trace_length / 64)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 64));
*borrow_mut(&mut ctx, 471) = val;
};
// expmods[7] = point^(trace_length / 16)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 16));
*borrow_mut(&mut ctx, 472) = val;
};
// expmods[8] = point^(trace_length / 8)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 8));
*borrow_mut(&mut ctx, 473) = val;
};
// expmods[9] = point^(trace_length / 4)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 4));
*borrow_mut(&mut ctx, 474) = val;
};
// expmods[10] = point^(trace_length / 2)
{
let val = fpow(/*point*/ point, (/*trace_length*/ trace_length / 2));
*borrow_mut(&mut ctx, 475) = val;
};
// expmods[11] = point^trace_length
{
let val = fpow(/*point*/ point, /*trace_length*/ trace_length);
*borrow_mut(&mut ctx, 476) = val;
};
// expmods[12] = trace_generator^(trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 64));
*borrow_mut(&mut ctx, 477) = val;
};
// expmods[13] = trace_generator^(trace_length / 32)
{
let val = fpow(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 32));
*borrow_mut(&mut ctx, 478) = val;
};
// expmods[14] = trace_generator^(3 * trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(3, /*trace_length*/ trace_length) / 64));
*borrow_mut(&mut ctx, 479) = val;
};
// expmods[15] = trace_generator^(trace_length / 16)
{
let val = fpow(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 16));
*borrow_mut(&mut ctx, 480) = val;
};
// expmods[16] = trace_generator^(5 * trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(5, /*trace_length*/ trace_length) / 64));
*borrow_mut(&mut ctx, 481) = val;
};
// expmods[17] = trace_generator^(3 * trace_length / 32)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(3, /*trace_length*/ trace_length) / 32));
*borrow_mut(&mut ctx, 482) = val;
};
// expmods[18] = trace_generator^(7 * trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(7, /*trace_length*/ trace_length) / 64));
*borrow_mut(&mut ctx, 483) = val;
};
// expmods[19] = trace_generator^(trace_length / 8)
{
let val = fpow(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 8));
*borrow_mut(&mut ctx, 484) = val;
};
// expmods[20] = trace_generator^(9 * trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(9, /*trace_length*/ trace_length) / 64));
*borrow_mut(&mut ctx, 485) = val;
};
// expmods[21] = trace_generator^(5 * trace_length / 32)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(5, /*trace_length*/ trace_length) / 32));
*borrow_mut(&mut ctx, 486) = val;
};
// expmods[22] = trace_generator^(11 * trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(11, /*trace_length*/ trace_length) / 64));
*borrow_mut(&mut ctx, 487) = val;
};
// expmods[23] = trace_generator^(3 * trace_length / 16)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(3, /*trace_length*/ trace_length) / 16));
*borrow_mut(&mut ctx, 488) = val;
};
// expmods[24] = trace_generator^(13 * trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(13, /*trace_length*/ trace_length) / 64));
*borrow_mut(&mut ctx, 489) = val;
};
// expmods[25] = trace_generator^(7 * trace_length / 32)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(7, /*trace_length*/ trace_length) / 32));
*borrow_mut(&mut ctx, 490) = val;
};
// expmods[26] = trace_generator^(15 * trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(15, /*trace_length*/ trace_length) / 64));
*borrow_mut(&mut ctx, 491) = val;
};
// expmods[27] = trace_generator^(trace_length / 2)
{
let val = fpow(/*trace_generator*/ trace_generator, (/*trace_length*/ trace_length / 2));
*borrow_mut(&mut ctx, 492) = val;
};
// expmods[28] = trace_generator^(3 * trace_length / 4)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(3, /*trace_length*/ trace_length) / 4));
*borrow_mut(&mut ctx, 493) = val;
};
// expmods[29] = trace_generator^(15 * trace_length / 16)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(15, /*trace_length*/ trace_length) / 16));
*borrow_mut(&mut ctx, 494) = val;
};
// expmods[30] = trace_generator^(251 * trace_length / 256)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(251, /*trace_length*/ trace_length) / 256));
*borrow_mut(&mut ctx, 495) = val;
};
// expmods[31] = trace_generator^(63 * trace_length / 64)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(63, /*trace_length*/ trace_length) / 64));
*borrow_mut(&mut ctx, 496) = val;
};
// expmods[32] = trace_generator^(255 * trace_length / 256)
{
let val = fpow(/*trace_generator*/ trace_generator, (fmul(255, /*trace_length*/ trace_length) / 256));
*borrow_mut(&mut ctx, 497) = val;
};
// expmods[33] = trace_generator^(16 * (trace_length / 16 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(16, (((/*trace_length*/ trace_length / 16) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 498) = val;
};
// expmods[34] = trace_generator^(2 * (trace_length / 2 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(2, (((/*trace_length*/ trace_length / 2) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 499) = val;
};
// expmods[35] = trace_generator^(4 * (trace_length / 4 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(4, (((/*trace_length*/ trace_length / 4) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 500) = val;
};
// expmods[36] = trace_generator^(8 * (trace_length / 8 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(8, (((/*trace_length*/ trace_length / 8) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 501) = val;
};
// expmods[37] = trace_generator^(512 * (trace_length / 512 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(512, (((/*trace_length*/ trace_length / 512) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 502) = val;
};
// expmods[38] = trace_generator^(256 * (trace_length / 256 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(256, (((/*trace_length*/ trace_length / 256) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 503) = val;
};
// expmods[39] = trace_generator^(32768 * (trace_length / 32768 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(32768, (((/*trace_length*/ trace_length / 32768) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 504) = val;
};
// expmods[40] = trace_generator^(1024 * (trace_length / 1024 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(1024, (((/*trace_length*/ trace_length / 1024) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 505) = val;
};
// expmods[41] = trace_generator^(16384 * (trace_length / 16384 - 1))
{
let val = fpow(/*trace_generator*/ trace_generator, fmul(16384, (((/*trace_length*/ trace_length / 16384) + (PRIME - 1)) % PRIME)));
*borrow_mut(&mut ctx, 506) = val;
};

        };

        {
            // compute domains
            // domains[0] = point^trace_length - 1
{
let val = ((/*(point^trace_length)*/ *borrow(&ctx, 476) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 507) = val;
};
// domains[1] = point^(trace_length / 2) - 1
{
let val = ((/*(point^(trace_length/2))*/ *borrow(&ctx, 475) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 508) = val;
};
// domains[2] = point^(trace_length / 4) - 1
{
let val = ((/*(point^(trace_length/4))*/ *borrow(&ctx, 474) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 509) = val;
};
// domains[3] = point^(trace_length / 8) - 1
{
let val = ((/*(point^(trace_length/8))*/ *borrow(&ctx, 473) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 510) = val;
};
// domains[4] = point^(trace_length / 16) - trace_generator^(15 * trace_length / 16)
{
let val = ((/*(point^(trace_length/16))*/ *borrow(&ctx, 472) + (PRIME - /*(trace_generator^((15*trace_length)/16))*/ *borrow(&ctx, 494))) % PRIME);
*borrow_mut(&mut ctx, 511) = val;
};
// domains[5] = point^(trace_length / 16) - 1
{
let val = ((/*(point^(trace_length/16))*/ *borrow(&ctx, 472) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 512) = val;
};
// domains[6] = point^(trace_length / 64) - 1
{
let val = ((/*(point^(trace_length/64))*/ *borrow(&ctx, 471) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 513) = val;
};
// domains[7] = point^(trace_length / 128) - 1
{
let val = ((/*(point^(trace_length/128))*/ *borrow(&ctx, 470) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 514) = val;
};
// domains[8] = point^(trace_length / 256) - 1
{
let val = ((/*(point^(trace_length/256))*/ *borrow(&ctx, 469) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 515) = val;
};
// domains[9] = point^(trace_length / 256) - trace_generator^(255 * trace_length / 256)
{
let val = ((/*(point^(trace_length/256))*/ *borrow(&ctx, 469) + (PRIME - /*(trace_generator^((255*trace_length)/256))*/ *borrow(&ctx, 497))) % PRIME);
*borrow_mut(&mut ctx, 516) = val;
};
// domains[10] = point^(trace_length / 256) - trace_generator^(63 * trace_length / 64)
{
let val = ((/*(point^(trace_length/256))*/ *borrow(&ctx, 469) + (PRIME - /*(trace_generator^((63*trace_length)/64))*/ *borrow(&ctx, 496))) % PRIME);
*borrow_mut(&mut ctx, 517) = val;
};
// domains[11] = point^(trace_length / 512) - trace_generator^(trace_length / 2)
{
let val = ((/*(point^(trace_length/512))*/ *borrow(&ctx, 468) + (PRIME - /*(trace_generator^(trace_length/2))*/ *borrow(&ctx, 492))) % PRIME);
*borrow_mut(&mut ctx, 518) = val;
};
// domains[12] = point^(trace_length / 512) - 1
{
let val = ((/*(point^(trace_length/512))*/ *borrow(&ctx, 468) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 519) = val;
};
// domains[13] = point^(trace_length / 1024) - trace_generator^(3 * trace_length / 4)
{
let val = ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((3*trace_length)/4))*/ *borrow(&ctx, 493))) % PRIME);
*borrow_mut(&mut ctx, 520) = val;
};
// domains[14] = point^(trace_length / 1024) - 1
{
let val = ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 521) = val;
};
// domains[15] = (point^(trace_length / 1024) - trace_generator^(trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(trace_length / 32)) * (point^(trace_length / 1024) - trace_generator^(3 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(trace_length / 16)) * (point^(trace_length / 1024) - trace_generator^(5 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(3 * trace_length / 32)) * (point^(trace_length / 1024) - trace_generator^(7 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(trace_length / 8)) * (point^(trace_length / 1024) - trace_generator^(9 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(5 * trace_length / 32)) * (point^(trace_length / 1024) - trace_generator^(11 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(3 * trace_length / 16)) * (point^(trace_length / 1024) - trace_generator^(13 * trace_length / 64)) * (point^(trace_length / 1024) - trace_generator^(7 * trace_length / 32)) * (point^(trace_length / 1024) - trace_generator^(15 * trace_length / 64)) * domain14
{
let val = fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(fmul(((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^(trace_length/64))*/ *borrow(&ctx, 477))) % PRIME), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^(trace_length/32))*/ *borrow(&ctx, 478))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((3*trace_length)/64))*/ *borrow(&ctx, 479))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^(trace_length/16))*/ *borrow(&ctx, 480))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((5*trace_length)/64))*/ *borrow(&ctx, 481))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((3*trace_length)/32))*/ *borrow(&ctx, 482))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((7*trace_length)/64))*/ *borrow(&ctx, 483))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^(trace_length/8))*/ *borrow(&ctx, 484))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((9*trace_length)/64))*/ *borrow(&ctx, 485))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((5*trace_length)/32))*/ *borrow(&ctx, 486))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((11*trace_length)/64))*/ *borrow(&ctx, 487))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((3*trace_length)/16))*/ *borrow(&ctx, 488))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((13*trace_length)/64))*/ *borrow(&ctx, 489))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((7*trace_length)/32))*/ *borrow(&ctx, 490))) % PRIME)), ((/*(point^(trace_length/1024))*/ *borrow(&ctx, 467) + (PRIME - /*(trace_generator^((15*trace_length)/64))*/ *borrow(&ctx, 491))) % PRIME)), /*domain14*/ *borrow(&ctx, 521));
*borrow_mut(&mut ctx, 522) = val;
};
// domains[16] = point^(trace_length / 16384) - trace_generator^(255 * trace_length / 256)
{
let val = ((/*(point^(trace_length/16384))*/ *borrow(&ctx, 466) + (PRIME - /*(trace_generator^((255*trace_length)/256))*/ *borrow(&ctx, 497))) % PRIME);
*borrow_mut(&mut ctx, 523) = val;
};
// domains[17] = point^(trace_length / 16384) - trace_generator^(251 * trace_length / 256)
{
let val = ((/*(point^(trace_length/16384))*/ *borrow(&ctx, 466) + (PRIME - /*(trace_generator^((251*trace_length)/256))*/ *borrow(&ctx, 495))) % PRIME);
*borrow_mut(&mut ctx, 524) = val;
};
// domains[18] = point^(trace_length / 16384) - 1
{
let val = ((/*(point^(trace_length/16384))*/ *borrow(&ctx, 466) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 525) = val;
};
// domains[19] = point^(trace_length / 16384) - trace_generator^(63 * trace_length / 64)
{
let val = ((/*(point^(trace_length/16384))*/ *borrow(&ctx, 466) + (PRIME - /*(trace_generator^((63*trace_length)/64))*/ *borrow(&ctx, 496))) % PRIME);
*borrow_mut(&mut ctx, 526) = val;
};
// domains[20] = point^(trace_length / 32768) - trace_generator^(255 * trace_length / 256)
{
let val = ((/*(point^(trace_length/32768))*/ *borrow(&ctx, 465) + (PRIME - /*(trace_generator^((255*trace_length)/256))*/ *borrow(&ctx, 497))) % PRIME);
*borrow_mut(&mut ctx, 527) = val;
};
// domains[21] = point^(trace_length / 32768) - trace_generator^(251 * trace_length / 256)
{
let val = ((/*(point^(trace_length/32768))*/ *borrow(&ctx, 465) + (PRIME - /*(trace_generator^((251*trace_length)/256))*/ *borrow(&ctx, 495))) % PRIME);
*borrow_mut(&mut ctx, 528) = val;
};
// domains[22] = point^(trace_length / 32768) - 1
{
let val = ((/*(point^(trace_length/32768))*/ *borrow(&ctx, 465) + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 529) = val;
};
// domains[23] = point - trace_generator^(16 * (trace_length / 16 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(16*((trace_length/16)-1)))*/ *borrow(&ctx, 498))) % PRIME);
*borrow_mut(&mut ctx, 530) = val;
};
// domains[24] = point - 1
{
let val = ((/*point*/ point + (PRIME - 1)) % PRIME);
*borrow_mut(&mut ctx, 531) = val;
};
// domains[25] = point - trace_generator^(2 * (trace_length / 2 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(2*((trace_length/2)-1)))*/ *borrow(&ctx, 499))) % PRIME);
*borrow_mut(&mut ctx, 532) = val;
};
// domains[26] = point - trace_generator^(4 * (trace_length / 4 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(4*((trace_length/4)-1)))*/ *borrow(&ctx, 500))) % PRIME);
*borrow_mut(&mut ctx, 533) = val;
};
// domains[27] = point - trace_generator^(8 * (trace_length / 8 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(8*((trace_length/8)-1)))*/ *borrow(&ctx, 501))) % PRIME);
*borrow_mut(&mut ctx, 534) = val;
};
// domains[28] = point - trace_generator^(512 * (trace_length / 512 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(512*((trace_length/512)-1)))*/ *borrow(&ctx, 502))) % PRIME);
*borrow_mut(&mut ctx, 535) = val;
};
// domains[29] = point - trace_generator^(256 * (trace_length / 256 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(256*((trace_length/256)-1)))*/ *borrow(&ctx, 503))) % PRIME);
*borrow_mut(&mut ctx, 536) = val;
};
// domains[30] = point - trace_generator^(32768 * (trace_length / 32768 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(32768*((trace_length/32768)-1)))*/ *borrow(&ctx, 504))) % PRIME);
*borrow_mut(&mut ctx, 537) = val;
};
// domains[31] = point - trace_generator^(1024 * (trace_length / 1024 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(1024*((trace_length/1024)-1)))*/ *borrow(&ctx, 505))) % PRIME);
*borrow_mut(&mut ctx, 538) = val;
};
// domains[32] = point - trace_generator^(16384 * (trace_length / 16384 - 1))
{
let val = ((/*point*/ point + (PRIME - /*(trace_generator^(16384*((trace_length/16384)-1)))*/ *borrow(&ctx, 506))) % PRIME);
*borrow_mut(&mut ctx, 539) = val;
};


        };

        {
            // compute denominators
            // denominators[0] = domains[0]
{
let val = /*domains[0]*/ *borrow(&ctx, 507);
*borrow_mut(&mut ctx, 566) = val;
};
// denominators[1] = domains[4]
{
let val = /*domains[4]*/ *borrow(&ctx, 511);
*borrow_mut(&mut ctx, 567) = val;
};
// denominators[2] = domains[5]
{
let val = /*domains[5]*/ *borrow(&ctx, 512);
*borrow_mut(&mut ctx, 568) = val;
};
// denominators[3] = domains[23]
{
let val = /*domains[23]*/ *borrow(&ctx, 530);
*borrow_mut(&mut ctx, 569) = val;
};
// denominators[4] = domains[24]
{
let val = /*domains[24]*/ *borrow(&ctx, 531);
*borrow_mut(&mut ctx, 570) = val;
};
// denominators[5] = domains[1]
{
let val = /*domains[1]*/ *borrow(&ctx, 508);
*borrow_mut(&mut ctx, 571) = val;
};
// denominators[6] = domains[25]
{
let val = /*domains[25]*/ *borrow(&ctx, 532);
*borrow_mut(&mut ctx, 572) = val;
};
// denominators[7] = domains[3]
{
let val = /*domains[3]*/ *borrow(&ctx, 510);
*borrow_mut(&mut ctx, 573) = val;
};
// denominators[8] = domains[2]
{
let val = /*domains[2]*/ *borrow(&ctx, 509);
*borrow_mut(&mut ctx, 574) = val;
};
// denominators[9] = domains[26]
{
let val = /*domains[26]*/ *borrow(&ctx, 533);
*borrow_mut(&mut ctx, 575) = val;
};
// denominators[10] = domains[27]
{
let val = /*domains[27]*/ *borrow(&ctx, 534);
*borrow_mut(&mut ctx, 576) = val;
};
// denominators[11] = domains[8]
{
let val = /*domains[8]*/ *borrow(&ctx, 515);
*borrow_mut(&mut ctx, 577) = val;
};
// denominators[12] = domains[9]
{
let val = /*domains[9]*/ *borrow(&ctx, 516);
*borrow_mut(&mut ctx, 578) = val;
};
// denominators[13] = domains[10]
{
let val = /*domains[10]*/ *borrow(&ctx, 517);
*borrow_mut(&mut ctx, 579) = val;
};
// denominators[14] = domains[12]
{
let val = /*domains[12]*/ *borrow(&ctx, 519);
*borrow_mut(&mut ctx, 580) = val;
};
// denominators[15] = domains[6]
{
let val = /*domains[6]*/ *borrow(&ctx, 513);
*borrow_mut(&mut ctx, 581) = val;
};
// denominators[16] = domains[16]
{
let val = /*domains[16]*/ *borrow(&ctx, 523);
*borrow_mut(&mut ctx, 582) = val;
};
// denominators[17] = domains[7]
{
let val = /*domains[7]*/ *borrow(&ctx, 514);
*borrow_mut(&mut ctx, 583) = val;
};
// denominators[18] = domains[20]
{
let val = /*domains[20]*/ *borrow(&ctx, 527);
*borrow_mut(&mut ctx, 584) = val;
};
// denominators[19] = domains[21]
{
let val = /*domains[21]*/ *borrow(&ctx, 528);
*borrow_mut(&mut ctx, 585) = val;
};
// denominators[20] = domains[17]
{
let val = /*domains[17]*/ *borrow(&ctx, 524);
*borrow_mut(&mut ctx, 586) = val;
};
// denominators[21] = domains[22]
{
let val = /*domains[22]*/ *borrow(&ctx, 529);
*borrow_mut(&mut ctx, 587) = val;
};
// denominators[22] = domains[18]
{
let val = /*domains[18]*/ *borrow(&ctx, 525);
*borrow_mut(&mut ctx, 588) = val;
};
// denominators[23] = domains[14]
{
let val = /*domains[14]*/ *borrow(&ctx, 521);
*borrow_mut(&mut ctx, 589) = val;
};
// denominators[24] = domains[15]
{
let val = /*domains[15]*/ *borrow(&ctx, 522);
*borrow_mut(&mut ctx, 590) = val;
};
// denominators[25] = domains[19]
{
let val = /*domains[19]*/ *borrow(&ctx, 526);
*borrow_mut(&mut ctx, 591) = val;
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
                            *vector::borrow_mut(&mut ctx, partialProductPtr) = prod;
                            // prod *= d_{i}.
                            prod = fmul(prod, *borrow(&ctx, partialProductPtr + productsToValuesOffset));
                            partialProductPtr = partialProductPtr + 1;

                        };

                        let firstPartialProductPtr = 362;
                        // Compute the inverse of the product.

                        let prodInv = fpow(prod, PRIME - 2);

                        assert!(prodInv != 0, EPRODUCT_INVERSE_ZERO);

                        // Compute the inverses.
                        // Loop over denominator_invs in reverse order.
                        // currentPartialProductPtr is initialized to one past the end.
                        let currentPartialProductPtr = 380;
                        while (currentPartialProductPtr > firstPartialProductPtr) {
                            currentPartialProductPtr = currentPartialProductPtr - 1;
                            // Store 1/d_{i} = (d_0 * ... * d_{i-1}) * 1/(d_0 * ... * d_{i}).
                            *borrow_mut(&mut ctx, currentPartialProductPtr) = fmul(*borrow(&ctx, currentPartialProductPtr), prodInv);
                            // Update prodInv to be 1/(d_0 * ... * d_{i-1}) by multiplying by d_i.
                            prodInv = fmul(prodInv, *borrow(&ctx, currentPartialProductPtr + productsToValuesOffset));
                        };

                    };

        {
            // cpu/decode/opcode_rc/bit_0 = column0_row0 - (column0_row1 + column0_row1)
{
let val = ((/*column0_row0*/ *borrow(&ctx, 211) + (PRIME - ((/*column0_row1*/ *borrow(&ctx, 212) + /*column0_row1*/ *borrow(&ctx, 212)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 423) = val;
};
// cpu/decode/opcode_rc/bit_2 = column0_row2 - (column0_row3 + column0_row3)
{
let val = ((/*column0_row2*/ *borrow(&ctx, 213) + (PRIME - ((/*column0_row3*/ *borrow(&ctx, 214) + /*column0_row3*/ *borrow(&ctx, 214)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 424) = val;
};
// cpu/decode/opcode_rc/bit_4 = column0_row4 - (column0_row5 + column0_row5)
{
let val = ((/*column0_row4*/ *borrow(&ctx, 215) + (PRIME - ((/*column0_row5*/ *borrow(&ctx, 216) + /*column0_row5*/ *borrow(&ctx, 216)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 425) = val;
};
// cpu/decode/opcode_rc/bit_3 = column0_row3 - (column0_row4 + column0_row4)
{
let val = ((/*column0_row3*/ *borrow(&ctx, 214) + (PRIME - ((/*column0_row4*/ *borrow(&ctx, 215) + /*column0_row4*/ *borrow(&ctx, 215)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 426) = val;
};
// cpu/decode/flag_op1_base_op0_0 = 1 - (cpu__decode__opcode_rc__bit_2 + cpu__decode__opcode_rc__bit_4 + cpu__decode__opcode_rc__bit_3)
{
let val = ((1 + (PRIME - ((((/*cpu__decode__opcode_rc__bit_2*/ *borrow(&ctx, 424) + /*cpu__decode__opcode_rc__bit_4*/ *borrow(&ctx, 425)) % PRIME) + /*cpu__decode__opcode_rc__bit_3*/ *borrow(&ctx, 426)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 427) = val;
};
// cpu/decode/opcode_rc/bit_5 = column0_row5 - (column0_row6 + column0_row6)
{
let val = ((/*column0_row5*/ *borrow(&ctx, 216) + (PRIME - ((/*column0_row6*/ *borrow(&ctx, 217) + /*column0_row6*/ *borrow(&ctx, 217)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 428) = val;
};
// cpu/decode/opcode_rc/bit_6 = column0_row6 - (column0_row7 + column0_row7)
{
let val = ((/*column0_row6*/ *borrow(&ctx, 217) + (PRIME - ((/*column0_row7*/ *borrow(&ctx, 218) + /*column0_row7*/ *borrow(&ctx, 218)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 429) = val;
};
// cpu/decode/opcode_rc/bit_9 = column0_row9 - (column0_row10 + column0_row10)
{
let val = ((/*column0_row9*/ *borrow(&ctx, 220) + (PRIME - ((/*column0_row10*/ *borrow(&ctx, 221) + /*column0_row10*/ *borrow(&ctx, 221)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 430) = val;
};
// cpu/decode/flag_res_op1_0 = 1 - (cpu__decode__opcode_rc__bit_5 + cpu__decode__opcode_rc__bit_6 + cpu__decode__opcode_rc__bit_9)
{
let val = ((1 + (PRIME - ((((/*cpu__decode__opcode_rc__bit_5*/ *borrow(&ctx, 428) + /*cpu__decode__opcode_rc__bit_6*/ *borrow(&ctx, 429)) % PRIME) + /*cpu__decode__opcode_rc__bit_9*/ *borrow(&ctx, 430)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 431) = val;
};
// cpu/decode/opcode_rc/bit_7 = column0_row7 - (column0_row8 + column0_row8)
{
let val = ((/*column0_row7*/ *borrow(&ctx, 218) + (PRIME - ((/*column0_row8*/ *borrow(&ctx, 219) + /*column0_row8*/ *borrow(&ctx, 219)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 432) = val;
};
// cpu/decode/opcode_rc/bit_8 = column0_row8 - (column0_row9 + column0_row9)
{
let val = ((/*column0_row8*/ *borrow(&ctx, 219) + (PRIME - ((/*column0_row9*/ *borrow(&ctx, 220) + /*column0_row9*/ *borrow(&ctx, 220)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 433) = val;
};
// cpu/decode/flag_pc_update_regular_0 = 1 - (cpu__decode__opcode_rc__bit_7 + cpu__decode__opcode_rc__bit_8 + cpu__decode__opcode_rc__bit_9)
{
let val = ((1 + (PRIME - ((((/*cpu__decode__opcode_rc__bit_7*/ *borrow(&ctx, 432) + /*cpu__decode__opcode_rc__bit_8*/ *borrow(&ctx, 433)) % PRIME) + /*cpu__decode__opcode_rc__bit_9*/ *borrow(&ctx, 430)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 434) = val;
};
// cpu/decode/opcode_rc/bit_12 = column0_row12 - (column0_row13 + column0_row13)
{
let val = ((/*column0_row12*/ *borrow(&ctx, 223) + (PRIME - ((/*column0_row13*/ *borrow(&ctx, 224) + /*column0_row13*/ *borrow(&ctx, 224)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 435) = val;
};
// cpu/decode/opcode_rc/bit_13 = column0_row13 - (column0_row14 + column0_row14)
{
let val = ((/*column0_row13*/ *borrow(&ctx, 224) + (PRIME - ((/*column0_row14*/ *borrow(&ctx, 225) + /*column0_row14*/ *borrow(&ctx, 225)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 436) = val;
};
// cpu/decode/fp_update_regular_0 = 1 - (cpu__decode__opcode_rc__bit_12 + cpu__decode__opcode_rc__bit_13)
{
let val = ((1 + (PRIME - ((/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435) + /*cpu__decode__opcode_rc__bit_13*/ *borrow(&ctx, 436)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 437) = val;
};
// cpu/decode/opcode_rc/bit_1 = column0_row1 - (column0_row2 + column0_row2)
{
let val = ((/*column0_row1*/ *borrow(&ctx, 212) + (PRIME - ((/*column0_row2*/ *borrow(&ctx, 213) + /*column0_row2*/ *borrow(&ctx, 213)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 438) = val;
};
// npc_reg_0 = column5_row0 + cpu__decode__opcode_rc__bit_2 + 1
{
let val = ((((/*column5_row0*/ *borrow(&ctx, 247) + /*cpu__decode__opcode_rc__bit_2*/ *borrow(&ctx, 424)) % PRIME) + 1) % PRIME);
*borrow_mut(&mut ctx, 439) = val;
};
// cpu/decode/opcode_rc/bit_10 = column0_row10 - (column0_row11 + column0_row11)
{
let val = ((/*column0_row10*/ *borrow(&ctx, 221) + (PRIME - ((/*column0_row11*/ *borrow(&ctx, 222) + /*column0_row11*/ *borrow(&ctx, 222)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 440) = val;
};
// cpu/decode/opcode_rc/bit_11 = column0_row11 - (column0_row12 + column0_row12)
{
let val = ((/*column0_row11*/ *borrow(&ctx, 222) + (PRIME - ((/*column0_row12*/ *borrow(&ctx, 223) + /*column0_row12*/ *borrow(&ctx, 223)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 441) = val;
};
// cpu/decode/opcode_rc/bit_14 = column0_row14 - (column0_row15 + column0_row15)
{
let val = ((/*column0_row14*/ *borrow(&ctx, 225) + (PRIME - ((/*column0_row15*/ *borrow(&ctx, 226) + /*column0_row15*/ *borrow(&ctx, 226)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 442) = val;
};
// memory/address_diff_0 = column6_row2 - column6_row0
{
let val = ((/*column6_row2*/ *borrow(&ctx, 299) + (PRIME - /*column6_row0*/ *borrow(&ctx, 297))) % PRIME);
*borrow_mut(&mut ctx, 443) = val;
};
// rc16/diff_0 = column7_row6 - column7_row2
{
let val = ((/*column7_row6*/ *borrow(&ctx, 307) + (PRIME - /*column7_row2*/ *borrow(&ctx, 303))) % PRIME);
*borrow_mut(&mut ctx, 444) = val;
};
// pedersen/hash0/ec_subset_sum/bit_0 = column3_row0 - (column3_row1 + column3_row1)
{
let val = ((/*column3_row0*/ *borrow(&ctx, 236) + (PRIME - ((/*column3_row1*/ *borrow(&ctx, 237) + /*column3_row1*/ *borrow(&ctx, 237)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 445) = val;
};
// pedersen/hash0/ec_subset_sum/bit_neg_0 = 1 - pedersen__hash0__ec_subset_sum__bit_0
{
let val = ((1 + (PRIME - /*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 445))) % PRIME);
*borrow_mut(&mut ctx, 446) = val;
};
// rc_builtin/value0_0 = column7_row12
{
let val = /*column7_row12*/ *borrow(&ctx, 312);
*borrow_mut(&mut ctx, 447) = val;
};
// rc_builtin/value1_0 = rc_builtin__value0_0 * offset_size + column7_row44
{
let val = ((fmul(/*rc_builtin__value0_0*/ *borrow(&ctx, 447), /*offset_size*/ offset_size) + /*column7_row44*/ *borrow(&ctx, 319)) % PRIME);
*borrow_mut(&mut ctx, 448) = val;
};
// rc_builtin/value2_0 = rc_builtin__value1_0 * offset_size + column7_row76
{
let val = ((fmul(/*rc_builtin__value1_0*/ *borrow(&ctx, 448), /*offset_size*/ offset_size) + /*column7_row76*/ *borrow(&ctx, 322)) % PRIME);
*borrow_mut(&mut ctx, 449) = val;
};
// rc_builtin/value3_0 = rc_builtin__value2_0 * offset_size + column7_row108
{
let val = ((fmul(/*rc_builtin__value2_0*/ *borrow(&ctx, 449), /*offset_size*/ offset_size) + /*column7_row108*/ *borrow(&ctx, 325)) % PRIME);
*borrow_mut(&mut ctx, 450) = val;
};
// rc_builtin/value4_0 = rc_builtin__value3_0 * offset_size + column7_row140
{
let val = ((fmul(/*rc_builtin__value3_0*/ *borrow(&ctx, 450), /*offset_size*/ offset_size) + /*column7_row140*/ *borrow(&ctx, 328)) % PRIME);
*borrow_mut(&mut ctx, 451) = val;
};
// rc_builtin/value5_0 = rc_builtin__value4_0 * offset_size + column7_row172
{
let val = ((fmul(/*rc_builtin__value4_0*/ *borrow(&ctx, 451), /*offset_size*/ offset_size) + /*column7_row172*/ *borrow(&ctx, 331)) % PRIME);
*borrow_mut(&mut ctx, 452) = val;
};
// rc_builtin/value6_0 = rc_builtin__value5_0 * offset_size + column7_row204
{
let val = ((fmul(/*rc_builtin__value5_0*/ *borrow(&ctx, 452), /*offset_size*/ offset_size) + /*column7_row204*/ *borrow(&ctx, 334)) % PRIME);
*borrow_mut(&mut ctx, 453) = val;
};
// rc_builtin/value7_0 = rc_builtin__value6_0 * offset_size + column7_row236
{
let val = ((fmul(/*rc_builtin__value6_0*/ *borrow(&ctx, 453), /*offset_size*/ offset_size) + /*column7_row236*/ *borrow(&ctx, 337)) % PRIME);
*borrow_mut(&mut ctx, 454) = val;
};
// ecdsa/signature0/doubling_key/x_squared = column8_row4 * column8_row4
{
let val = fmul(/*column8_row4*/ *borrow(&ctx, 355), /*column8_row4*/ *borrow(&ctx, 355));
*borrow_mut(&mut ctx, 455) = val;
};
// ecdsa/signature0/exponentiate_generator/bit_0 = column8_row38 - (column8_row166 + column8_row166)
{
let val = ((/*column8_row38*/ *borrow(&ctx, 367) + (PRIME - ((/*column8_row166*/ *borrow(&ctx, 388) + /*column8_row166*/ *borrow(&ctx, 388)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 456) = val;
};
// ecdsa/signature0/exponentiate_generator/bit_neg_0 = 1 - ecdsa__signature0__exponentiate_generator__bit_0
{
let val = ((1 + (PRIME - /*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 456))) % PRIME);
*borrow_mut(&mut ctx, 457) = val;
};
// ecdsa/signature0/exponentiate_key/bit_0 = column8_row12 - (column8_row76 + column8_row76)
{
let val = ((/*column8_row12*/ *borrow(&ctx, 359) + (PRIME - ((/*column8_row76*/ *borrow(&ctx, 377) + /*column8_row76*/ *borrow(&ctx, 377)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 458) = val;
};
// ecdsa/signature0/exponentiate_key/bit_neg_0 = 1 - ecdsa__signature0__exponentiate_key__bit_0
{
let val = ((1 + (PRIME - /*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 458))) % PRIME);
*borrow_mut(&mut ctx, 459) = val;
};
// bitwise/sum_var_0_0 = column7_row1 + column7_row17 * 2 + column7_row33 * 4 + column7_row49 * 8 + column7_row65 * 18446744073709551616 + column7_row81 * 36893488147419103232 + column7_row97 * 73786976294838206464 + column7_row113 * 147573952589676412928
{
let val = ((((((((((((((/*column7_row1*/ *borrow(&ctx, 302) + fmul(/*column7_row17*/ *borrow(&ctx, 315), 2)) % PRIME) + fmul(/*column7_row33*/ *borrow(&ctx, 318), 4)) % PRIME) + fmul(/*column7_row49*/ *borrow(&ctx, 320), 8)) % PRIME) + fmul(/*column7_row65*/ *borrow(&ctx, 321), 18446744073709551616)) % PRIME) + fmul(/*column7_row81*/ *borrow(&ctx, 323), 36893488147419103232)) % PRIME) + fmul(/*column7_row97*/ *borrow(&ctx, 324), 73786976294838206464)) % PRIME) + fmul(/*column7_row113*/ *borrow(&ctx, 326), 147573952589676412928)) % PRIME);
*borrow_mut(&mut ctx, 460) = val;
};
// bitwise/sum_var_8_0 = column7_row129 * 340282366920938463463374607431768211456 + column7_row145 * 680564733841876926926749214863536422912 + column7_row161 * 1361129467683753853853498429727072845824 + column7_row177 * 2722258935367507707706996859454145691648 + column7_row193 * 6277101735386680763835789423207666416102355444464034512896 + column7_row209 * 12554203470773361527671578846415332832204710888928069025792 + column7_row225 * 25108406941546723055343157692830665664409421777856138051584 + column7_row241 * 50216813883093446110686315385661331328818843555712276103168
{
let val = ((((((((((((((fmul(/*column7_row129*/ *borrow(&ctx, 327), 340282366920938463463374607431768211456) + fmul(/*column7_row145*/ *borrow(&ctx, 329), 680564733841876926926749214863536422912)) % PRIME) + fmul(/*column7_row161*/ *borrow(&ctx, 330), 1361129467683753853853498429727072845824)) % PRIME) + fmul(/*column7_row177*/ *borrow(&ctx, 332), 2722258935367507707706996859454145691648)) % PRIME) + fmul(/*column7_row193*/ *borrow(&ctx, 333), 6277101735386680763835789423207666416102355444464034512896)) % PRIME) + fmul(/*column7_row209*/ *borrow(&ctx, 335), 12554203470773361527671578846415332832204710888928069025792)) % PRIME) + fmul(/*column7_row225*/ *borrow(&ctx, 336), 25108406941546723055343157692830665664409421777856138051584)) % PRIME) + fmul(/*column7_row241*/ *borrow(&ctx, 338), 50216813883093446110686315385661331328818843555712276103168)) % PRIME);
*borrow_mut(&mut ctx, 461) = val;
};
// ec_op/doubling_q/x_squared_0 = column8_row44 * column8_row44
{
let val = fmul(/*column8_row44*/ *borrow(&ctx, 369), /*column8_row44*/ *borrow(&ctx, 369));
*borrow_mut(&mut ctx, 462) = val;
};
// ec_op/ec_subset_sum/bit_0 = column8_row18 - (column8_row82 + column8_row82)
{
let val = ((/*column8_row18*/ *borrow(&ctx, 360) + (PRIME - ((/*column8_row82*/ *borrow(&ctx, 378) + /*column8_row82*/ *borrow(&ctx, 378)) % PRIME))) % PRIME);
*borrow_mut(&mut ctx, 463) = val;
};
// ec_op/ec_subset_sum/bit_neg_0 = 1 - ec_op__ec_subset_sum__bit_0
{
let val = ((1 + (PRIME - /*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 463))) % PRIME);
*borrow_mut(&mut ctx, 464) = val;
};


            // compute compositions

            let composition_alpha_pow = 1u256;
            let composition_alpha = /*composition_alpha*/ *borrow(&ctx, 41);


//Constraint expression for cpu/decode/opcode_rc/bit: cpu__decode__opcode_rc__bit_0 * cpu__decode__opcode_rc__bit_0 - cpu__decode__opcode_rc__bit_0
{
let val =((fmul(/*cpu__decode__opcode_rc__bit_0*/ *borrow(&ctx, 423), /*cpu__decode__opcode_rc__bit_0*/ *borrow(&ctx, 423)) + (PRIME - /*cpu__decode__opcode_rc__bit_0*/ *borrow(&ctx, 423))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 567));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 540));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/decode/opcode_rc/zero: column0_row0
{
let val =/*column0_row0*/ *borrow(&ctx, 211);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 541));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/decode/opcode_rc_input: column5_row1 - (((column0_row0 * offset_size + column7_row4) * offset_size + column7_row8) * offset_size + column7_row0)
{
let val =((/*column5_row1*/ *borrow(&ctx, 248) + (PRIME - ((fmul(((fmul(((fmul(/*column0_row0*/ *borrow(&ctx, 211), /*offset_size*/ offset_size) + /*column7_row4*/ *borrow(&ctx, 305)) % PRIME), /*offset_size*/ offset_size) + /*column7_row8*/ *borrow(&ctx, 309)) % PRIME), /*offset_size*/ offset_size) + /*column7_row0*/ *borrow(&ctx, 301)) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/decode/flag_op1_base_op0_bit: cpu__decode__flag_op1_base_op0_0 * cpu__decode__flag_op1_base_op0_0 - cpu__decode__flag_op1_base_op0_0
{
let val =((fmul(/*cpu__decode__flag_op1_base_op0_0*/ *borrow(&ctx, 427), /*cpu__decode__flag_op1_base_op0_0*/ *borrow(&ctx, 427)) + (PRIME - /*cpu__decode__flag_op1_base_op0_0*/ *borrow(&ctx, 427))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/decode/flag_res_op1_bit: cpu__decode__flag_res_op1_0 * cpu__decode__flag_res_op1_0 - cpu__decode__flag_res_op1_0
{
let val =((fmul(/*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 431), /*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 431)) + (PRIME - /*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 431))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/decode/flag_pc_update_regular_bit: cpu__decode__flag_pc_update_regular_0 * cpu__decode__flag_pc_update_regular_0 - cpu__decode__flag_pc_update_regular_0
{
let val =((fmul(/*cpu__decode__flag_pc_update_regular_0*/ *borrow(&ctx, 434), /*cpu__decode__flag_pc_update_regular_0*/ *borrow(&ctx, 434)) + (PRIME - /*cpu__decode__flag_pc_update_regular_0*/ *borrow(&ctx, 434))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/decode/fp_update_regular_bit: cpu__decode__fp_update_regular_0 * cpu__decode__fp_update_regular_0 - cpu__decode__fp_update_regular_0
{
let val =((fmul(/*cpu__decode__fp_update_regular_0*/ *borrow(&ctx, 437), /*cpu__decode__fp_update_regular_0*/ *borrow(&ctx, 437)) + (PRIME - /*cpu__decode__fp_update_regular_0*/ *borrow(&ctx, 437))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/operands/mem_dst_addr: column5_row8 + half_offset_size - (cpu__decode__opcode_rc__bit_0 * column7_row11 + (1 - cpu__decode__opcode_rc__bit_0) * column7_row3 + column7_row0)
{
let val =((((/*column5_row8*/ *borrow(&ctx, 255) + /*half_offset_size*/ half_offset_size) % PRIME) + (PRIME - ((((fmul(/*cpu__decode__opcode_rc__bit_0*/ *borrow(&ctx, 423), /*column7_row11*/ *borrow(&ctx, 311)) + fmul(((1 + (PRIME - /*cpu__decode__opcode_rc__bit_0*/ *borrow(&ctx, 423))) % PRIME), /*column7_row3*/ *borrow(&ctx, 304))) % PRIME) + /*column7_row0*/ *borrow(&ctx, 301)) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/operands/mem0_addr: column5_row4 + half_offset_size - (cpu__decode__opcode_rc__bit_1 * column7_row11 + (1 - cpu__decode__opcode_rc__bit_1) * column7_row3 + column7_row8)
{
let val =((((/*column5_row4*/ *borrow(&ctx, 251) + /*half_offset_size*/ half_offset_size) % PRIME) + (PRIME - ((((fmul(/*cpu__decode__opcode_rc__bit_1*/ *borrow(&ctx, 438), /*column7_row11*/ *borrow(&ctx, 311)) + fmul(((1 + (PRIME - /*cpu__decode__opcode_rc__bit_1*/ *borrow(&ctx, 438))) % PRIME), /*column7_row3*/ *borrow(&ctx, 304))) % PRIME) + /*column7_row8*/ *borrow(&ctx, 309)) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/operands/mem1_addr: column5_row12 + half_offset_size - (cpu__decode__opcode_rc__bit_2 * column5_row0 + cpu__decode__opcode_rc__bit_4 * column7_row3 + cpu__decode__opcode_rc__bit_3 * column7_row11 + cpu__decode__flag_op1_base_op0_0 * column5_row5 + column7_row4)
{
let val =((((/*column5_row12*/ *borrow(&ctx, 257) + /*half_offset_size*/ half_offset_size) % PRIME) + (PRIME - ((((((((fmul(/*cpu__decode__opcode_rc__bit_2*/ *borrow(&ctx, 424), /*column5_row0*/ *borrow(&ctx, 247)) + fmul(/*cpu__decode__opcode_rc__bit_4*/ *borrow(&ctx, 425), /*column7_row3*/ *borrow(&ctx, 304))) % PRIME) + fmul(/*cpu__decode__opcode_rc__bit_3*/ *borrow(&ctx, 426), /*column7_row11*/ *borrow(&ctx, 311))) % PRIME) + fmul(/*cpu__decode__flag_op1_base_op0_0*/ *borrow(&ctx, 427), /*column5_row5*/ *borrow(&ctx, 252))) % PRIME) + /*column7_row4*/ *borrow(&ctx, 305)) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/operands/ops_mul: column7_row7 - column5_row5 * column5_row13
{
let val =((/*column7_row7*/ *borrow(&ctx, 308) + (PRIME - fmul(/*column5_row5*/ *borrow(&ctx, 252), /*column5_row13*/ *borrow(&ctx, 258)))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/operands/res: (1 - cpu__decode__opcode_rc__bit_9) * column7_row15 - (cpu__decode__opcode_rc__bit_5 * (column5_row5 + column5_row13) + cpu__decode__opcode_rc__bit_6 * column7_row7 + cpu__decode__flag_res_op1_0 * column5_row13)
{
let val =((fmul(((1 + (PRIME - /*cpu__decode__opcode_rc__bit_9*/ *borrow(&ctx, 430))) % PRIME), /*column7_row15*/ *borrow(&ctx, 314)) + (PRIME - ((((fmul(/*cpu__decode__opcode_rc__bit_5*/ *borrow(&ctx, 428), ((/*column5_row5*/ *borrow(&ctx, 252) + /*column5_row13*/ *borrow(&ctx, 258)) % PRIME)) + fmul(/*cpu__decode__opcode_rc__bit_6*/ *borrow(&ctx, 429), /*column7_row7*/ *borrow(&ctx, 308))) % PRIME) + fmul(/*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 431), /*column5_row13*/ *borrow(&ctx, 258))) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/update_registers/update_pc/tmp0: column8_row0 - cpu__decode__opcode_rc__bit_9 * column5_row9
{
let val =((/*column8_row0*/ *borrow(&ctx, 353) + (PRIME - fmul(/*cpu__decode__opcode_rc__bit_9*/ *borrow(&ctx, 430), /*column5_row9*/ *borrow(&ctx, 256)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 569));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/update_registers/update_pc/tmp1: column8_row8 - column8_row0 * column7_row15
{
let val =((/*column8_row8*/ *borrow(&ctx, 357) + (PRIME - fmul(/*column8_row0*/ *borrow(&ctx, 353), /*column7_row15*/ *borrow(&ctx, 314)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 569));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/update_registers/update_pc/pc_cond_negative: (1 - cpu__decode__opcode_rc__bit_9) * column5_row16 + column8_row0 * (column5_row16 - (column5_row0 + column5_row13)) - (cpu__decode__flag_pc_update_regular_0 * npc_reg_0 + cpu__decode__opcode_rc__bit_7 * column7_row15 + cpu__decode__opcode_rc__bit_8 * (column5_row0 + column7_row15))
{
let val =((((fmul(((1 + (PRIME - /*cpu__decode__opcode_rc__bit_9*/ *borrow(&ctx, 430))) % PRIME), /*column5_row16*/ *borrow(&ctx, 259)) + fmul(/*column8_row0*/ *borrow(&ctx, 353), ((/*column5_row16*/ *borrow(&ctx, 259) + (PRIME - ((/*column5_row0*/ *borrow(&ctx, 247) + /*column5_row13*/ *borrow(&ctx, 258)) % PRIME))) % PRIME))) % PRIME) + (PRIME - ((((fmul(/*cpu__decode__flag_pc_update_regular_0*/ *borrow(&ctx, 434), /*npc_reg_0*/ *borrow(&ctx, 439)) + fmul(/*cpu__decode__opcode_rc__bit_7*/ *borrow(&ctx, 432), /*column7_row15*/ *borrow(&ctx, 314))) % PRIME) + fmul(/*cpu__decode__opcode_rc__bit_8*/ *borrow(&ctx, 433), ((/*column5_row0*/ *borrow(&ctx, 247) + /*column7_row15*/ *borrow(&ctx, 314)) % PRIME))) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 569));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/update_registers/update_pc/pc_cond_positive: (column8_row8 - cpu__decode__opcode_rc__bit_9) * (column5_row16 - npc_reg_0)
{
let val =fmul(((/*column8_row8*/ *borrow(&ctx, 357) + (PRIME - /*cpu__decode__opcode_rc__bit_9*/ *borrow(&ctx, 430))) % PRIME), ((/*column5_row16*/ *borrow(&ctx, 259) + (PRIME - /*npc_reg_0*/ *borrow(&ctx, 439))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 569));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/update_registers/update_ap/ap_update: column7_row19 - (column7_row3 + cpu__decode__opcode_rc__bit_10 * column7_row15 + cpu__decode__opcode_rc__bit_11 + cpu__decode__opcode_rc__bit_12 * 2)
{
let val =((/*column7_row19*/ *borrow(&ctx, 316) + (PRIME - ((((((/*column7_row3*/ *borrow(&ctx, 304) + fmul(/*cpu__decode__opcode_rc__bit_10*/ *borrow(&ctx, 440), /*column7_row15*/ *borrow(&ctx, 314))) % PRIME) + /*cpu__decode__opcode_rc__bit_11*/ *borrow(&ctx, 441)) % PRIME) + fmul(/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435), 2)) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 569));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/update_registers/update_fp/fp_update: column7_row27 - (cpu__decode__fp_update_regular_0 * column7_row11 + cpu__decode__opcode_rc__bit_13 * column5_row9 + cpu__decode__opcode_rc__bit_12 * (column7_row3 + 2))
{
let val =((/*column7_row27*/ *borrow(&ctx, 317) + (PRIME - ((((fmul(/*cpu__decode__fp_update_regular_0*/ *borrow(&ctx, 437), /*column7_row11*/ *borrow(&ctx, 311)) + fmul(/*cpu__decode__opcode_rc__bit_13*/ *borrow(&ctx, 436), /*column5_row9*/ *borrow(&ctx, 256))) % PRIME) + fmul(/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435), ((/*column7_row3*/ *borrow(&ctx, 304) + 2) % PRIME))) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 569));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/call/push_fp: cpu__decode__opcode_rc__bit_12 * (column5_row9 - column7_row11)
{
let val =fmul(/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435), ((/*column5_row9*/ *borrow(&ctx, 256) + (PRIME - /*column7_row11*/ *borrow(&ctx, 311))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/call/push_pc: cpu__decode__opcode_rc__bit_12 * (column5_row5 - (column5_row0 + cpu__decode__opcode_rc__bit_2 + 1))
{
let val =fmul(/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435), ((/*column5_row5*/ *borrow(&ctx, 252) + (PRIME - /*((column5_row0+cpu__decode__opcode_rc__bit_2)+1)*/ *borrow(&ctx, 439))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/call/off0: cpu__decode__opcode_rc__bit_12 * (column7_row0 - half_offset_size)
{
let val =fmul(/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435), ((/*column7_row0*/ *borrow(&ctx, 301) + (PRIME - /*half_offset_size*/ half_offset_size)) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/call/off1: cpu__decode__opcode_rc__bit_12 * (column7_row8 - (half_offset_size + 1))
{
let val =fmul(/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435), ((/*column7_row8*/ *borrow(&ctx, 309) + (PRIME - ((/*half_offset_size*/ half_offset_size + 1) % PRIME))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/call/flags: cpu__decode__opcode_rc__bit_12 * (cpu__decode__opcode_rc__bit_12 + cpu__decode__opcode_rc__bit_12 + 1 + 1 - (cpu__decode__opcode_rc__bit_0 + cpu__decode__opcode_rc__bit_1 + 4))
{
let val =fmul(/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435), ((((((((/*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435) + /*cpu__decode__opcode_rc__bit_12*/ *borrow(&ctx, 435)) % PRIME) + 1) % PRIME) + 1) % PRIME) + (PRIME - ((((/*cpu__decode__opcode_rc__bit_0*/ *borrow(&ctx, 423) + /*cpu__decode__opcode_rc__bit_1*/ *borrow(&ctx, 438)) % PRIME) + 4) % PRIME))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/ret/off0: cpu__decode__opcode_rc__bit_13 * (column7_row0 + 2 - half_offset_size)
{
let val =fmul(/*cpu__decode__opcode_rc__bit_13*/ *borrow(&ctx, 436), ((((/*column7_row0*/ *borrow(&ctx, 301) + 2) % PRIME) + (PRIME - /*half_offset_size*/ half_offset_size)) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/ret/off2: cpu__decode__opcode_rc__bit_13 * (column7_row4 + 1 - half_offset_size)
{
let val =fmul(/*cpu__decode__opcode_rc__bit_13*/ *borrow(&ctx, 436), ((((/*column7_row4*/ *borrow(&ctx, 305) + 1) % PRIME) + (PRIME - /*half_offset_size*/ half_offset_size)) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/ret/flags: cpu__decode__opcode_rc__bit_13 * (cpu__decode__opcode_rc__bit_7 + cpu__decode__opcode_rc__bit_0 + cpu__decode__opcode_rc__bit_3 + cpu__decode__flag_res_op1_0 - 4)
{
let val =fmul(/*cpu__decode__opcode_rc__bit_13*/ *borrow(&ctx, 436), ((((((((/*cpu__decode__opcode_rc__bit_7*/ *borrow(&ctx, 432) + /*cpu__decode__opcode_rc__bit_0*/ *borrow(&ctx, 423)) % PRIME) + /*cpu__decode__opcode_rc__bit_3*/ *borrow(&ctx, 426)) % PRIME) + /*cpu__decode__flag_res_op1_0*/ *borrow(&ctx, 431)) % PRIME) + (PRIME - 4)) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for cpu/opcodes/assert_eq/assert_eq: cpu__decode__opcode_rc__bit_14 * (column5_row9 - column7_row15)
{
let val =fmul(/*cpu__decode__opcode_rc__bit_14*/ *borrow(&ctx, 442), ((/*column5_row9*/ *borrow(&ctx, 256) + (PRIME - /*column7_row15*/ *borrow(&ctx, 314))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 542));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for initial_ap: column7_row3 - initial_ap
{
let val =((/*column7_row3*/ *borrow(&ctx, 304) + (PRIME - /*initial_ap*/ initial_ap)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for initial_fp: column7_row11 - initial_ap
{
let val =((/*column7_row11*/ *borrow(&ctx, 311) + (PRIME - /*initial_ap*/ initial_ap)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for initial_pc: column5_row0 - initial_pc
{
let val =((/*column5_row0*/ *borrow(&ctx, 247) + (PRIME - /*initial_pc*/ initial_pc)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for final_ap: column7_row3 - final_ap
{
let val =((/*column7_row3*/ *borrow(&ctx, 304) + (PRIME - /*final_ap*/ final_ap)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 543));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for final_fp: column7_row11 - initial_ap
{
let val =((/*column7_row11*/ *borrow(&ctx, 311) + (PRIME - /*initial_ap*/ initial_ap)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 543));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for final_pc: column5_row0 - final_pc
{
let val =((/*column5_row0*/ *borrow(&ctx, 247) + (PRIME - /*final_pc*/ final_pc)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 543));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for memory/multi_column_perm/perm/init0: (memory__multi_column_perm__perm__interaction_elm - (column6_row0 + memory__multi_column_perm__hash_interaction_elm0 * column6_row1)) * column9_inter1_row0 + column5_row0 + memory__multi_column_perm__hash_interaction_elm0 * column5_row1 - memory__multi_column_perm__perm__interaction_elm
{
let val =((((((fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm + (PRIME - ((/*column6_row0*/ *borrow(&ctx, 297) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column6_row1*/ *borrow(&ctx, 298))) % PRIME))) % PRIME), /*column9_inter1_row0*/ *borrow(&ctx, 415)) + /*column5_row0*/ *borrow(&ctx, 247)) % PRIME) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column5_row1*/ *borrow(&ctx, 248))) % PRIME) + (PRIME - /*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for memory/multi_column_perm/perm/step0: (memory__multi_column_perm__perm__interaction_elm - (column6_row2 + memory__multi_column_perm__hash_interaction_elm0 * column6_row3)) * column9_inter1_row2 - (memory__multi_column_perm__perm__interaction_elm - (column5_row2 + memory__multi_column_perm__hash_interaction_elm0 * column5_row3)) * column9_inter1_row0
{
let val =((fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm + (PRIME - ((/*column6_row2*/ *borrow(&ctx, 299) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column6_row3*/ *borrow(&ctx, 300))) % PRIME))) % PRIME), /*column9_inter1_row2*/ *borrow(&ctx, 417)) + (PRIME - fmul(((/*memory__multi_column_perm__perm__interaction_elm*/ memory__multi_column_perm__perm__interaction_elm + (PRIME - ((/*column5_row2*/ *borrow(&ctx, 249) + fmul(/*memory__multi_column_perm__hash_interaction_elm0*/ memory__multi_column_perm__hash_interaction_elm0, /*column5_row3*/ *borrow(&ctx, 250))) % PRIME))) % PRIME), /*column9_inter1_row0*/ *borrow(&ctx, 415)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 572));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 545));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for memory/multi_column_perm/perm/last: column9_inter1_row0 - memory__multi_column_perm__perm__public_memory_prod
{
let val =((/*column9_inter1_row0*/ *borrow(&ctx, 415) + (PRIME - /*memory__multi_column_perm__perm__public_memory_prod*/ memory__multi_column_perm__perm__public_memory_prod)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 546));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for memory/diff_is_bit: memory__address_diff_0 * memory__address_diff_0 - memory__address_diff_0
{
let val =((fmul(/*memory__address_diff_0*/ *borrow(&ctx, 443), /*memory__address_diff_0*/ *borrow(&ctx, 443)) + (PRIME - /*memory__address_diff_0*/ *borrow(&ctx, 443))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 572));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 545));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for memory/is_func: (memory__address_diff_0 - 1) * (column6_row1 - column6_row3)
{
let val =fmul(((/*memory__address_diff_0*/ *borrow(&ctx, 443) + (PRIME - 1)) % PRIME), ((/*column6_row1*/ *borrow(&ctx, 298) + (PRIME - /*column6_row3*/ *borrow(&ctx, 300))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 572));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 545));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for memory/initial_addr: column6_row0 - 1
{
let val =((/*column6_row0*/ *borrow(&ctx, 297) + (PRIME - 1)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for public_memory_addr_zero: column5_row2
{
let val =/*column5_row2*/ *borrow(&ctx, 249);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 547));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for public_memory_value_zero: column5_row3
{
let val =/*column5_row3*/ *borrow(&ctx, 250);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 547));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc16/perm/init0: (rc16__perm__interaction_elm - column7_row2) * column9_inter1_row1 + column7_row0 - rc16__perm__interaction_elm
{
let val =((((fmul(((/*rc16__perm__interaction_elm*/ rc16__perm__interaction_elm + (PRIME - /*column7_row2*/ *borrow(&ctx, 303))) % PRIME), /*column9_inter1_row1*/ *borrow(&ctx, 416)) + /*column7_row0*/ *borrow(&ctx, 301)) % PRIME) + (PRIME - /*rc16__perm__interaction_elm*/ rc16__perm__interaction_elm)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc16/perm/step0: (rc16__perm__interaction_elm - column7_row6) * column9_inter1_row5 - (rc16__perm__interaction_elm - column7_row4) * column9_inter1_row1
{
let val =((fmul(((/*rc16__perm__interaction_elm*/ rc16__perm__interaction_elm + (PRIME - /*column7_row6*/ *borrow(&ctx, 307))) % PRIME), /*column9_inter1_row5*/ *borrow(&ctx, 419)) + (PRIME - fmul(((/*rc16__perm__interaction_elm*/ rc16__perm__interaction_elm + (PRIME - /*column7_row4*/ *borrow(&ctx, 305))) % PRIME), /*column9_inter1_row1*/ *borrow(&ctx, 416)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 575));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 548));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc16/perm/last: column9_inter1_row1 - rc16__perm__public_memory_prod
{
let val =((/*column9_inter1_row1*/ *borrow(&ctx, 416) + (PRIME - /*rc16__perm__public_memory_prod*/ rc16__perm__public_memory_prod)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 549));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc16/diff_is_bit: rc16__diff_0 * rc16__diff_0 - rc16__diff_0
{
let val =((fmul(/*rc16__diff_0*/ *borrow(&ctx, 444), /*rc16__diff_0*/ *borrow(&ctx, 444)) + (PRIME - /*rc16__diff_0*/ *borrow(&ctx, 444))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 575));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 548));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc16/minimum: column7_row2 - rc_min
{
let val =((/*column7_row2*/ *borrow(&ctx, 303) + (PRIME - /*rc_min*/ rc_min)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc16/maximum: column7_row2 - rc_max
{
let val =((/*column7_row2*/ *borrow(&ctx, 303) + (PRIME - /*rc_max*/ rc_max)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 549));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for diluted_check/permutation/init0: (diluted_check__permutation__interaction_elm - column7_row5) * column9_inter1_row7 + column7_row1 - diluted_check__permutation__interaction_elm
{
let val =((((fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm + (PRIME - /*column7_row5*/ *borrow(&ctx, 306))) % PRIME), /*column9_inter1_row7*/ *borrow(&ctx, 420)) + /*column7_row1*/ *borrow(&ctx, 302)) % PRIME) + (PRIME - /*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for diluted_check/permutation/step0: (diluted_check__permutation__interaction_elm - column7_row13) * column9_inter1_row15 - (diluted_check__permutation__interaction_elm - column7_row9) * column9_inter1_row7
{
let val =((fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm + (PRIME - /*column7_row13*/ *borrow(&ctx, 313))) % PRIME), /*column9_inter1_row15*/ *borrow(&ctx, 422)) + (PRIME - fmul(((/*diluted_check__permutation__interaction_elm*/ diluted_check__permutation__interaction_elm + (PRIME - /*column7_row9*/ *borrow(&ctx, 310))) % PRIME), /*column9_inter1_row7*/ *borrow(&ctx, 420)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 576));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 547));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for diluted_check/permutation/last: column9_inter1_row7 - diluted_check__permutation__public_memory_prod
{
let val =((/*column9_inter1_row7*/ *borrow(&ctx, 420) + (PRIME - /*diluted_check__permutation__public_memory_prod*/ diluted_check__permutation__public_memory_prod)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 550));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for diluted_check/init: column9_inter1_row3 - 1
{
let val =((/*column9_inter1_row3*/ *borrow(&ctx, 418) + (PRIME - 1)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for diluted_check/first_element: column7_row5 - diluted_check__first_elm
{
let val =((/*column7_row5*/ *borrow(&ctx, 306) + (PRIME - /*diluted_check__first_elm*/ diluted_check__first_elm)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for diluted_check/step: column9_inter1_row11 - (column9_inter1_row3 * (1 + diluted_check__interaction_z * (column7_row13 - column7_row5)) + diluted_check__interaction_alpha * (column7_row13 - column7_row5) * (column7_row13 - column7_row5))
{
let val =((/*column9_inter1_row11*/ *borrow(&ctx, 421) + (PRIME - ((fmul(/*column9_inter1_row3*/ *borrow(&ctx, 418), ((1 + fmul(/*diluted_check__interaction_z*/ diluted_check__interaction_z, ((/*column7_row13*/ *borrow(&ctx, 313) + (PRIME - /*column7_row5*/ *borrow(&ctx, 306))) % PRIME))) % PRIME)) + fmul(fmul(/*diluted_check__interaction_alpha*/ diluted_check__interaction_alpha, ((/*column7_row13*/ *borrow(&ctx, 313) + (PRIME - /*column7_row5*/ *borrow(&ctx, 306))) % PRIME)), ((/*column7_row13*/ *borrow(&ctx, 313) + (PRIME - /*column7_row5*/ *borrow(&ctx, 306))) % PRIME))) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 576));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 547));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for diluted_check/last: column9_inter1_row3 - diluted_check__final_cum_val
{
let val =((/*column9_inter1_row3*/ *borrow(&ctx, 418) + (PRIME - /*diluted_check__final_cum_val*/ diluted_check__final_cum_val)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 550));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/last_one_is_zero: column8_row86 * (column3_row0 - (column3_row1 + column3_row1))
{
let val =fmul(/*column8_row86*/ *borrow(&ctx, 380), /*(column3_row0-(column3_row1+column3_row1))*/ *borrow(&ctx, 445));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones0: column8_row86 * (column3_row1 - 3138550867693340381917894711603833208051177722232017256448 * column3_row192)
{
let val =fmul(/*column8_row86*/ *borrow(&ctx, 380), ((/*column3_row1*/ *borrow(&ctx, 237) + (PRIME - fmul(3138550867693340381917894711603833208051177722232017256448, /*column3_row192*/ *borrow(&ctx, 238)))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit192: column8_row86 - column4_row255 * (column3_row192 - (column3_row193 + column3_row193))
{
let val =((/*column8_row86*/ *borrow(&ctx, 380) + (PRIME - fmul(/*column4_row255*/ *borrow(&ctx, 246), ((/*column3_row192*/ *borrow(&ctx, 238) + (PRIME - ((/*column3_row193*/ *borrow(&ctx, 239) + /*column3_row193*/ *borrow(&ctx, 239)) % PRIME))) % PRIME)))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones192: column4_row255 * (column3_row193 - 8 * column3_row196)
{
let val =fmul(/*column4_row255*/ *borrow(&ctx, 246), ((/*column3_row193*/ *borrow(&ctx, 239) + (PRIME - fmul(8, /*column3_row196*/ *borrow(&ctx, 240)))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit196: column4_row255 - (column3_row251 - (column3_row252 + column3_row252)) * (column3_row196 - (column3_row197 + column3_row197))
{
let val =((/*column4_row255*/ *borrow(&ctx, 246) + (PRIME - fmul(((/*column3_row251*/ *borrow(&ctx, 242) + (PRIME - ((/*column3_row252*/ *borrow(&ctx, 243) + /*column3_row252*/ *borrow(&ctx, 243)) % PRIME))) % PRIME), ((/*column3_row196*/ *borrow(&ctx, 240) + (PRIME - ((/*column3_row197*/ *borrow(&ctx, 241) + /*column3_row197*/ *borrow(&ctx, 241)) % PRIME))) % PRIME)))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones196: (column3_row251 - (column3_row252 + column3_row252)) * (column3_row197 - 18014398509481984 * column3_row251)
{
let val =fmul(((/*column3_row251*/ *borrow(&ctx, 242) + (PRIME - ((/*column3_row252*/ *borrow(&ctx, 243) + /*column3_row252*/ *borrow(&ctx, 243)) % PRIME))) % PRIME), ((/*column3_row197*/ *borrow(&ctx, 241) + (PRIME - fmul(18014398509481984, /*column3_row251*/ *borrow(&ctx, 242)))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/booleanity_test: pedersen__hash0__ec_subset_sum__bit_0 * (pedersen__hash0__ec_subset_sum__bit_0 - 1)
{
let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 445), ((/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 445) + (PRIME - 1)) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 578));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 540));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/bit_extraction_end: column3_row0
{
let val =/*column3_row0*/ *borrow(&ctx, 236);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 553));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/zeros_tail: column3_row0
{
let val =/*column3_row0*/ *borrow(&ctx, 236);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 552));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/add_points/slope: pedersen__hash0__ec_subset_sum__bit_0 * (column2_row0 - pedersen__points__y) - column4_row0 * (column1_row0 - pedersen__points__x)
{
let val =((fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 445), ((/*column2_row0*/ *borrow(&ctx, 232) + (PRIME - /*pedersen__points__y*/ pedersen__points__y)) % PRIME)) + (PRIME - fmul(/*column4_row0*/ *borrow(&ctx, 245), ((/*column1_row0*/ *borrow(&ctx, 227) + (PRIME - /*pedersen__points__x*/ pedersen__points__x)) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 578));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 540));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/add_points/x: column4_row0 * column4_row0 - pedersen__hash0__ec_subset_sum__bit_0 * (column1_row0 + pedersen__points__x + column1_row1)
{
let val =((fmul(/*column4_row0*/ *borrow(&ctx, 245), /*column4_row0*/ *borrow(&ctx, 245)) + (PRIME - fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 445), ((((/*column1_row0*/ *borrow(&ctx, 227) + /*pedersen__points__x*/ pedersen__points__x) % PRIME) + /*column1_row1*/ *borrow(&ctx, 228)) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 578));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 540));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/add_points/y: pedersen__hash0__ec_subset_sum__bit_0 * (column2_row0 + column2_row1) - column4_row0 * (column1_row0 - column1_row1)
{
let val =((fmul(/*pedersen__hash0__ec_subset_sum__bit_0*/ *borrow(&ctx, 445), ((/*column2_row0*/ *borrow(&ctx, 232) + /*column2_row1*/ *borrow(&ctx, 233)) % PRIME)) + (PRIME - fmul(/*column4_row0*/ *borrow(&ctx, 245), ((/*column1_row0*/ *borrow(&ctx, 227) + (PRIME - /*column1_row1*/ *borrow(&ctx, 228))) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 578));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 540));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/copy_point/x: pedersen__hash0__ec_subset_sum__bit_neg_0 * (column1_row1 - column1_row0)
{
let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_neg_0*/ *borrow(&ctx, 446), ((/*column1_row1*/ *borrow(&ctx, 228) + (PRIME - /*column1_row0*/ *borrow(&ctx, 227))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 578));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 540));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/ec_subset_sum/copy_point/y: pedersen__hash0__ec_subset_sum__bit_neg_0 * (column2_row1 - column2_row0)
{
let val =fmul(/*pedersen__hash0__ec_subset_sum__bit_neg_0*/ *borrow(&ctx, 446), ((/*column2_row1*/ *borrow(&ctx, 233) + (PRIME - /*column2_row0*/ *borrow(&ctx, 232))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 578));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 540));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/copy_point/x: column1_row256 - column1_row255
{
let val =((/*column1_row256*/ *borrow(&ctx, 230) + (PRIME - /*column1_row255*/ *borrow(&ctx, 229))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 518));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/copy_point/y: column2_row256 - column2_row255
{
let val =((/*column2_row256*/ *borrow(&ctx, 235) + (PRIME - /*column2_row255*/ *borrow(&ctx, 234))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 518));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/init/x: column1_row0 - pedersen__shift_point.x
{
let val =((/*column1_row0*/ *borrow(&ctx, 227) + (PRIME - /*pedersen__shift_point__x*/ pedersen__shift_point__x)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 554));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/hash0/init/y: column2_row0 - pedersen__shift_point.y
{
let val =((/*column2_row0*/ *borrow(&ctx, 232) + (PRIME - /*pedersen__shift_point__y*/ pedersen__shift_point__y)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 554));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/input0_value0: column5_row7 - column3_row0
{
let val =((/*column5_row7*/ *borrow(&ctx, 254) + (PRIME - /*column3_row0*/ *borrow(&ctx, 236))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 554));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/input0_addr: column5_row518 - (column5_row134 + 1)
{
let val =((/*column5_row518*/ *borrow(&ctx, 272) + (PRIME - ((/*column5_row134*/ *borrow(&ctx, 262) + 1) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 535));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 554));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/init_addr: column5_row6 - initial_pedersen_addr
{
let val =((/*column5_row6*/ *borrow(&ctx, 253) + (PRIME - /*initial_pedersen_addr*/ initial_pedersen_addr)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/input1_value0: column5_row263 - column3_row256
{
let val =((/*column5_row263*/ *borrow(&ctx, 267) + (PRIME - /*column3_row256*/ *borrow(&ctx, 244))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 554));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/input1_addr: column5_row262 - (column5_row6 + 1)
{
let val =((/*column5_row262*/ *borrow(&ctx, 266) + (PRIME - ((/*column5_row6*/ *borrow(&ctx, 253) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 554));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/output_value0: column5_row135 - column1_row511
{
let val =((/*column5_row135*/ *borrow(&ctx, 263) + (PRIME - /*column1_row511*/ *borrow(&ctx, 231))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 554));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for pedersen/output_addr: column5_row134 - (column5_row262 + 1)
{
let val =((/*column5_row134*/ *borrow(&ctx, 262) + (PRIME - ((/*column5_row262*/ *borrow(&ctx, 266) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 554));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc_builtin/value: rc_builtin__value7_0 - column5_row71
{
let val =((/*rc_builtin__value7_0*/ *borrow(&ctx, 454) + (PRIME - /*column5_row71*/ *borrow(&ctx, 261))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc_builtin/addr_step: column5_row326 - (column5_row70 + 1)
{
let val =((/*column5_row326*/ *borrow(&ctx, 268) + (PRIME - ((/*column5_row70*/ *borrow(&ctx, 260) + 1) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 536));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for rc_builtin/init_addr: column5_row70 - initial_rc_addr
{
let val =((/*column5_row70*/ *borrow(&ctx, 260) + (PRIME - /*initial_rc_addr*/ initial_rc_addr)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/doubling_key/slope: ecdsa__signature0__doubling_key__x_squared + ecdsa__signature0__doubling_key__x_squared + ecdsa__signature0__doubling_key__x_squared + ecdsa__sig_config.alpha - (column8_row36 + column8_row36) * column8_row50
{
let val =((((((((/*ecdsa__signature0__doubling_key__x_squared*/ *borrow(&ctx, 455) + /*ecdsa__signature0__doubling_key__x_squared*/ *borrow(&ctx, 455)) % PRIME) + /*ecdsa__signature0__doubling_key__x_squared*/ *borrow(&ctx, 455)) % PRIME) + /*ecdsa__sig_config__alpha*/ ecdsa__sig_config__alpha) % PRIME) + (PRIME - fmul(((/*column8_row36*/ *borrow(&ctx, 366) + /*column8_row36*/ *borrow(&ctx, 366)) % PRIME), /*column8_row50*/ *borrow(&ctx, 370)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/doubling_key/x: column8_row50 * column8_row50 - (column8_row4 + column8_row4 + column8_row68)
{
let val =((fmul(/*column8_row50*/ *borrow(&ctx, 370), /*column8_row50*/ *borrow(&ctx, 370)) + (PRIME - ((((/*column8_row4*/ *borrow(&ctx, 355) + /*column8_row4*/ *borrow(&ctx, 355)) % PRIME) + /*column8_row68*/ *borrow(&ctx, 375)) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/doubling_key/y: column8_row36 + column8_row100 - column8_row50 * (column8_row4 - column8_row68)
{
let val =((((/*column8_row36*/ *borrow(&ctx, 366) + /*column8_row100*/ *borrow(&ctx, 383)) % PRIME) + (PRIME - fmul(/*column8_row50*/ *borrow(&ctx, 370), ((/*column8_row4*/ *borrow(&ctx, 355) + (PRIME - /*column8_row68*/ *borrow(&ctx, 375))) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/booleanity_test: ecdsa__signature0__exponentiate_generator__bit_0 * (ecdsa__signature0__exponentiate_generator__bit_0 - 1)
{
let val =fmul(/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 456), ((/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 456) + (PRIME - 1)) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 584));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 557));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/bit_extraction_end: column8_row38
{
let val =/*column8_row38*/ *borrow(&ctx, 367);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 559));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/zeros_tail: column8_row38
{
let val =/*column8_row38*/ *borrow(&ctx, 367);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 558));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/slope: ecdsa__signature0__exponentiate_generator__bit_0 * (column8_row70 - ecdsa__generator_points__y) - column8_row102 * (column8_row6 - ecdsa__generator_points__x)
{
let val =((fmul(/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 456), ((/*column8_row70*/ *borrow(&ctx, 376) + (PRIME - /*ecdsa__generator_points__y*/ ecdsa__generator_points__y)) % PRIME)) + (PRIME - fmul(/*column8_row102*/ *borrow(&ctx, 384), ((/*column8_row6*/ *borrow(&ctx, 356) + (PRIME - /*ecdsa__generator_points__x*/ ecdsa__generator_points__x)) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 584));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 557));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/x: column8_row102 * column8_row102 - ecdsa__signature0__exponentiate_generator__bit_0 * (column8_row6 + ecdsa__generator_points__x + column8_row134)
{
let val =((fmul(/*column8_row102*/ *borrow(&ctx, 384), /*column8_row102*/ *borrow(&ctx, 384)) + (PRIME - fmul(/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 456), ((((/*column8_row6*/ *borrow(&ctx, 356) + /*ecdsa__generator_points__x*/ ecdsa__generator_points__x) % PRIME) + /*column8_row134*/ *borrow(&ctx, 387)) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 584));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 557));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/y: ecdsa__signature0__exponentiate_generator__bit_0 * (column8_row70 + column8_row198) - column8_row102 * (column8_row6 - column8_row134)
{
let val =((fmul(/*ecdsa__signature0__exponentiate_generator__bit_0*/ *borrow(&ctx, 456), ((/*column8_row70*/ *borrow(&ctx, 376) + /*column8_row198*/ *borrow(&ctx, 389)) % PRIME)) + (PRIME - fmul(/*column8_row102*/ *borrow(&ctx, 384), ((/*column8_row6*/ *borrow(&ctx, 356) + (PRIME - /*column8_row134*/ *borrow(&ctx, 387))) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 584));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 557));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/add_points/x_diff_inv: column8_row22 * (column8_row6 - ecdsa__generator_points__x) - 1
{
let val =((fmul(/*column8_row22*/ *borrow(&ctx, 362), ((/*column8_row6*/ *borrow(&ctx, 356) + (PRIME - /*ecdsa__generator_points__x*/ ecdsa__generator_points__x)) % PRIME)) + (PRIME - 1)) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 584));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 557));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/copy_point/x: ecdsa__signature0__exponentiate_generator__bit_neg_0 * (column8_row134 - column8_row6)
{
let val =fmul(/*ecdsa__signature0__exponentiate_generator__bit_neg_0*/ *borrow(&ctx, 457), ((/*column8_row134*/ *borrow(&ctx, 387) + (PRIME - /*column8_row6*/ *borrow(&ctx, 356))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 584));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 557));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_generator/copy_point/y: ecdsa__signature0__exponentiate_generator__bit_neg_0 * (column8_row198 - column8_row70)
{
let val =fmul(/*ecdsa__signature0__exponentiate_generator__bit_neg_0*/ *borrow(&ctx, 457), ((/*column8_row198*/ *borrow(&ctx, 389) + (PRIME - /*column8_row70*/ *borrow(&ctx, 376))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 584));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 557));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/booleanity_test: ecdsa__signature0__exponentiate_key__bit_0 * (ecdsa__signature0__exponentiate_key__bit_0 - 1)
{
let val =fmul(/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 458), ((/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 458) + (PRIME - 1)) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/bit_extraction_end: column8_row12
{
let val =/*column8_row12*/ *borrow(&ctx, 359);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 560));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/zeros_tail: column8_row12
{
let val =/*column8_row12*/ *borrow(&ctx, 359);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 556));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/add_points/slope: ecdsa__signature0__exponentiate_key__bit_0 * (column8_row52 - column8_row36) - column8_row10 * (column8_row20 - column8_row4)
{
let val =((fmul(/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 458), ((/*column8_row52*/ *borrow(&ctx, 371) + (PRIME - /*column8_row36*/ *borrow(&ctx, 366))) % PRIME)) + (PRIME - fmul(/*column8_row10*/ *borrow(&ctx, 358), ((/*column8_row20*/ *borrow(&ctx, 361) + (PRIME - /*column8_row4*/ *borrow(&ctx, 355))) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/add_points/x: column8_row10 * column8_row10 - ecdsa__signature0__exponentiate_key__bit_0 * (column8_row20 + column8_row4 + column8_row84)
{
let val =((fmul(/*column8_row10*/ *borrow(&ctx, 358), /*column8_row10*/ *borrow(&ctx, 358)) + (PRIME - fmul(/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 458), ((((/*column8_row20*/ *borrow(&ctx, 361) + /*column8_row4*/ *borrow(&ctx, 355)) % PRIME) + /*column8_row84*/ *borrow(&ctx, 379)) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/add_points/y: ecdsa__signature0__exponentiate_key__bit_0 * (column8_row52 + column8_row116) - column8_row10 * (column8_row20 - column8_row84)
{
let val =((fmul(/*ecdsa__signature0__exponentiate_key__bit_0*/ *borrow(&ctx, 458), ((/*column8_row52*/ *borrow(&ctx, 371) + /*column8_row116*/ *borrow(&ctx, 386)) % PRIME)) + (PRIME - fmul(/*column8_row10*/ *borrow(&ctx, 358), ((/*column8_row20*/ *borrow(&ctx, 361) + (PRIME - /*column8_row84*/ *borrow(&ctx, 379))) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/add_points/x_diff_inv: column8_row42 * (column8_row20 - column8_row4) - 1
{
let val =((fmul(/*column8_row42*/ *borrow(&ctx, 368), ((/*column8_row20*/ *borrow(&ctx, 361) + (PRIME - /*column8_row4*/ *borrow(&ctx, 355))) % PRIME)) + (PRIME - 1)) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/copy_point/x: ecdsa__signature0__exponentiate_key__bit_neg_0 * (column8_row84 - column8_row20)
{
let val =fmul(/*ecdsa__signature0__exponentiate_key__bit_neg_0*/ *borrow(&ctx, 459), ((/*column8_row84*/ *borrow(&ctx, 379) + (PRIME - /*column8_row20*/ *borrow(&ctx, 361))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/exponentiate_key/copy_point/y: ecdsa__signature0__exponentiate_key__bit_neg_0 * (column8_row116 - column8_row52)
{
let val =fmul(/*ecdsa__signature0__exponentiate_key__bit_neg_0*/ *borrow(&ctx, 459), ((/*column8_row116*/ *borrow(&ctx, 386) + (PRIME - /*column8_row52*/ *borrow(&ctx, 371))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/init_gen/x: column8_row6 - ecdsa__sig_config.shift_point.x
{
let val =((/*column8_row6*/ *borrow(&ctx, 356) + (PRIME - /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/init_gen/y: column8_row70 + ecdsa__sig_config.shift_point.y
{
let val =((/*column8_row70*/ *borrow(&ctx, 376) + /*ecdsa__sig_config__shift_point__y*/ ecdsa__sig_config__shift_point__y) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/init_key/x: column8_row20 - ecdsa__sig_config.shift_point.x
{
let val =((/*column8_row20*/ *borrow(&ctx, 361) + (PRIME - /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/init_key/y: column8_row52 - ecdsa__sig_config.shift_point.y
{
let val =((/*column8_row52*/ *borrow(&ctx, 371) + (PRIME - /*ecdsa__sig_config__shift_point__y*/ ecdsa__sig_config__shift_point__y)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/add_results/slope: column8_row32710 - (column8_row16372 + column8_row32742 * (column8_row32646 - column8_row16340))
{
let val =((/*column8_row32710*/ *borrow(&ctx, 409) + (PRIME - ((/*column8_row16372*/ *borrow(&ctx, 403) + fmul(/*column8_row32742*/ *borrow(&ctx, 412), ((/*column8_row32646*/ *borrow(&ctx, 407) + (PRIME - /*column8_row16340*/ *borrow(&ctx, 398))) % PRIME))) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/add_results/x: column8_row32742 * column8_row32742 - (column8_row32646 + column8_row16340 + column8_row16388)
{
let val =((fmul(/*column8_row32742*/ *borrow(&ctx, 412), /*column8_row32742*/ *borrow(&ctx, 412)) + (PRIME - ((((/*column8_row32646*/ *borrow(&ctx, 407) + /*column8_row16340*/ *borrow(&ctx, 398)) % PRIME) + /*column8_row16388*/ *borrow(&ctx, 405)) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/add_results/y: column8_row32710 + column8_row16420 - column8_row32742 * (column8_row32646 - column8_row16388)
{
let val =((((/*column8_row32710*/ *borrow(&ctx, 409) + /*column8_row16420*/ *borrow(&ctx, 406)) % PRIME) + (PRIME - fmul(/*column8_row32742*/ *borrow(&ctx, 412), ((/*column8_row32646*/ *borrow(&ctx, 407) + (PRIME - /*column8_row16388*/ *borrow(&ctx, 405))) % PRIME)))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/add_results/x_diff_inv: column8_row32662 * (column8_row32646 - column8_row16340) - 1
{
let val =((fmul(/*column8_row32662*/ *borrow(&ctx, 408), ((/*column8_row32646*/ *borrow(&ctx, 407) + (PRIME - /*column8_row16340*/ *borrow(&ctx, 398))) % PRIME)) + (PRIME - 1)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/extract_r/slope: column8_row32756 + ecdsa__sig_config.shift_point.y - column8_row16346 * (column8_row32724 - ecdsa__sig_config.shift_point.x)
{
let val =((((/*column8_row32756*/ *borrow(&ctx, 413) + /*ecdsa__sig_config__shift_point__y*/ ecdsa__sig_config__shift_point__y) % PRIME) + (PRIME - fmul(/*column8_row16346*/ *borrow(&ctx, 399), ((/*column8_row32724*/ *borrow(&ctx, 410) + (PRIME - /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x)) % PRIME)))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/extract_r/x: column8_row16346 * column8_row16346 - (column8_row32724 + ecdsa__sig_config.shift_point.x + column8_row12)
{
let val =((fmul(/*column8_row16346*/ *borrow(&ctx, 399), /*column8_row16346*/ *borrow(&ctx, 399)) + (PRIME - ((((/*column8_row32724*/ *borrow(&ctx, 410) + /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x) % PRIME) + /*column8_row12*/ *borrow(&ctx, 359)) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/extract_r/x_diff_inv: column8_row32730 * (column8_row32724 - ecdsa__sig_config.shift_point.x) - 1
{
let val =((fmul(/*column8_row32730*/ *borrow(&ctx, 411), ((/*column8_row32724*/ *borrow(&ctx, 410) + (PRIME - /*ecdsa__sig_config__shift_point__x*/ ecdsa__sig_config__shift_point__x)) % PRIME)) + (PRIME - 1)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/z_nonzero: column8_row38 * column8_row16378 - 1
{
let val =((fmul(/*column8_row38*/ *borrow(&ctx, 367), /*column8_row16378*/ *borrow(&ctx, 404)) + (PRIME - 1)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/r_and_w_nonzero: column8_row12 * column8_row16370 - 1
{
let val =((fmul(/*column8_row12*/ *borrow(&ctx, 359), /*column8_row16370*/ *borrow(&ctx, 402)) + (PRIME - 1)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/q_on_curve/x_squared: column8_row32762 - column8_row4 * column8_row4
{
let val =((/*column8_row32762*/ *borrow(&ctx, 414) + (PRIME - /*(column8_row4*column8_row4)*/ *borrow(&ctx, 455))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/signature0/q_on_curve/on_curve: column8_row36 * column8_row36 - (column8_row4 * column8_row32762 + ecdsa__sig_config.alpha * column8_row4 + ecdsa__sig_config.beta)
{
let val =((fmul(/*column8_row36*/ *borrow(&ctx, 366), /*column8_row36*/ *borrow(&ctx, 366)) + (PRIME - ((((fmul(/*column8_row4*/ *borrow(&ctx, 355), /*column8_row32762*/ *borrow(&ctx, 414)) + fmul(/*ecdsa__sig_config__alpha*/ ecdsa__sig_config__alpha, /*column8_row4*/ *borrow(&ctx, 355))) % PRIME) + /*ecdsa__sig_config__beta*/ ecdsa__sig_config__beta) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/init_addr: column5_row390 - initial_ecdsa_addr
{
let val =((/*column5_row390*/ *borrow(&ctx, 269) + (PRIME - /*initial_ecdsa_addr*/ initial_ecdsa_addr)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/message_addr: column5_row16774 - (column5_row390 + 1)
{
let val =((/*column5_row16774*/ *borrow(&ctx, 293) + (PRIME - ((/*column5_row390*/ *borrow(&ctx, 269) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/pubkey_addr: column5_row33158 - (column5_row16774 + 1)
{
let val =((/*column5_row33158*/ *borrow(&ctx, 296) + (PRIME - ((/*column5_row16774*/ *borrow(&ctx, 293) + 1) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 537));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/message_value0: column5_row16775 - column8_row38
{
let val =((/*column5_row16775*/ *borrow(&ctx, 294) + (PRIME - /*column8_row38*/ *borrow(&ctx, 367))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ecdsa/pubkey_value0: column5_row391 - column8_row4
{
let val =((/*column5_row391*/ *borrow(&ctx, 270) + (PRIME - /*column8_row4*/ *borrow(&ctx, 355))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 561));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/init_var_pool_addr: column5_row198 - initial_bitwise_addr
{
let val =((/*column5_row198*/ *borrow(&ctx, 264) + (PRIME - /*initial_bitwise_addr*/ initial_bitwise_addr)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/step_var_pool_addr: column5_row454 - (column5_row198 + 1)
{
let val =((/*column5_row454*/ *borrow(&ctx, 271) + (PRIME - ((/*column5_row198*/ *borrow(&ctx, 264) + 1) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 520));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/x_or_y_addr: column5_row902 - (column5_row966 + 1)
{
let val =((/*column5_row902*/ *borrow(&ctx, 274) + (PRIME - ((/*column5_row966*/ *borrow(&ctx, 276) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 563));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/next_var_pool_addr: column5_row1222 - (column5_row902 + 1)
{
let val =((/*column5_row1222*/ *borrow(&ctx, 278) + (PRIME - ((/*column5_row902*/ *borrow(&ctx, 274) + 1) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 538));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 563));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/partition: bitwise__sum_var_0_0 + bitwise__sum_var_8_0 - column5_row199
{
let val =((((/*bitwise__sum_var_0_0*/ *borrow(&ctx, 460) + /*bitwise__sum_var_8_0*/ *borrow(&ctx, 461)) % PRIME) + (PRIME - /*column5_row199*/ *borrow(&ctx, 265))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 551));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/or_is_and_plus_xor: column5_row903 - (column5_row711 + column5_row967)
{
let val =((/*column5_row903*/ *borrow(&ctx, 275) + (PRIME - ((/*column5_row711*/ *borrow(&ctx, 273) + /*column5_row967*/ *borrow(&ctx, 277)) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 563));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/addition_is_xor_with_and: column7_row1 + column7_row257 - (column7_row769 + column7_row513 + column7_row513)
{
let val =((((/*column7_row1*/ *borrow(&ctx, 302) + /*column7_row257*/ *borrow(&ctx, 339)) % PRIME) + (PRIME - ((((/*column7_row769*/ *borrow(&ctx, 347) + /*column7_row513*/ *borrow(&ctx, 341)) % PRIME) + /*column7_row513*/ *borrow(&ctx, 341)) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 564));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/unique_unpacking192: (column7_row705 + column7_row961) * 16 - column7_row9
{
let val =((fmul(((/*column7_row705*/ *borrow(&ctx, 343) + /*column7_row961*/ *borrow(&ctx, 349)) % PRIME), 16) + (PRIME - /*column7_row9*/ *borrow(&ctx, 310))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 563));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/unique_unpacking193: (column7_row721 + column7_row977) * 16 - column7_row521
{
let val =((fmul(((/*column7_row721*/ *borrow(&ctx, 344) + /*column7_row977*/ *borrow(&ctx, 350)) % PRIME), 16) + (PRIME - /*column7_row521*/ *borrow(&ctx, 342))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 563));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/unique_unpacking194: (column7_row737 + column7_row993) * 16 - column7_row265
{
let val =((fmul(((/*column7_row737*/ *borrow(&ctx, 345) + /*column7_row993*/ *borrow(&ctx, 351)) % PRIME), 16) + (PRIME - /*column7_row265*/ *borrow(&ctx, 340))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 563));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for bitwise/unique_unpacking195: (column7_row753 + column7_row1009) * 256 - column7_row777
{
let val =((fmul(((/*column7_row753*/ *borrow(&ctx, 346) + /*column7_row1009*/ *borrow(&ctx, 352)) % PRIME), 256) + (PRIME - /*column7_row777*/ *borrow(&ctx, 348))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 563));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/init_addr: column5_row8582 - initial_ec_op_addr
{
let val =((/*column5_row8582*/ *borrow(&ctx, 285) + (PRIME - /*initial_ec_op_addr*/ initial_ec_op_addr)) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 544));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/p_x_addr: column5_row24966 - (column5_row8582 + 7)
{
let val =((/*column5_row24966*/ *borrow(&ctx, 295) + (PRIME - ((/*column5_row8582*/ *borrow(&ctx, 285) + 7) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 539));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/p_y_addr: column5_row4486 - (column5_row8582 + 1)
{
let val =((/*column5_row4486*/ *borrow(&ctx, 281) + (PRIME - ((/*column5_row8582*/ *borrow(&ctx, 285) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/q_x_addr: column5_row12678 - (column5_row4486 + 1)
{
let val =((/*column5_row12678*/ *borrow(&ctx, 289) + (PRIME - ((/*column5_row4486*/ *borrow(&ctx, 281) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/q_y_addr: column5_row2438 - (column5_row12678 + 1)
{
let val =((/*column5_row2438*/ *borrow(&ctx, 279) + (PRIME - ((/*column5_row12678*/ *borrow(&ctx, 289) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/m_addr: column5_row10630 - (column5_row2438 + 1)
{
let val =((/*column5_row10630*/ *borrow(&ctx, 287) + (PRIME - ((/*column5_row2438*/ *borrow(&ctx, 279) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/r_x_addr: column5_row6534 - (column5_row10630 + 1)
{
let val =((/*column5_row6534*/ *borrow(&ctx, 283) + (PRIME - ((/*column5_row10630*/ *borrow(&ctx, 287) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/r_y_addr: column5_row14726 - (column5_row6534 + 1)
{
let val =((/*column5_row14726*/ *borrow(&ctx, 291) + (PRIME - ((/*column5_row6534*/ *borrow(&ctx, 283) + 1) % PRIME))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/doubling_q/slope: ec_op__doubling_q__x_squared_0 + ec_op__doubling_q__x_squared_0 + ec_op__doubling_q__x_squared_0 + ec_op__curve_config.alpha - (column8_row28 + column8_row28) * column8_row60
{
let val =((((((((/*ec_op__doubling_q__x_squared_0*/ *borrow(&ctx, 462) + /*ec_op__doubling_q__x_squared_0*/ *borrow(&ctx, 462)) % PRIME) + /*ec_op__doubling_q__x_squared_0*/ *borrow(&ctx, 462)) % PRIME) + /*ec_op__curve_config__alpha*/ ec_op__curve_config__alpha) % PRIME) + (PRIME - fmul(((/*column8_row28*/ *borrow(&ctx, 364) + /*column8_row28*/ *borrow(&ctx, 364)) % PRIME), /*column8_row60*/ *borrow(&ctx, 373)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/doubling_q/x: column8_row60 * column8_row60 - (column8_row44 + column8_row44 + column8_row108)
{
let val =((fmul(/*column8_row60*/ *borrow(&ctx, 373), /*column8_row60*/ *borrow(&ctx, 373)) + (PRIME - ((((/*column8_row44*/ *borrow(&ctx, 369) + /*column8_row44*/ *borrow(&ctx, 369)) % PRIME) + /*column8_row108*/ *borrow(&ctx, 385)) % PRIME))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/doubling_q/y: column8_row28 + column8_row92 - column8_row60 * (column8_row44 - column8_row108)
{
let val =((((/*column8_row28*/ *borrow(&ctx, 364) + /*column8_row92*/ *borrow(&ctx, 381)) % PRIME) + (PRIME - fmul(/*column8_row60*/ *borrow(&ctx, 373), ((/*column8_row44*/ *borrow(&ctx, 369) + (PRIME - /*column8_row108*/ *borrow(&ctx, 385))) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/get_q_x: column5_row12679 - column8_row44
{
let val =((/*column5_row12679*/ *borrow(&ctx, 290) + (PRIME - /*column8_row44*/ *borrow(&ctx, 369))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/get_q_y: column5_row2439 - column8_row28
{
let val =((/*column5_row2439*/ *borrow(&ctx, 280) + (PRIME - /*column8_row28*/ *borrow(&ctx, 364))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/bit_unpacking/last_one_is_zero: column8_row16362 * (column8_row18 - (column8_row82 + column8_row82))
{
let val =fmul(/*column8_row16362*/ *borrow(&ctx, 401), /*(column8_row18-(column8_row82+column8_row82))*/ *borrow(&ctx, 463));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/bit_unpacking/zeroes_between_ones0: column8_row16362 * (column8_row82 - 3138550867693340381917894711603833208051177722232017256448 * column8_row12306)
{
let val =fmul(/*column8_row16362*/ *borrow(&ctx, 401), ((/*column8_row82*/ *borrow(&ctx, 378) + (PRIME - fmul(3138550867693340381917894711603833208051177722232017256448, /*column8_row12306*/ *borrow(&ctx, 390)))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/bit_unpacking/cumulative_bit192: column8_row16362 - column8_row16330 * (column8_row12306 - (column8_row12370 + column8_row12370))
{
let val =((/*column8_row16362*/ *borrow(&ctx, 401) + (PRIME - fmul(/*column8_row16330*/ *borrow(&ctx, 397), ((/*column8_row12306*/ *borrow(&ctx, 390) + (PRIME - ((/*column8_row12370*/ *borrow(&ctx, 391) + /*column8_row12370*/ *borrow(&ctx, 391)) % PRIME))) % PRIME)))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/bit_unpacking/zeroes_between_ones192: column8_row16330 * (column8_row12370 - 8 * column8_row12562)
{
let val =fmul(/*column8_row16330*/ *borrow(&ctx, 397), ((/*column8_row12370*/ *borrow(&ctx, 391) + (PRIME - fmul(8, /*column8_row12562*/ *borrow(&ctx, 392)))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/bit_unpacking/cumulative_bit196: column8_row16330 - (column8_row16082 - (column8_row16146 + column8_row16146)) * (column8_row12562 - (column8_row12626 + column8_row12626))
{
let val =((/*column8_row16330*/ *borrow(&ctx, 397) + (PRIME - fmul(((/*column8_row16082*/ *borrow(&ctx, 394) + (PRIME - ((/*column8_row16146*/ *borrow(&ctx, 395) + /*column8_row16146*/ *borrow(&ctx, 395)) % PRIME))) % PRIME), ((/*column8_row12562*/ *borrow(&ctx, 392) + (PRIME - ((/*column8_row12626*/ *borrow(&ctx, 393) + /*column8_row12626*/ *borrow(&ctx, 393)) % PRIME))) % PRIME)))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/bit_unpacking/zeroes_between_ones196: (column8_row16082 - (column8_row16146 + column8_row16146)) * (column8_row12626 - 18014398509481984 * column8_row16082)
{
let val =fmul(((/*column8_row16082*/ *borrow(&ctx, 394) + (PRIME - ((/*column8_row16146*/ *borrow(&ctx, 395) + /*column8_row16146*/ *borrow(&ctx, 395)) % PRIME))) % PRIME), ((/*column8_row12626*/ *borrow(&ctx, 393) + (PRIME - fmul(18014398509481984, /*column8_row16082*/ *borrow(&ctx, 394)))) % PRIME));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/booleanity_test: ec_op__ec_subset_sum__bit_0 * (ec_op__ec_subset_sum__bit_0 - 1)
{
let val =fmul(/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 463), ((/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 463) + (PRIME - 1)) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/bit_extraction_end: column8_row18
{
let val =/*column8_row18*/ *borrow(&ctx, 360);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 565));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/zeros_tail: column8_row18
{
let val =/*column8_row18*/ *borrow(&ctx, 360);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 556));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/add_points/slope: ec_op__ec_subset_sum__bit_0 * (column8_row34 - column8_row28) - column8_row26 * (column8_row2 - column8_row44)
{
let val =((fmul(/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 463), ((/*column8_row34*/ *borrow(&ctx, 365) + (PRIME - /*column8_row28*/ *borrow(&ctx, 364))) % PRIME)) + (PRIME - fmul(/*column8_row26*/ *borrow(&ctx, 363), ((/*column8_row2*/ *borrow(&ctx, 354) + (PRIME - /*column8_row44*/ *borrow(&ctx, 369))) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/add_points/x: column8_row26 * column8_row26 - ec_op__ec_subset_sum__bit_0 * (column8_row2 + column8_row44 + column8_row66)
{
let val =((fmul(/*column8_row26*/ *borrow(&ctx, 363), /*column8_row26*/ *borrow(&ctx, 363)) + (PRIME - fmul(/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 463), ((((/*column8_row2*/ *borrow(&ctx, 354) + /*column8_row44*/ *borrow(&ctx, 369)) % PRIME) + /*column8_row66*/ *borrow(&ctx, 374)) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/add_points/y: ec_op__ec_subset_sum__bit_0 * (column8_row34 + column8_row98) - column8_row26 * (column8_row2 - column8_row66)
{
let val =((fmul(/*ec_op__ec_subset_sum__bit_0*/ *borrow(&ctx, 463), ((/*column8_row34*/ *borrow(&ctx, 365) + /*column8_row98*/ *borrow(&ctx, 382)) % PRIME)) + (PRIME - fmul(/*column8_row26*/ *borrow(&ctx, 363), ((/*column8_row2*/ *borrow(&ctx, 354) + (PRIME - /*column8_row66*/ *borrow(&ctx, 374))) % PRIME)))) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/add_points/x_diff_inv: column8_row58 * (column8_row2 - column8_row44) - 1
{
let val =((fmul(/*column8_row58*/ *borrow(&ctx, 372), ((/*column8_row2*/ *borrow(&ctx, 354) + (PRIME - /*column8_row44*/ *borrow(&ctx, 369))) % PRIME)) + (PRIME - 1)) % PRIME);
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/copy_point/x: ec_op__ec_subset_sum__bit_neg_0 * (column8_row66 - column8_row2)
{
let val =fmul(/*ec_op__ec_subset_sum__bit_neg_0*/ *borrow(&ctx, 464), ((/*column8_row66*/ *borrow(&ctx, 374) + (PRIME - /*column8_row2*/ *borrow(&ctx, 354))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/ec_subset_sum/copy_point/y: ec_op__ec_subset_sum__bit_neg_0 * (column8_row98 - column8_row34)
{
let val =fmul(/*ec_op__ec_subset_sum__bit_neg_0*/ *borrow(&ctx, 464), ((/*column8_row98*/ *borrow(&ctx, 382) + (PRIME - /*column8_row34*/ *borrow(&ctx, 365))) % PRIME));
// Numerator
// val *= numerator
val = fmul(val, *borrow(&ctx, 582));

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 555));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/get_m: column8_row18 - column5_row10631
{
let val =((/*column8_row18*/ *borrow(&ctx, 360) + (PRIME - /*column5_row10631*/ *borrow(&ctx, 288))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/get_p_x: column5_row8583 - column8_row2
{
let val =((/*column5_row8583*/ *borrow(&ctx, 286) + (PRIME - /*column8_row2*/ *borrow(&ctx, 354))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/get_p_y: column5_row4487 - column8_row34
{
let val =((/*column5_row4487*/ *borrow(&ctx, 282) + (PRIME - /*column8_row34*/ *borrow(&ctx, 365))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/set_r_x: column5_row6535 - column8_row16322
{
let val =((/*column5_row6535*/ *borrow(&ctx, 284) + (PRIME - /*column8_row16322*/ *borrow(&ctx, 396))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

res = (res + fmul(val, composition_alpha_pow)) % PRIME;
composition_alpha_pow = fmul(composition_alpha_pow, composition_alpha);

};

//Constraint expression for ec_op/set_r_y: column5_row14727 - column8_row16354
{
let val =((/*column5_row14727*/ *borrow(&ctx, 292) + (PRIME - /*column8_row16354*/ *borrow(&ctx, 400))) % PRIME);

// Denominator
// val *= denominator inverse
 val = fmul(val, *borrow(&ctx, 562));

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
