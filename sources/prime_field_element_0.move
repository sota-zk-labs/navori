module verifier_addr::prime_field_element_0 {
    use aptos_std::from_bcs;

    // #[test_only]
    // use aptos_std::debug::print;

    // This line is used for generating constants DO NOT REMOVE!
    // 3
    const GENERATOR_VAL: u256 = 0x3;
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    const MASK: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // 3618502788666127798953978732740734578953660990361066340291730267701097005025
    const K_MONTGOMERY_R: u256 = 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1;
    // 113078212145816603762751633895895194930089271709401121343797004406777446400
    const K_MONTGOMERY_R_INV: u256 = 0x40000000000001100000000000012100000000000000000000000000000000;
    // 1
    const ONE_VAL: u256 = 0x1;
    // End of generating constants!

    const MAX_U128: u256 = 0xffffffffffffffffffffffffffffffff;
    const K_MODULUS_0: u256 = 0x8000000000000110000000000000000;

    // formula: a * b = q * K_MODULUS + r
    // split a, b into two limbs: a = a_0 * 2 ^ 128 + a_1
    // let ab = a * b = (a_0 * 2 ^ 128 + a_1) * (b_0 * 2 ^ 128 + b_1)
    // = (a_0 * b_0 * 2 ^ 256) + (a_0 * b_1 + a_1 * b_0) * 2^128 + (a_1 * b_1)
    // let ab_mid = (a_0 * b_1 + a_1 * b_0) = ab_mid_0 * 2 ^ 128 + ab_mid_1
    // then ab = (a_0 * b_0 + ab_mid_0) * 2 ^ 256 + (ab_mid_1 * 2 ^ 128 + a_1 * b_1) = ab_0 * 2 ^ 256 + ab_1
    // q = q_0 * 2 ^ 128 + q_1
    // K_MODULUS = K_MODULUS_0 * 2 ^ 128 + K_MODULUS_1
    // K_MODULUS_1 = 1;
    // optimistically cal q_0 = ab_0 / K_MODULUS_0, set q_1 = 0
    // let qk = q * K_MODULUS; 
    // using the technique above, cal qk_mid = qk_mid_0 + qk_mid_1
    // res = (ab - qk) mod k
    // OPTIMIZED: LAST_MODULUS=1
    // qk_mid_0 = 0
    // qk_mid_1 = qq_0
    public fun fmul(a: u256, b: u256): u256 {
        // assumming a, b < K_MODULUS
        // a = a % K_MODULUS;
        // b = b % K_MODULUS;
        let a_0 = a >> 128;
        let a_1 = a & MAX_U128;

        let b_0 = b >> 128;
        let b_1 = b & MAX_U128;

        let ab_mid = a_0 * b_1 + b_0 * a_1;
        let ab_mid_0 = ab_mid >> 128;
        let ab_mid_1 = ab_mid & MAX_U128;

        let ab_0 = a_0 * b_0 + ab_mid_0;

        let q_0 = ab_0 / K_MODULUS_0;

        let qk_mid_1 = q_0;
        let qk_0 = q_0 * K_MODULUS_0;

        let upper_left = ab_0 - qk_0;

        let upper_left_a = upper_left << 128;

        // compute div of x =(x_0 * 2 ^ 256 + x_1 * 2 ^ 128) / 2 ^ 128
        let div = upper_left_a / K_MODULUS_0;
        let remainder = upper_left_a - div * K_MODULUS_0;
        let remainder = ((remainder << 128) - div) % K_MODULUS;

        let ab_1 = (remainder + (a_1 * b_1) % K_MODULUS + (ab_mid_1 << 128) % K_MODULUS);
        let qk_1 = (qk_mid_1 << 128) % K_MODULUS;

        let res = (K_MODULUS - qk_1 + ab_1) % K_MODULUS;
        res
    }

    public fun naive_mul_mod(a: u256, b: u256): u256 {
        let res = 0;
        while (b > 0) {
            let aa = b & 15;
            if (aa != 0) {
                res = (res + a * aa) % K_MODULUS;
            };

            a = (a << 4) % K_MODULUS;
            b = b >> 4;
        };
        res
    }

    public fun from_montgomery(val: u256): u256 {
        let res = fmul(val, K_MONTGOMERY_R_INV);
        res
    }

    public fun from_montgomery_bytes(bs: vector<u8>): u256 {
        let res = from_bcs::to_u256(bs);
        from_montgomery(res)
    }

    public fun to_montgomery_int(val: u256): u256 {
        let res = fmul(val, K_MONTGOMERY_R);
        res
    }

    public fun fadd(a: u256, b: u256): u256 {
        let res = a + b;
        let res = res % K_MODULUS;
        res
    }

    public fun fsub(a: u256, b: u256): u256 {
        fadd(a, K_MODULUS - b)
    }

    public fun fpow(val: u256, exp: u256): u256 {
        expmod(val, exp, K_MODULUS)
    }

    fun expmod(base: u256, exponent: u256, modulus: u256): u256 {
        let res: u256 = 1;
        let base = base % modulus;
        let exponent = exponent;

        while (exponent > 0) {
            if (exponent % 2 == 1) {
                res = fmul(res, base);
            };
            exponent = exponent / 2;
            base = fmul(base, base);
        };
        res
    }

    public fun inverse(val: u256): u256 {
        expmod(val, K_MODULUS - 2, K_MODULUS)
    }


    #[test(s = @verifier_addr)]
    fun testmath_basic() {
        let res = 8 % K_MODULUS;
        assert!(res == 8, 1);
    }

    #[test(s = @verifier_addr)]
    fun test_expmod() {
        let res = expmod(0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539, 15, K_MODULUS);
        assert!(res == 2607735469685256064975697808597423000021425046638838630471627721324227832437, 1);
    }

    #[test(s = @verifier_addr)]
    fun tes_mulmod() {
        let res = fmul(
            0x800000000000011000000000000000000000000000000000000000000000000,
            0x800000000000011000000000000000000000000000000000000000000000000
        );
        assert!(res == 1, 1);
    }

    #[test(s = @verifier_addr)]
    fun tes_mulmod1() {
        let res = fmul(
            0x6f31595cf7b7c9239fde468365c31cb213f6e99bfac7e9f13c6063a760a28f3,
            0x6f31595cf7b7c9239fde468365c31cb213f6e99bfac7e9f13c6063a760a28f3
        );
        assert!(res == 0x3640da36d563e087290172eec26556cf9359dd4800d74e854504b7dbae81ba4, 1);
        // assert!(res == 0x6097aa03e733f4c41191a1dd5731289c210364e1183819f428704c582a0bb05, 1);
    }

    #[test(s = @verifier_addr)]
    fun tes_mulmod2() {
        let res = fmul(
            0x6f31595cf7b7c9239fde468365c31cb213f6e99bfac7e9f13c6063a760a28f3,
            0x5f31595cf7b7c9239fde468365c31cb213f6e99bfac7e9f13c6063a760a28f3
        );
        assert!(res == 0x2fdbdfde6ae533be13e17f0d624c8bb2b9bef967b4dfe911d5b500f2084da17, 1);
        // assert!(res == 0x6097aa03e733f4c41191a1dd5731289c210364e1183819f428704c582a0bb05, 1);
    }

    #[test(s = @verifier_addr)]
    fun tes_mulmod3() {
        let res = fmul(
            0x5f31595cf7b7c9239fde468365c31cb213f6e99bfac7e9f13c6063a760a28f3,
            1
        );
        assert!(res == 0x5f31595cf7b7c9239fde468365c31cb213f6e99bfac7e9f13c6063a760a28f3, 1);
        // assert!(res == 0x6097aa03e733f4c41191a1dd5731289c210364e1183819f428704c582a0bb05, 1);
    }
}



