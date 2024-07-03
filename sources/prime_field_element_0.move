module verifier_addr::prime_field_element_0 {
    use aptos_std::from_bcs;

    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    const K_MONTGOMERY_R: u256 = 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1;
    const K_MONTGOMERY_R_INV: u256 = 0x40000000000001100000000000012100000000000000000000000000000000;
    const GENERATOR_VAL: u256 = 3;
    const ONE_VAL: u256 = 1;

    public fun k_modulus(): u256 {
        K_MODULUS
    }

    public fun k_montgomery_r(): u256 {
        K_MONTGOMERY_R
    }

    public fun k_montgomery_r_inv(): u256 {
        K_MONTGOMERY_R_INV
    }

    public fun generator_val(): u256 {
        GENERATOR_VAL
    }

    public fun one_val(): u256 {
        ONE_VAL
    }


    public fun fmul(a: u256, b: u256): u256 {
        let res = 0;
        a = a % K_MODULUS;
        while (b > 0) {
            if (b % 2 == 1) {
                res = (res + a) % K_MODULUS;
            };

            a = (a * 2) % K_MODULUS;
            b = b / 2;
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

    public fun left_shift(val: u256, shift: u256): u256 {
        let res = val;
        let count = shift;

        while (count > 0) {
            res = res * 2;
            count = count - 1;
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
}



