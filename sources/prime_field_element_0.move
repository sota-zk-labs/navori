module verifier_addr::prime_field_element_0 {
    use aptos_std::from_bcs;
    use aptos_std::;
    #[test_only]
    use aptos_std::debug;

    const K_MODULUS : u256= 0x800000000000011000000000000000000000000000000000000000000000001;
    const K_MONTGOMERY_R : u256 = 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1;
    const K_MONTGOMERY_R_INV : u256 = 0x40000000000001100000000000012100000000000000000000000000000000;
    const GENERATOR_VAL : u256 = 3;
    const ONE_VAL : u256 = 1;

    public fun fmul(a: u256, b: u256) : u256 {
        let  res = 0;
        let  temp_b = b;

        // While second number doesn't become 1
        while (temp_b > 0) {
        // If second number becomes odd, add the first number to result
        if (temp_b % 2 == 1) {
        res = (res + a) % K_MODULUS;
        };

        // Double the first number and halve the second number
        a = (a * 2) % K_MODULUS;
        temp_b = temp_b / 2;
        };

        res = res % K_MODULUS;
        res
    }

    public fun from_montgomery(val: u256) : u256 {
        let res = fmul(val, K_MONTGOMERY_R_INV);
        res
    }

    public fun from_montgomery_bytes(bs : vector<u8>) : u256{
        let res = from_bcs::to_u256(bs);
        from_montgomery(res)

    }

    public fun to_montgomery_int(val : u256) : u256 {
        let res = fmul(val, K_MONTGOMERY_R);
        res
    }

    public fun fadd(a : u256, b: u256) : u256 {
        let res = a + b;
        let res = res % K_MODULUS;
        res
    }

    public fun fsub(a : u256, b: u256) : u256 {
        fadd(a, K_MODULUS - b)
    }

    public fun fpow(val : u256, exp : u256) : u256 {
        expmod(val,exp, K_MODULUS)
    }

    fun expmod(base: u256, exponent: u256, modulus: u256) :u256 {
        let  res: u256 = 1;
        let  base = base % modulus;
        let  exponent = exponent;

        while (exponent > 0) {
            if (exponent % 2 == 1) {
                res = (res * base) % modulus;
            };
            exponent = exponent / 2;
            base = (base * base) % modulus;
        };
        res
    }
    public fun left_shift(val: u256, shift: u256): u256 {
        let  res = val;
        let  count = shift;

        while (count > 0) {
        res = res * 2;
        count = count - 1;
        };

        res
    }

    public fun montgomery_reduction(a: u256, b: u256, modulus: u256): u256 {
        let t: u256 = a * b;
        let m: u256 = (t * K_MONTGOMERY_R_INV) % modulus;
        let u: u256 = (t + m * modulus) / (left_shift(1,256));

        if (u >= modulus) {
            u = u - modulus;
        };
        u
    }

    public fun montgomery_pow(base: u256, exponent: u256, modulus: u256): u256 {
        let  res: u256 = to_montgomery_int(ONE_VAL);
        let  base = to_montgomery_int(base);
        let  exponent = exponent;

        while (exponent > 0) {
            if (exponent % 2 == 1) {
                res = montgomery_reduction(res, base, modulus);
            };
            base = montgomery_reduction(base, base, modulus);
            exponent = exponent / 2;
        };
        from_montgomery(res)
    }


    public fun inverse(val: u256): u256 {
        expmod(val, K_MODULUS - 2, K_MODULUS)
    }



    #[test(s = @verifier_addr)]

    fun testmath_basic() {
        let test1 : u256 = 0x100;
        let test2 : u256 = test1;
        let res =  8 % K_MODULUS;
        assert!(res == 8,1);

    }
    #[test(s = @verifier_addr)]
    fun test_expmod() {
        let base :u256 = 0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539;

        let res = montgomery_pow(0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539, 15, K_MODULUS);
        assert!(res == 3, 2);
    }
    #[test(s = @verifier_addr)]
    fun test_fpow() {
        let res = fpow(2,3);
        assert!(res == 8, 3);
    }
}



