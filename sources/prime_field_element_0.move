module verifier_addr::prime_field_element_0 {
    use aptos_std::from_bcs;

    const K_MODULUS : u256= 0x800000000000011000000000000000000000000000000000000000000000001;
    const K_MONTGOMERY_R : u256 = 0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1;
    const K_MONTGOMERY_R_INV : u256 = 0x40000000000001100000000000012100000000000000000000000000000000;
    const GENERATOR_VAL : u64 = 3;
    const ONE_VAL : u64 = 1;

    public fun fmul(a: u256, b: u256) : u256 {
        let res = a * b;
        let res = res % K_MODULUS;
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
        let res = expmod(2, 3, 5);
        assert!(res == 3, 2);
    }
    #[test(s = @verifier_addr)]
    fun test_fpow() {
        let res = fpow(2,3);
        assert!(res == 8, 3);
    }
}



