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
        mod_mul(a, b, K_MODULUS)
    }

    public fun from_montgomery(val: u256): u256 {
        fmul(val, K_MONTGOMERY_R_INV)
    }

    public fun from_montgomery_bytes(bs: vector<u8>): u256 {
        from_montgomery(from_bcs::to_u256(bs))
    }

    public fun to_montgomery_int(val: u256): u256 {
        fmul(val, K_MONTGOMERY_R)
    }

    public fun fadd(a: u256, b: u256): u256 {
        mod_add(a, b, K_MODULUS)
    }

    public fun fsub(a: u256, b: u256): u256 {
        mod_sub(a, b, K_MODULUS)
    }

    public fun fpow(val: u256, exp: u256): u256 {
        mod_exp(val, exp, K_MODULUS)
    }

    public fun inverse(val: u256): u256 {
        mod_exp(val, K_MODULUS - 2, K_MODULUS)
    }

    #[test_only]
    use aptos_std::debug;
    use aptos_std::debug::print;
    use aptos_std::math128::pow;
    use lib_addr::math_mod::{mod_mul, mod_add, mod_sub, mod_exp};

    #[test()]
    fun test_fpow() {
        let res = fmul(K_MONTGOMERY_R, K_MONTGOMERY_R);
        print(&res);
    }
}



