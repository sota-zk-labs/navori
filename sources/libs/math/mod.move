module lib_addr::math_mod {

    use aptos_std::debug::print;

    public fun mod_add(a: u256, b: u256, k: u256): u256 {
        (a % k) + (b % k) % k
    }

    public fun mod_sub(a: u256, b: u256, k: u256): u256 {
        ((a % k) - (b % k) + k) % k
    }

    public fun mod_mul(a: u256, b: u256, k: u256): u256 {
        let res = 0;
        a = a % k;
        while (b > 0) {
            if (b % 2 == 1) {
                res = (res + a) % k;
            };

            a = (a << 1) % k;
            b = b >> 1;
        };
        res
    }

    public fun mod_div(a: u256, b: u256, k: u256): u256 {
        ((a % k) / (b % k)) % k
    }

    public fun mod_exp(b: u256, e: u256, k: u256): u256 {
        let res: u256 = 1;
        b = b % k;

        while (e > 0) {
            if (e % 2 == 1) {
                res = mod_mul(res, b, k);
            };
            e = e >> 1;
            b = mod_mul(b, b, k);
        };
        res
    }

    // #[test_only]
    // use aptos_std::debug::print;

    #[test]
    fun test_mod_add_max() {
        let a = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
        let b = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
        let k = 0x800000000000011000000000000000000000000000000000000000000000001;
        let res = mod_add(a, b, k);
        print(&res);
        // assert(res == 0, 1);
    }

    #[test]
    fun test_mod_sub_max() {
        let a = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
        let b = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
        let k = 0x800000000000011000000000000000000000000000000000000000000000001;
        let res = mod_sub(a, b, k);
        print(&res);
        assert(res == 0, 1);
    }

    #[test]
    fun test_mod_mul_max() {
        let a = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
        let b = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
        let k = 0x800000000000011000000000000000000000000000000000000000000000001;
        let res = mod_mul(a, b, k);

        print(&res);
    }

    #[test]
    fun test_mod_div_max() {
        let a = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
        let b = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
        let k = 0x800000000000011000000000000000000000000000000000000000000000001;
        let res = mod_div(a, b, k);

        print(&res);
        assert!(res == 1, 1);

    }
}