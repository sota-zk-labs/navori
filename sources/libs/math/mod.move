module lib_addr::math_mod {

    #[test_only]
    use aptos_std::debug::print;

    public fun mod_add(a: u256, b: u256, k: u256): u256 {
        let res = a % k + b % k;
        return if (res < k) { res } else { res - k }
    }

    public fun mod_sub(a: u256, b: u256, k: u256): u256 {
        let res = a % k - b % k;
        return if (res < 0) { res + k } else { res }
    }

    public fun mod_mul(a: u256, b: u256, k: u256): u256 {
        let res = 0;
        a = a % k;
        b = b % k;
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
        mod_mul(a, mod_exp(b, k - 2, k), k)
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
        assert!(res == 1, 1);
    }

    #[test()]
    fun test_expmod() {
        let a = 0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539;
        let b = 15;
        let c = 2607735469685256064975697808597423000021425046638838630471627721324227832437;
        let k = 0x800000000000011000000000000000000000000000000000000000000000001;
        let res = mod_exp(a, b, k);
        assert!(res == c, 1);
    }

    #[test]
    fun test_mod_div() {
        assert!(mod_div(21, 3, 5) == 2, 1);
        assert!(mod_div(24, 4, 5) == 1, 1);
    }
}