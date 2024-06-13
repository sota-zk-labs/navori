module lib_addr::bitwise {
    use lib_addr::umax::u256_max;

    public fun not(value: u256): u256 {
        let all_ones: u256 = u256_max();

        let inverted_value: u256 = value ^ all_ones;
        return inverted_value
    }

    #[test]
    fun test_not() {
        assert!(not(0u256) == 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256, 1);
        assert!(
            not(
                0x00000000000000000000000000000000ffffffffffffffffffffffffffffffffu256
            ) == 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000u256,
            1
        );
    }
}