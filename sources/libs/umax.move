module lib_addr::umax {
    const U256_MAX: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffu256;
    const U128_MAX: u128 = 0xffffffffffffffffffffffffffffffffu128;
    const U64_MAX: u64 = 0xffffffffffffffffu64;
    const U32_MAX: u32 = 0xffffffffu32;
    const U16_MAX: u16 = 0xffffu16;
    const U8_MAX: u8 = 0xffu8;

    public fun u256_max(): u256 {
        return U256_MAX
    }

    public fun u128_max(): u128 {
        return U128_MAX
    }

    public fun u64_max(): u64 {
        return U64_MAX
    }

    public fun u32_max(): u32 {
        return U32_MAX
    }

    public fun u16_max(): u16 {
        return U16_MAX
    }

    public fun u8_max(): u8 {
        return U8_MAX
    }
}