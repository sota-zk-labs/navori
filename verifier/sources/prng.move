module verifier_addr::prng {
    use std::vector::borrow;
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_be};
    use lib_addr::vector::set_el;

    public fun store_prng(ctx: &mut vector<u256>, prng_ptr: u64, digest: u256, counter: u256) {
        set_el(ctx, prng_ptr, digest);
        set_el(ctx, prng_ptr + 1, counter);
    }

    public fun load_prng(ctx: &vector<u256>, prng_ptr: u64): (u256, u256) {
        let digest = *borrow(ctx, prng_ptr);
        let counter = *borrow(ctx, prng_ptr + 1);
        (digest, counter)
    }

    public fun init_prng(ctx: &mut vector<u256>, prng_ptr: u64, public_input_hash: u256) {
        store_prng(ctx, prng_ptr, public_input_hash, 0);
    }

    /*
      Auxiliary function for getRandomBytes.
    */
    fun get_random_bytes_inner(digest: u256, counter: u256): (u256, u256, u256) {
        let random_bytes = bytes32_to_u256(keccak256(vec_to_bytes_be(&vector[digest, counter])));
        (digest, counter + 1, random_bytes)
    }

    public fun get_random_bytes(ctx: &mut vector<u256>, prng_ptr: u64): u256 {
        let (digest, counter) = load_prng(ctx, prng_ptr);
        let (digest, counter, random_bytes) = get_random_bytes_inner(digest, counter);
        store_prng(ctx, prng_ptr, digest, counter);
        random_bytes
    }
}