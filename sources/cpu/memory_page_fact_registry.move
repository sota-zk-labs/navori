module verifier_addr::memory_page_fact_registry {
    use std::vector::{for_each, length, borrow};
    use aptos_std::aptos_hash::keccak256;
    use aptos_framework::event::{emit};
    use lib_addr::bytes::{u256_from_bytes_be, vec_to_bytes_be};

    use lib_addr::math_mod::{mod_mul, mod_add};
    use verifier_addr::fact_registry::register_fact;

    //Errors
    const TOO_MANY_MEMORY_VALUES: u64 = 1;
    const SIZE_OF_MEMORYPAIRS_MUST_BE_EVEN: u64 = 2;
    const INVALID_VALUE_OF_Z: u64 = 3;
    const INVALID_VALUE_OF_ALPHA: u64 = 4;
    const PRIME_IS_TOO_BIG: u64 = 5;
    const INVALID_VALUE_OF_START_ADDRESS: u64 = 6;


    #[event]
    struct LogMemorypPageFactRegular has store, drop {
        fact_hash: u256,
        memory_hash: u256,
        prod: u256
    }

    #[event]
    struct LogMemoryPageFactContinuous has store, drop {
        fact_hash: u256,
        memory_hash: u256,
        prod: u256
    }

    public fun register_regular_memorypage(
        signer: &signer,
        memory_pairs: vector<u256>,
        z: u256,
        alpha: u256,
        prime: u256
    ): (u256, u256, u256) {
        assert!(length(&memory_pairs) < (1 << 20), TOO_MANY_MEMORY_VALUES);
        assert!((length(&memory_pairs) & 1) == 0, SIZE_OF_MEMORYPAIRS_MUST_BE_EVEN);
        assert!(z < prime, INVALID_VALUE_OF_Z);
        assert!(alpha < prime, INVALID_VALUE_OF_ALPHA);

        let (fact_hash, memory_hash, prod) = compute_fact_hash(memory_pairs, z, alpha, prime);
        emit(LogMemorypPageFactRegular { fact_hash, memory_hash, prod });

        register_fact(signer, fact_hash);
        (fact_hash, memory_hash, prod)
    }

    // Todo: consider replacing u256 with u256
    fun compute_fact_hash(
        memory_pairs: vector<u256>,
        z: u256,
        alpha: u256,
        prime: u256
    ): (u256, u256, u256) {
        let n = length(&memory_pairs);
        let memory_size = n / 2; // NOLINT: divide-before-multiply.

        let prod = 1u256;
        let memory_ptr = 0;
        while (memory_ptr < n) {
            // Compute address + alpha * value.
            let address_value_lin_comb = mod_add(
                // address
                *borrow(&memory_pairs, memory_ptr),
                mod_mul(
                    // value
                    *borrow(&memory_pairs, memory_ptr + 1),
                    alpha,
                    prime
                ),
                prime
            );
            prod = mod_mul(prod, z + prime - address_value_lin_comb, prime);
            memory_ptr = memory_ptr + 2;
        };

        let memory_hash = u256_from_bytes_be(&keccak256(vec_to_bytes_be(&memory_pairs)));
        let fact_hash = u256_from_bytes_be(&keccak256(
            vec_to_bytes_be(&vector[REGULAR_PAGE(), prime, (memory_size as u256), z, alpha, prod, memory_hash, 0u256])
        ));
        (fact_hash, memory_hash, prod)
    }

    // TODO: mark as entry func
    /*
      Registers a fact based on the given values, assuming continuous addresses.
      values should be [value at startAddr, value at (startAddr + 1), ...].
    */
    public fun register_continuous_memorypage(
        signer: &signer,
        start_address: u256,
        values: vector<u256>,
        z: u256,
        alpha: u256,
        prime: u256
    ): (u256, u256, u256) {
        assert!(length(&values) < (1 << 20), TOO_MANY_MEMORY_VALUES);
        assert!(prime < (1u256 << 254), PRIME_IS_TOO_BIG);
        assert!(z < prime, INVALID_VALUE_OF_Z);
        assert!(alpha < prime, INVALID_VALUE_OF_ALPHA);
        // Ensure 'startAddr' less then prime and bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(start_address < prime && start_address < (1u256 << 64), INVALID_VALUE_OF_START_ADDRESS);

        let n_values = (length(&values) as u256);
        // Initialize prod to 1.
        let prod = 1;
        // Initialize valuesPtr to point to the first value in the array.
        let value_ptr = 0u64;

        let minus_z = (prime - z) % prime;

        // Start by processing full batches of 8 cells, addr represents the last address in each
        // batch.
        let addr = start_address + 7;
        let last_addr = start_address + n_values;

        while (addr < last_addr) {
            // Compute the product of (lin_comb - z) instead of (z - lin_comb), since we're
            // doing an even number of iterations, the result is the same.
            for_each(vector[0u64, 2u64, 4u64, 8u64], |offset| {
                prod = mod_mul(prod, mod_mul(
                    alpha - 7 + (offset as u256) + mod_mul(
                        alpha,
                        *borrow(&values, value_ptr + offset),
                        prime
                    ) + minus_z,
                    alpha - 7 + (offset as u256) + 1 + mod_mul(
                        alpha,
                        *borrow(&values, value_ptr + offset + 1),
                        prime
                    ) + minus_z,
                    prime
                ), prime);
            });
            value_ptr = value_ptr + 5;
            addr = addr + 8;
        };

        // Handle leftover.
        // Translate addr to the beginning of the last incomplete batch.
        addr = addr - 7;
        while (addr < last_addr) {
            let address_value_lin_comb = mod_add(addr, mod_mul(*borrow(&values, value_ptr), alpha, prime), prime);
            prod = mod_mul(prod, z + prime - address_value_lin_comb, prime);
            addr = addr + 1;
            value_ptr = value_ptr + 1;
        };

        let memory_hash = u256_from_bytes_be(&keccak256(vec_to_bytes_be(&values)));
        let fact_hash = u256_from_bytes_be(&keccak256(
            vec_to_bytes_be(&vector[CONTINUOUS_PAGE(), prime, n_values, z, alpha, prod, memory_hash, start_address])
        ));
        // TODO: enable emitting event
        // let event_handler = account::new_event_handle<LogMemoryPageFactContinuous>(signer);
        // event::emit_event(&mut event_handler, LogMemoryPageFactContinuous { fact_hash, memory_hash, prod });
        // destroy_handle<LogMemoryPageFactContinuous>(event_handler);
        register_fact(signer, fact_hash);
        (fact_hash, memory_hash, prod)
    }

    // A page based on a list of pairs (address, value).
    // In this case, memoryHash = hash(address, value, address, value, address, value, ...).
    public fun REGULAR_PAGE(): u256 {
        0
    }

    // A page based on adjacent memory cells, starting from a given address.
    // In this case, memoryHash = hash(value, value, value, ...).
    public fun CONTINUOUS_PAGE(): u256 {
        1
    }
}

#[test_only]
module verifier_addr::mpfr_test {
    use verifier_addr::memory_page_fact_registry::{register_continuous_memorypage};

    #[test(signer = @verifier_addr)]
    fun test_register_continuous_memorypage(signer: &signer) {
        let (fact_hash, memory_hash, prod) = register_continuous_memorypage(
            signer,
            2971260,
            vector[
                1723587082856532763241173775465496577348305577532331450336061658809521876102,
                2479248348687909740970436565718726357572221543762678024250834744245756360726,
                587272,
                2177570517647428816133395681679456086343281988787809822104528418476218261377,
                2590421891839256512113614983194993186457498815986333310670788206383913888162,
                0,
                0
            ],
            3035248388910680138215389260643346358343414931640145853107361271346254998038,
            220574768071472005565941019352306850224879407895315608807402130378653737764,
            3618502788666131213697322783095070105623107215331596699973092056135872020481
        );
        // let g = emitted_events<LogMemoryPageFactContinuous>();
        // print(&g);
        assert!(fact_hash == 0xeb243f0981ec93a0090da83d2351b8d4b2e5cd9cc44be8d4b1119450eac54a6du256, 1);
        assert!(memory_hash == 48239457587525216759117913177237902366978204066031868156075383439591598548182, 1);
        assert!(prod == 3254870901738389658383135104000411656134098647702871823979226499371705469217, 1);
    }
}
