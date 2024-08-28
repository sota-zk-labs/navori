module verifier_addr::memory_page_fact_registry {
    use std::vector::{borrow, for_each, length};
    use aptos_std::aptos_hash::keccak256;
    use aptos_framework::event::emit;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_be};
    use lib_addr::prime_field_element_0::{fadd, fmul};
    use verifier_addr::fact_registry::register_fact;

    // This line is used for generating constants DO NOT REMOVE!
    // 1
    const CONTINUOUS_PAGE: u256 = 0x1;
    // 4
    const EINVALID_VALUE_OF_ALPHA: u64 = 0x4;
    // 6
    const EINVALID_VALUE_OF_START_ADDRESS: u64 = 0x6;
    // 3
    const EINVALID_VALUE_OF_Z: u64 = 0x3;
    // 5
    const EPRIME_IS_TOO_BIG: u64 = 0x5;
    // 2
    const ESIZE_OF_MEMORYPAIRS_MUST_BE_EVEN: u64 = 0x2;
    // 1
    const ETOO_MANY_MEMORY_VALUES: u64 = 0x1;
    // 0
    const REGULAR_PAGE: u256 = 0x0;
    // End of generating constants!

    #[event]
    struct LogMemorypPageFactRegular has store, drop {
        fact_hash: u256,
        memory_hash: u256,
        prod: u256
    }

    #[event]
    struct LogMemoryPageFactContinuous has store, drop {
        fact_hash: vector<u8>,
        memory_hash: u256,
        prod: u256
    }

    struct Ptr has key, store {
        addr: u256,
        value_ptr: u64,
        prod: u256
    }

    public fun register_regular_memorypage(
        signer: &signer,
        memory_pairs: vector<u256>,
        z: u256,
        alpha: u256,
        prime: u256
    ): (u256, u256, u256) {
        assert!(length(&memory_pairs) < (1 << 20), ETOO_MANY_MEMORY_VALUES);
        assert!((length(&memory_pairs) & 1) == 0, ESIZE_OF_MEMORYPAIRS_MUST_BE_EVEN);
        assert!(z < prime, EINVALID_VALUE_OF_Z);
        assert!(alpha < prime, EINVALID_VALUE_OF_ALPHA);

        let (fact_hash, memory_hash, prod) = compute_fact_hash(memory_pairs, z, alpha, prime);
        emit(LogMemorypPageFactRegular { fact_hash, memory_hash, prod });

        register_fact(signer, fact_hash);
        (fact_hash, memory_hash, prod)
    }

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
            let address_value_lin_comb = fadd(
                // address
                *borrow(&memory_pairs, memory_ptr),
                fmul(
                    // value
                    *borrow(&memory_pairs, memory_ptr + 1),
                    alpha)
            );
            prod = fmul(prod, z + prime - address_value_lin_comb);
            memory_ptr = memory_ptr + 2;
        };

        let memory_hash = bytes32_to_u256(keccak256(vec_to_bytes_be(&memory_pairs)));
        let fact_hash = bytes32_to_u256(keccak256(
            vec_to_bytes_be(&vector[REGULAR_PAGE, prime, (memory_size as u256), z, alpha, prod, memory_hash, 0u256])
        ));
        (fact_hash, memory_hash, prod)
    }

    /*
       Receives a list of MemoryPageEntry. Each element in the list holds arguments for a seperate
       call to registerContinuousMemoryPage.
     */
    //TODO: assert admin
    public entry fun register_continuous_page_batch(
        s: &signer,
        start_addr: vector<u256>,
        values: vector<vector<u256>>,
        z: u256,
        alpha: u256,
        prime: u256
    ) {
        for (i in 0..length(&start_addr) ) {
            register_continuous_memorypage(s, *borrow(&start_addr, i), *borrow(&values, i), z, alpha, prime);
        }
    }
    /*
      Registers a fact based on the given values, assuming continuous addresses.
      values should be [value at startAddr, value at (startAddr + 1), ...].
    */
    //TODO: assert admin
    public entry fun register_continuous_memorypage(
        s: &signer,
        start_address: u256,
        values: vector<u256>,
        z: u256,
        alpha: u256,
        prime: u256
    ) {
        assert!(length(&values) < (1 << 20), ETOO_MANY_MEMORY_VALUES);
        assert!(prime < (1u256 << 254), EPRIME_IS_TOO_BIG);
        assert!(z < prime, EINVALID_VALUE_OF_Z);
        assert!(alpha < prime, EINVALID_VALUE_OF_ALPHA);
        // Ensure 'startAddr' less then prime and bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(start_address < prime && start_address < (1u256 << 64), EINVALID_VALUE_OF_START_ADDRESS);

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
            for_each(vector[0u64, 2u64, 4u64, 6u64], |offset| {
                prod = fmul(prod,
                    fmul(
                        addr - 7 + (offset as u256) + fmul(alpha, *borrow(&values, value_ptr + offset)) + minus_z,
                        addr - 7 + (offset as u256) + 1 + fmul(
                            alpha,
                            *borrow(&values, value_ptr + offset + 1)
                        ) + minus_z
                    ));
            });
            value_ptr = value_ptr + 8;
            addr = addr + 8;
        };

        // Handle leftover.
        // Translate addr to the beginning of the last incomplete batch.
        addr = addr - 7;
        while (addr < last_addr) {
            let address_value_lin_comb = fadd(addr, fmul(*borrow(&values, value_ptr), alpha));
            prod = fmul(prod, z + prime - address_value_lin_comb);
            addr = addr + 1;
            value_ptr = value_ptr + 1;
        };

        let memory_hash = bytes32_to_u256(keccak256(vec_to_bytes_be(&values)));
        let fact_hash = keccak256(
            vec_to_bytes_be(&vector[CONTINUOUS_PAGE, prime, n_values, z, alpha, prod, memory_hash, start_address])
        );
        emit(LogMemoryPageFactContinuous {
            fact_hash,
            memory_hash,
            prod
        });
        register_fact(s, bytes32_to_u256(fact_hash));
    }

    // A page based on a list of pairs (address, value).
    // In this case, memoryHash = hash(address, value, address, value, address, value, ...).
    // A page based on adjacent memory cells, starting from a given address.
    // In this case, memoryHash = hash(value, value, value, ...).
}