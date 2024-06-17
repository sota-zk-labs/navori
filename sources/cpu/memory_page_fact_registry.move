module verifier_addr::memory_page_fact_registry {
    use std::bcs;
    use std::vector::{for_each, length};
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::math64::pow;
    use aptos_framework::event;
    use aptos_framework::event::emit;

    use lib_addr::endia_encode::to_big_endian;
    use lib_addr::math_mod::mod_mul;
    use lib_addr::memory;
    use lib_addr::memory::{allocate, mload, mloadrange};
    use verifier_addr::fact_registry::register_fact;
    use verifier_addr::vector::append_vector;

    const REGULAR_PAGE: u256 = 0;
    const CONTINUOUS_PAGE: u256 = 1;

    //Errors
    const TOO_MANY_MEMORY_VALUES: u64 = 1;
    const SIZE_OF_MEMORYPAIRS_MUST_BE_EVEN: u64 = 2;
    const INVALID_VALUE_OF_Z: u64 = 3;
    const INVALID_VALUE_OF_ALPHA: u64 = 4;
    const PRIME_IS_TOO_BIG: u64 = 5;
    const INVALID_VALUE_OF_START_ADDRESS: u64 = 6;


    #[event]
    struct LogMemorypPageFactRegular has store, drop {
        fact_hash: vector<u8>,
        memory_hash: u256,
        prod: u256
    }

    #[event]
    struct LogMemoryPageFactContinuous has store, drop {
        fact_hash: vector<u8>,
        memory_hash: u256,
        prod: u256
    }

    public fun register_regular_memorypage(
        memory_pairs: vector<u256>,
        z: u256,
        alpha: u256,
        prime: u256
    ): (vector<u8>, u256, u256) {
        assert!(length(&memory_pairs) < pow(2, 20), TOO_MANY_MEMORY_VALUES);
        assert!(length(&memory_pairs) % 2 == 0, SIZE_OF_MEMORYPAIRS_MUST_BE_EVEN);
        assert!(z < prime, INVALID_VALUE_OF_Z);
        assert!(alpha < prime, INVALID_VALUE_OF_ALPHA);

        let (fact_hash, memory_hash, prod) = compute_fact_hash(memory_pairs, z, alpha, prime);
        emit(LogMemorypPageFactRegular { fact_hash, memory_hash, prod });

        register_fact(fact_hash);
        (fact_hash, memory_hash, prod)
    }

    fun compute_fact_hash(
        memory_pairs: vector<u256>,
        z: u256,
        alpha: u256,
        prime: u256
    ): (vector<u8>, u256, u256) {
        //uint256[] memory memoryPairs
        let memory = memory::new();
        let memory_ptr = allocate(&mut memory, (length(&memory_pairs) as u256));
        for_each(memory_pairs, |p| {
            allocate(&mut memory, p);
        });

        let memory_size = length(&memory_pairs) / 2; // NOLINT: divide-before-multiply.

        let prod = 1;


        let memory_ptr = memory_ptr + 0x20;
        let last_ptr = memory_ptr + (memory_size as u256) * 0x40;

        let ptr = memory_ptr;
        while (ptr < last_ptr) {
            let address_value_lin_comb = (mload(&memory, ptr) + mod_mul(
                alpha,
                mload(&memory, ptr + 0x20),
                prime
            )) % prime;
            prod = mod_mul(prod, z + prime - address_value_lin_comb, prime);
            ptr = ptr + 0x40;
        };
        let input_hash = mloadrange(&memory, memory_ptr, (memory_size * 0x40 as u256));
        let memory_hash = to_big_endian(keccak256(input_hash));
        //TODO: need convert to bigendian format
        let fact_hash = keccak256(
            append_vector(
                append_vector(
                    append_vector(
                        append_vector(
                            append_vector(
                                append_vector(
                                    bcs::to_bytes(&REGULAR_PAGE), bcs::to_bytes(&prime)
                                ),
                                bcs::to_bytes(&memory_size)
                            ),
                            bcs::to_bytes(&z)
                        ),
                        bcs::to_bytes(&prod)
                    ),
                    bcs::to_bytes(&memory_hash)
                ),
                bcs::to_bytes(&0)
            ));

        (fact_hash, (memory_size as u256), prod)
    }

    /*
      Registers a fact based on the given values, assuming continuous addresses.
      values should be [value at startAddr, value at (startAddr + 1), ...].
    */
    public fun register_continuos_memorypage(
        start_address: u256,
        values: vector<u256>,
        z: u256,
        alpha: u256,
        prime: u256
    ): (vector<u8>, u256, u256) {
        //uint256[] memory values,
        let memory = memory::new();
        let value_ptr = allocate(&mut memory, (length(&values) as u256));
        for_each(values, |p| {
            allocate(&mut memory, p);
        });

        assert!(length(&values) < pow(2, 20), TOO_MANY_MEMORY_VALUES);
        assert!(prime < (pow(2, 254) as u256), PRIME_IS_TOO_BIG);
        assert!(z < prime, INVALID_VALUE_OF_Z);
        assert!(alpha < prime, INVALID_VALUE_OF_ALPHA);
        assert!(start_address < prime && start_address < (pow(2, 64) as u256), INVALID_VALUE_OF_START_ADDRESS);

        let n_values = length(&values);
        let prod = 1;
        value_ptr = value_ptr + 0x20;

        let minus_z = (prime - z) % prime;

        let addr = start_address + 7;
        let last_addr = start_address + (n_values as u256);

        while (addr < last_addr) {
            prod = prod * (
                ((addr - 7 + (alpha * mload(&memory, value_ptr)) % prime + minus_z))
                    * ((addr - 6 + (alpha * mload(&memory, value_ptr + 0x20)) % prime + minus_z))
                    % prime
            ) % prime ;

            prod = prod * (
                ((addr - 5 + (alpha * mload(&memory, value_ptr + 0x40)) % prime + minus_z))
                    * ((addr - 4 + (alpha * mload(&memory, value_ptr + 0x60)) % prime + minus_z))
                    % prime
            ) % prime ;

            prod = prod * (
                ((addr - 3 + (alpha * mload(&memory, value_ptr + 0x80)) % prime + minus_z))
                    * ((addr - 2 + (alpha * mload(&memory, value_ptr + 0xa0)) % prime + minus_z))
                    % prime
            ) % prime ;

            prod = prod * (
                ((addr - 1 + (alpha * mload(&memory, value_ptr + 0xc0)) % prime + minus_z))
                    * ((addr + (alpha * mload(&memory, value_ptr + 0xe0)) % prime + minus_z))
                    % prime
            ) % prime ;
            value_ptr = value_ptr + 0x100;
            addr = addr + 8;
        };
        addr = addr - 7;
        while (addr < last_addr) {
            let address_value_lin_comb = (addr + (alpha * mload(&memory, value_ptr)) % prime) % prime;
            prod = (prod * (z + prime - address_value_lin_comb)) % prime;
            addr = addr + 1;
        };

        let input_hash = mloadrange(&memory, value_ptr - (n_values * 0x20 as u256), (n_values * 0x20 as u256));
        let memory_hash = to_u256(to_big_endian(keccak256(input_hash)));
        //TODO: need convert to bigendian format
        let fact_hash = keccak256(
            append_vector(
                append_vector(
                    append_vector(
                        append_vector(
                            append_vector(
                                append_vector(
                                    append_vector(
                                        bcs::to_bytes(&CONTINUOUS_PAGE), bcs::to_bytes(&prime)
                                    ),
                                    bcs::to_bytes(&n_values)
                                ),
                                bcs::to_bytes(&z)
                            ),
                            bcs::to_bytes(&alpha)
                        ),
                        bcs::to_bytes(&prod)
                    ),
                    bcs::to_bytes(&memory_hash)
                ),
                bcs::to_bytes(&start_address)
            ));
        event::emit(LogMemoryPageFactContinuous { fact_hash, memory_hash, prod });
        register_fact(fact_hash);
        (fact_hash, memory_hash, prod)
    }
}
