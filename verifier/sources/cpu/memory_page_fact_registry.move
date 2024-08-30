// A fact registry for the claim:
//   I know n pairs (addr, value) for which the hash of the pairs is memoryHash, and the cumulative
//   product: \prod_i( z - (addr_i + alpha * value_i) ) is prod.
// The exact format of the hash depends on the type of the page
// (see MemoryPageFactRegistryConstants).
// The fact consists of (pageType, prime, n, z, alpha, prod, memoryHash, address).
// Note that address is only available for CONTINUOUS_PAGE, and otherwise it is 0.
module verifier_addr::memory_page_fact_registry {
    use std::signer::address_of;
    use std::vector::{borrow, for_each, is_empty, length};
    use aptos_std::aptos_hash::keccak256;
    use aptos_framework::event::emit;

    use lib_addr::bytes::{bytes32_to_u256, long_vec_to_bytes_le, vec_to_bytes_le};
    use lib_addr::prime_field_element_0::{fadd, fmul};
    use verifier_addr::fact_registry::register_fact;

    friend verifier_addr::gps_statement_verifier;
    #[test_only]
    friend verifier_addr::mpfr_test;
    // A page based on a list of pairs (address, value).
    // In this case, memoryHash = hash(address, value, address, value, address, value, ...).
    // A page based on adjacent memory cells, starting from a given address.
    // In this case, memoryHash = hash(value, value, value, ...).

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
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
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
        fact_hash: u256,
        memory_hash: u256,
        prod: u256
    }

    public(friend) fun init_data_type(signer: &signer) {
        move_to(signer, CfhCheckpoint {
            inner: CFH_CHECKPOINT1
        });
        move_to(signer, CfhCache {
            prod: 0
        });
    }

    public(friend) fun register_regular_memorypage(
        signer: &signer,
        memory_pairs: &vector<u256>,
        z: u256,
        alpha: u256
    ): vector<u256> acquires CfhCheckpoint, CfhCache {
        let memory_pairs_length = length(memory_pairs);
        assert!(memory_pairs_length < (1 << 20), ETOO_MANY_MEMORY_VALUES);
        assert!((memory_pairs_length & 1) == 0, ESIZE_OF_MEMORYPAIRS_MUST_BE_EVEN);
        assert!(z < K_MODULUS, EINVALID_VALUE_OF_Z);
        assert!(alpha < K_MODULUS, EINVALID_VALUE_OF_ALPHA);

        let tmp = compute_fact_hash(signer, memory_pairs, z, alpha);
        if (is_empty(&tmp)) {
            return vector[]
        };
        let (fact_hash, memory_hash, prod) = (*borrow(&tmp, 0), *borrow(&tmp, 1), *borrow(&tmp, 2));
        emit(LogMemorypPageFactRegular { fact_hash, memory_hash, prod });

        register_fact(signer, fact_hash);
        tmp
    }

    fun compute_fact_hash(
        signer: &signer,
        memory_pairs: &vector<u256>,
        z: u256,
        alpha: u256
    ): vector<u256> acquires CfhCheckpoint, CfhCache {
        let signer_addr = address_of(signer);
        let CfhCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<CfhCheckpoint>(signer_addr);
        let n = length(memory_pairs);
        let memory_size = n / 2; // NOLINT: divide-before-multiply.
        if (*checkpoint == CFH_CHECKPOINT1) {
            let prod = 1;
            let memory_ptr = 0;
            while (memory_ptr < n) {
                // Compute address + alpha * value.
                let address_value_lin_comb = fadd(
                    // address
                    *borrow(memory_pairs, memory_ptr),
                    fmul(
                        // value
                        *borrow(memory_pairs, memory_ptr + 1),
                        alpha
                    )
                );
                prod = fmul(prod, z + K_MODULUS - address_value_lin_comb);
                memory_ptr = memory_ptr + 2;
            };
            *borrow_global_mut<CfhCache>(signer_addr) = CfhCache {
                prod
            };
            *checkpoint = CFH_CHECKPOINT2;
            return vector[]
        };

        let memory_pairs_bytes = long_vec_to_bytes_le(signer, memory_pairs);
        if (length(&memory_pairs_bytes) == 0) {
            return vector[]
        };

        let memory_hash = bytes32_to_u256(keccak256(memory_pairs_bytes));
        let prod = borrow_global<CfhCache>(signer_addr).prod;
        let fact_hash = bytes32_to_u256(keccak256(
            vec_to_bytes_le(&vector[REGULAR_PAGE, K_MODULUS, (memory_size as u256), z, alpha, prod, memory_hash, 0u256])
        ));
        *checkpoint = CFH_CHECKPOINT1;
        vector[fact_hash, memory_hash, prod]
    }

    // TODO: mark as entry func
    //   Registers a fact based on the given values, assuming continuous addresses.
    //   values should be [value at startAddr, value at (startAddr + 1), ...].
    public(friend) fun register_continuous_memorypage(
        signer: &signer,
        start_address: u256,
        values: vector<u256>,
        z: u256,
        alpha: u256
    ): (u256, u256, u256) {
        assert!(length(&values) < (1 << 20), ETOO_MANY_MEMORY_VALUES);
        assert!(K_MODULUS < (1u256 << 254), EPRIME_IS_TOO_BIG);
        assert!(z < K_MODULUS, EINVALID_VALUE_OF_Z);
        assert!(alpha < K_MODULUS, EINVALID_VALUE_OF_ALPHA);
        // Ensure 'startAddr' less then prime and bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(start_address < K_MODULUS && start_address < (1u256 << 64), EINVALID_VALUE_OF_START_ADDRESS);

        let n_values = (length(&values) as u256);
        // Initialize prod to 1.
        let prod = 1;
        // Initialize valuesPtr to point to the first value in the array.
        let value_ptr = 0u64;

        let minus_z = (K_MODULUS - z) % K_MODULUS;

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
            prod = fmul(prod, z + K_MODULUS - address_value_lin_comb);
            addr = addr + 1;
            value_ptr = value_ptr + 1;
        };

        let memory_hash = bytes32_to_u256(keccak256(vec_to_bytes_le(&values)));
        let fact_hash = bytes32_to_u256(keccak256(
            vec_to_bytes_le(&vector[CONTINUOUS_PAGE, K_MODULUS, n_values, z, alpha, prod, memory_hash, start_address])
        ));
        emit(LogMemoryPageFactContinuous {
            fact_hash,
            memory_hash,
            prod
        });
        register_fact(signer, fact_hash);
        (fact_hash, memory_hash, prod)
    }

    // TODO: assert admin
    // Receives a list of MemoryPageEntry. Each element in the list holds arguments for a seperate
    // call to registerContinuousMemoryPage.
    public entry fun register_continuous_page_batch(
        s: &signer,
        start_addr: vector<u256>,
        values: vector<vector<u256>>,
        z: u256,
        alpha: u256
    ) {
        for (i in 0..length(&start_addr) ) {
            register_continuous_memorypage(s, *borrow(&start_addr, i), *borrow(&values, i), z, alpha);
        }
    }

    #[test_only]
    public fun get_cfh_checkpoint(signer: &signer): u8 acquires CfhCheckpoint {
        borrow_global<CfhCheckpoint>(address_of(signer)).inner
    }

    // Data of the function `compute_fact_hash`
    // checkpoints
    const CFH_CHECKPOINT1: u8 = 1;
    const CFH_CHECKPOINT2: u8 = 2;

    const ITERATION_LENGTH: u64 = 1500;

    struct CfhCheckpoint has key {
        inner: u8
    }

    struct CfhCache has key, drop {
        prod: u256
    }
}

#[test_only]
module verifier_addr::mpfr_test {
    use std::signer::address_of;

    use verifier_addr::fact_registry::{init_fact_registry, is_valid};
    use verifier_addr::memory_page_fact_registry::{register_continuous_memorypage, register_continuous_page_batch};

    #[test(signer = @test_signer)]
    fun test_register_continuous_memorypage(signer: &signer) {
        init_fact_registry(signer);
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
            220574768071472005565941019352306850224879407895315608807402130378653737764
        );
        // let g = emitted_events<LogMemoryPageFactContinuous>();
        // print(&g);
        assert!(fact_hash == 0xeb243f0981ec93a0090da83d2351b8d4b2e5cd9cc44be8d4b1119450eac54a6du256, 1);
        assert!(memory_hash == 48239457587525216759117913177237902366978204066031868156075383439591598548182, 1);
        assert!(prod == 3254870901738389658383135104000411656134098647702871823979226499371705469217, 1);
    }

    #[test(s = @test_signer)]
    // Transaction hash on ETH mainnet for this test: 0x6f59bed6f3df4b87c03c49f11e627e842ae5708a3670f428ddfb83c5b98d3754.
    fun test_register_continuous_page_batch(s: &signer) {
        init_fact_registry(s);
        register_continuous_page_batch(
            s,
            vector[1771799, 1771808],
            vector[vector[1007, 1006, 1005, 1004, 1003, 1002, 1001],
                vector[1008, 1007, 1006, 1005, 1004, 1003, 1002, 1001]],
            3199940278565943790978406278706496237292797978280982699986488410844249594708,
            195072032121178106591923000375621188629735561133807175660265096969353999946
        );
        is_valid(
            address_of(s),
            49238381412124717490517111631696093427076824100526472039743966257691104387218
        );
        is_valid(
            address_of(s),
            54205816271920378481316162362155116341907231556132238625024261418992095639341
        );
    }
}