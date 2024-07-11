module verifier_addr::gps_statement_verifier {
    use std::string;
    use std::string::String;
    use std::vector::{length, borrow, borrow_mut, slice};
    use verifier_addr::prime_field_element_0::k_modulus;
    use verifier_addr::memory_page_fact_registry::register_regular_memorypage;
    use verifier_addr::vector::{assign, set_el};
    use verifier_addr::cairo_bootloader_program::{PROGRAM_SIZE, get_compiled_program};
    use verifier_addr::gps_output_parser::{register_gps_facts, METADATA_TASKS_OFFSET, METADATA_OFFSET_TASK_OUTPUT_SIZE,
        METADATA_OFFSET_TASK_PROGRAM_HASH, METADATA_OFFSET_TASK_N_TREE_PAIRS, METADATA_TASK_HEADER_SIZE
    };
    use verifier_addr::cpu_public_input_offset_base::{OFFSET_OUTPUT_BEGIN_ADDR, INITIAL_PC, OFFSET_EXECUTION_BEGIN_ADDR,
        OFFSET_EXECUTION_STOP_PTR, OFFSET_OUTPUT_STOP_PTR
    };
    use verifier_addr::page_info::{PAGE_INFO_SIZE, PAGE_INFO_SIZE_OFFSET, PAGE_INFO_HASH_OFFSET, MEMORY_PAIR_SIZE};
    use verifier_addr::cairo_verifier_contract::{get_layout_info, verify_proof_external};

    const N_BUILTINS: u256 = 6;
    const N_MAIN_ARGS: u256 = 6;
    const N_MAIN_RETURN_VALUES: u256 = 6;

    const CAIRO_VERIFIER_ID_OUT_OF_RANGE: u64 = 1;
    const WRONG_CAIRO_VERIFIER_ID: u64 = 2;
    const INVALID_CAIROAUXINPUT_LENGTH: u64 = 3;
    const INVALID_NPAGES: u64 = 4;
    const INVALID_PUBLIC_MEMORY_PAGES_LENGTH: u64 = 5;
    const INVALID_SIZE_FOR_MEMORY_PAGE_0: u64 = 6;
    const INVALID_HASH_FOR_MEMORY_PAGE_0: u64 = 7;
    const INVALID_CUMULATIVE_PRODUCT: u64 = 8;
    const INVALID_NUMBER_OF_TASKS: u64 = 9;
    const INVALID_EXECUTION_BEGIN_ADDRESS: u64 = 10;
    const SELECTED_BUILTINS_VECTOR_IS_TOO_LONG: u64 = 10;
    const INVALID_TASK_OUTPUT_SIZE: u64 = 11;
    const INVALID_NUMBER_OF_PAIRS_IN_MERKLE_TREE_STRUCTURE: u64 = 12;
    const INVALID_LENGTH_OF_TASK_METADATA: u64 = 13;
    const INCONSISTENT_PROGRAM_OUTPUT_LENGTH: u64 = 14;
    const NOT_ALL_CAIRO_PUBLIC_INPUTS_WERE_WRITTEN: u64 = 15;

    struct ConstructorConfig has key {
        hashed_supported_cairo_verifiers: u256,
        simple_bootloader_program_hash: u256
    }

    public entry fun init(
        signer: &signer,
        hashed_supported_cairo_verifiers: u256,
        simple_bootloader_program_hash: u256
    ) {
        move_to(signer, ConstructorConfig {
            hashed_supported_cairo_verifiers,
            simple_bootloader_program_hash,
        });
    }

    public fun identify(): String {
        return string::utf8(b"StarkWare_GpsStatementVerifier_2022_5")
    }

    /*
      Returns the bootloader config.
    */
    public fun getBootloaderConfig(): (u256, u256) acquires ConstructorConfig {
        let config = borrow_global<ConstructorConfig>(@verifier_addr);
        return (config.simple_bootloader_program_hash, config.hashed_supported_cairo_verifiers)
    }

    /*
      Verifies a proof and registers the corresponding facts.
      For the structure of cairoAuxInput, see cpu/CpuPublicInputOffsets.sol.
      taskMetadata is structured as follows:
      1. Number of tasks.
      2. For each task:
         1. Task output size (including program hash and size).
         2. Program hash.
    */
    public entry fun verify_proof_and_register(
        signer: &signer,
        proof_params: vector<u256>,
        proof: vector<u256>,
        task_metadata: vector<u256>,
        cairo_aux_input: vector<u256>,
        cairo_verifier_id: u256
    ) acquires ConstructorConfig {
        // Aptos has no abstract contract, so we set `cairo_verifier_id` to 7, as shown in these transactions
        // https://etherscan.io/address/0x47312450b3ac8b5b8e247a6bb6d523e7605bdb60
        // Todo: Consider this function with another `cairo_verifier_id`
        assert!(cairo_verifier_id == 7, WRONG_CAIRO_VERIFIER_ID);

        // The values z and alpha are used only for the fact registration of the main page.
        // They are not part of the public input of CpuVerifier as they are computed there.
        // Take the relevant slice from 'cairoAuxInput'.
        // let cairo_public_input = cairo_aux_input[0..length(&cairo_aux_input) - 2]; // z and alpha.
        let cairo_public_input = slice(&cairo_aux_input, 0, length(&cairo_aux_input) - 2); // z and alpha.

        let (public_memory_offset, selected_builtins) = get_layout_info();
        assert!(length(&cairo_aux_input) > (public_memory_offset as u64), INVALID_CAIROAUXINPUT_LENGTH);
        let public_memory_pages = slice(
            &cairo_public_input,
            (public_memory_offset as u64),
            length(&cairo_public_input)
        );
        let n_pages = *borrow(&public_memory_pages, 0);
        assert!(n_pages < 10000, INVALID_NPAGES);

        // Validate publicMemoryPages.length.
        // Each page has a page info and a cumulative product.
        // There is no 'page address' in the page info for page 0, but this 'free' slot is
        // used to store the number of pages.
        assert!(
            (length(&public_memory_pages) as u256) == n_pages * (PAGE_INFO_SIZE() + 1),
            INVALID_PUBLIC_MEMORY_PAGES_LENGTH
        );

        // Process public memory.
        let (public_memory_length, memory_hash, prod) = register_public_memory_main_page(
            signer,
            task_metadata,
            cairo_aux_input,
            selected_builtins
        );

        // Make sure the first page is valid.
        // If the size or the hash are invalid, it may indicate that there is a mismatch
        // between the prover and the verifier on the bootloader program or bootloader config.
        assert!(
            *borrow(&public_memory_pages, (PAGE_INFO_SIZE_OFFSET() as u64)) == public_memory_length,
            INVALID_SIZE_FOR_MEMORY_PAGE_0
        );
        assert!(
            *borrow(&public_memory_pages, (PAGE_INFO_HASH_OFFSET() as u64)) == memory_hash,
            INVALID_HASH_FOR_MEMORY_PAGE_0
        );
        assert!(
            *borrow(&public_memory_pages, (n_pages * PAGE_INFO_SIZE() as u64)) == prod,
            INVALID_CUMULATIVE_PRODUCT
        );

        // NOLINTNEXTLINE: reentrancy-benign.
        verify_proof_external(proof_params, proof, cairo_public_input);

        register_gps_facts(signer, task_metadata, public_memory_pages, *borrow(&cairo_aux_input,
            (OFFSET_OUTPUT_BEGIN_ADDR() as u64)
        ));
    }

    /*
      Registers the fact for memory page 0, which includes:
      1. The bootloader program,
      2. Arguments and return values of main()
      3. Some of the data required for computing the task facts. which is represented in
         taskMetadata.
      Returns information on the registered fact.

      Arguments:
        selectedBuiltins: A bit-map of builtins that are present in the layout.
            See CairoVerifierContract.sol for more information.
        taskMetadata: Per task metadata.
        cairoAuxInput: Auxiliary input for the cairo verifier.

      Assumptions: cairoAuxInput is connected to the public input, which is verified by
      cairoVerifierContractAddresses.
      Guarantees: taskMetadata is consistent with the public memory, with some sanity checks.
    */
    fun register_public_memory_main_page(
        signer: &signer,
        task_metadata: vector<u256>,
        cairo_aux_input: vector<u256>,
        selected_builtins: u256
    ): (u256, u256, u256) acquires ConstructorConfig {
        let n_tasks = *borrow(&task_metadata, 0);
        // Ensure 'n_tasks' is bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(n_tasks < (1 << 30), INVALID_NUMBER_OF_TASKS);

        // Public memory length.
        let public_memory_length = (PROGRAM_SIZE() +
            // return fp and pc =
            2 +
            N_MAIN_ARGS +
            N_MAIN_RETURN_VALUES +
            // Bootloader config size =
            2 +
            // Number of tasks cell =
            1 +
            2 *
                n_tasks);

        let public_memory = assign(0u256, (MEMORY_PAIR_SIZE() * public_memory_length as u64));
        let offset = 0u64;

        // Write public memory, which is a list of pairs (address, value).
        {
            let bootloader_program = get_compiled_program();
            let (i, n) = (0, length(&bootloader_program));
            while (i < n) {
                *borrow_mut(&mut public_memory, offset) = (i as u256) + INITIAL_PC();
                *borrow_mut(&mut public_memory, offset + 1) = *borrow(&bootloader_program, i);
                offset = offset + 2;
                i = i + 1;
            }
        };

        {
            // Execution segment - Make sure [initial_fp - 2] = initial_fp and .
            // This is required for the "safe call" feature (that is, all "call" instructions will
            // return, even if the called function is malicious).
            // It guarantees that it's not possible to create a cycle in the call stack.
            let initial_fp = *borrow(&cairo_aux_input, (OFFSET_EXECUTION_BEGIN_ADDR() as u64));
            assert!(initial_fp >= 2, INVALID_EXECUTION_BEGIN_ADDRESS);
            *borrow_mut(&mut public_memory, offset + 0) = initial_fp - 2;
            *borrow_mut(&mut public_memory, offset + 1) = initial_fp;
            // Make sure [initial_fp - 1] = 0.
            *borrow_mut(&mut public_memory, offset + 2) = initial_fp - 1;
            *borrow_mut(&mut public_memory, offset + 3) = 0;
            offset = offset + 4;

            // Execution segment: Enforce main's arguments and return values.
            // Note that the page hash depends on the order of the (address, value) pair in the
            // public_memory and consequently the arguments must be written before the return values.
            let return_values_address = *borrow(&cairo_aux_input, (OFFSET_EXECUTION_STOP_PTR() as u64)) - N_BUILTINS;
            let builtin_segment_info_offset = OFFSET_OUTPUT_BEGIN_ADDR();

            let i = 0;
            while (i < N_BUILTINS) {
                // Write argument address.
                set_el(&mut public_memory, offset, initial_fp + 1);
                let return_value_offset = offset + (2 * N_BUILTINS as u64);

                // Write return value address.
                set_el(&mut public_memory, return_value_offset, return_values_address + i);

                // Write values.
                if ((selected_builtins & 1) != 0) {
                    // Set the argument to the builtin start pointer.
                    set_el(
                        &mut public_memory,
                        offset + 1,
                        *borrow(&cairo_aux_input, (builtin_segment_info_offset as u64))
                    );
                    // Set the return value to the builtin stop pointer.
                    set_el(&mut public_memory, return_value_offset + 1, *borrow(&cairo_aux_input,
                        (builtin_segment_info_offset + 1 as u64)
                    ));
                    builtin_segment_info_offset = builtin_segment_info_offset + 2;
                } else {
                    // Builtin is not present in layout, set the argument value and return value to 0.
                    set_el(&mut public_memory, offset + 1, 0);
                    set_el(&mut public_memory, return_value_offset + 1, 0);
                };
                offset = offset + 2;
                selected_builtins = selected_builtins >> 1;
                i = i + 1;
            };
            assert!(selected_builtins == 0, SELECTED_BUILTINS_VECTOR_IS_TOO_LONG);
            // Skip the return values which were already written.
            offset = offset + (2 * N_BUILTINS as u64);
        };

        // Program output.
        {
            {
                let ConstructorConfig {
                    hashed_supported_cairo_verifiers,
                    simple_bootloader_program_hash
                } = borrow_global<ConstructorConfig>(@verifier_addr);
                let output_address = *borrow(&cairo_aux_input, (OFFSET_OUTPUT_BEGIN_ADDR() as u64));
                // Force that memory[outputAddress] and memory[outputAddress + 1] contain the
                // bootloader config (which is 2 words size).
                set_el(&mut public_memory, offset + 0, output_address);
                set_el(&mut public_memory, offset + 1, *simple_bootloader_program_hash);
                set_el(&mut public_memory, offset + 2, output_address + 1);
                set_el(&mut public_memory, offset + 3, *hashed_supported_cairo_verifiers);
                // Force that memory[outputAddress + 2] = nTasks.
                set_el(&mut public_memory, offset + 4, output_address + 2);
                set_el(&mut public_memory, offset + 5, n_tasks);
                offset = offset + 6;
                output_address = output_address + 3;

                let task_metadata_slice = slice(&task_metadata,
                    (METADATA_TASKS_OFFSET() as u64), length(&task_metadata));
                let task = 0;
                while (task < n_tasks)
                    {
                        let output_size = *borrow(&task_metadata_slice, (METADATA_OFFSET_TASK_OUTPUT_SIZE() as u64));

                        // Ensure 'outputSize' is at least 2 and bounded from above as a sanity check
                        // (the bound is somewhat arbitrary).
                        assert!(2 <= output_size && output_size < (1 << 30), INVALID_TASK_OUTPUT_SIZE);
                        let program_hash = *borrow(&task_metadata_slice, (METADATA_OFFSET_TASK_PROGRAM_HASH() as u64));
                        let n_tree_pairs = *borrow(&task_metadata_slice, (METADATA_OFFSET_TASK_N_TREE_PAIRS() as u64));

                        // Ensure 'nTreePairs' is at least 1 and bounded from above as a sanity check
                        // (the bound is somewhat arbitrary).
                        assert!(
                            1 <= n_tree_pairs && n_tree_pairs < (1 << 20),
                            INVALID_NUMBER_OF_PAIRS_IN_MERKLE_TREE_STRUCTURE
                        );
                        // Force that memory[outputAddress] = outputSize.
                        set_el(&mut public_memory, offset + 0, output_address);
                        set_el(&mut public_memory, offset + 1, output_size);
                        // Force that memory[outputAddress + 1] = programHash.
                        set_el(&mut public_memory, offset + 2, output_address + 1);
                        set_el(&mut public_memory, offset + 3, program_hash);
                        offset = offset + 4;
                        output_address = output_address + output_size;
                        task_metadata_slice = slice(&task_metadata_slice,
                            (METADATA_TASK_HEADER_SIZE() + 2 * n_tree_pairs as u64), length(&task_metadata_slice));
                        task = task + 1;
                    };
                assert!(length(&task_metadata_slice) == 0, INVALID_LENGTH_OF_TASK_METADATA);

                assert!(
                    *borrow(&cairo_aux_input, (OFFSET_OUTPUT_STOP_PTR() as u64)) == output_address,
                    INCONSISTENT_PROGRAM_OUTPUT_LENGTH
                );
            }
        };

        assert!(length(&public_memory) == offset, NOT_ALL_CAIRO_PUBLIC_INPUTS_WERE_WRITTEN);
        let z = *borrow(&cairo_aux_input, length(&cairo_aux_input) - 2);
        let alpha = *borrow(&cairo_aux_input, length(&cairo_aux_input) - 1);
        let (_, memory_hash, prod) = register_regular_memorypage(
            signer,
            public_memory,
            z,
            alpha,
            k_modulus()
        );
        return (public_memory_length, memory_hash, prod)
    }
}
