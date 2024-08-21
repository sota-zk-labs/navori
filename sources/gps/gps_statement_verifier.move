module verifier_addr::gps_statement_verifier {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector::{borrow, borrow_mut, length, slice};
    use aptos_std::math64::min;

    use cpu_addr::cairo_bootloader_program::get_compiled_program;
    use lib_addr::vector::{assign, set_el};
    use verifier_addr::stark_verifier_7;

    use verifier_addr::cairo_verifier_contract::{get_layout_info, verify_proof_external};
    use verifier_addr::gps_output_parser;
    use verifier_addr::gps_output_parser::register_gps_facts;
    use verifier_addr::memory_page_fact_registry;
    use verifier_addr::memory_page_fact_registry::register_regular_memorypage;

    // This line is used for generating constants DO NOT REMOVE!
    // 0x800000000000011000000000000000000000000000000000000000000000001
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // 728
    const PROGRAM_SIZE: u256 = 0x2d8;
    // 1
    const METADATA_TASKS_OFFSET: u64 = 0x1;
    // 0
    const METADATA_OFFSET_TASK_OUTPUT_SIZE: u64 = 0x0;
    // 1
    const METADATA_OFFSET_TASK_PROGRAM_HASH: u64 = 0x1;
    // 2
    const METADATA_OFFSET_TASK_N_TREE_PAIRS: u64 = 0x2;
    // 3
    const METADATA_TASK_HEADER_SIZE: u64 = 0x3;
    // 8
    const OFFSET_OUTPUT_BEGIN_ADDR: u64 = 0x8;
    // 1
    const INITIAL_PC: u64 = 0x1;
    // 6
    const OFFSET_EXECUTION_BEGIN_ADDR: u64 = 0x6;
    // 7
    const OFFSET_EXECUTION_STOP_PTR: u64 = 0x7;
    // 9
    const OFFSET_OUTPUT_STOP_PTR: u64 = 0x9;
    // 3
    const PAGE_INFO_SIZE: u256 = 0x3;
    // 1
    const PAGE_INFO_SIZE_OFFSET: u256 = 0x1;
    // 2
    const PAGE_INFO_HASH_OFFSET: u256 = 0x2;
    // 2
    const MEMORY_PAIR_SIZE: u256 = 0x2;
    // End of generating constants!

    const N_BUILTINS: u256 = 9;
    const N_MAIN_ARGS: u256 = 9;
    const N_MAIN_RETURN_VALUES: u256 = 9;

    struct ConstructorConfig has key {
        hashed_supported_cairo_verifiers: u256,
        simple_bootloader_program_hash: u256
    }

    public entry fun init_gps_statement_verifier(
        signer: &signer,
        hashed_supported_cairo_verifiers: u256,
        simple_bootloader_program_hash: u256
    ) {
        move_to(signer, ConstructorConfig {
            hashed_supported_cairo_verifiers,
            simple_bootloader_program_hash,
        });
    }

    /*
      Returns the bootloader config.
    */
    public fun getBootloaderConfig(): (u256, u256) acquires ConstructorConfig {
        let config = borrow_global<ConstructorConfig>(@verifier_addr);
        return (config.simple_bootloader_program_hash, config.hashed_supported_cairo_verifiers)
    }

    public fun init_data_type(signer: &signer) {
        // Data of the function `verify_proof_and_register`
        move_to(signer, TaskMetaData {
            inner: vector[]
        });
        move_to(signer, VparParams {
            proof_params: vector[],
            proof: vector[],
            task_metadata: vector[],
            cairo_aux_input: vector[],
            cairo_verifier_id: 0
        });
        move_to(signer, VparCheckpoint {
            inner: REGISTER_PUBLIC_MEMORY_MAIN_PAGE
        });
        move_to(signer, VparCache {
            selected_builtins: 0,
            cairo_public_input: vector[],
            public_memory_pages: vector[],
            n_pages: 0,
            first_invoking: true
        });

        // Data of the function `register_public_memory_main_page`

        move_to(signer, RpmmpCheckpoint {
            inner: RPMMP_CHECKPOINT1
        });
        move_to(signer, Cache3 {
            public_memory: vector[],
            offset: 0,
            n_tasks: 0,
            public_memory_length: 0
        });
        move_to(signer, Cache4 {
            ptr: 0,
            task_metadata_slice: vector[],
            output_address: 0,
            first_invoking: true
        });

        memory_page_fact_registry::init_data_type(signer);
        gps_output_parser::init_data_type(signer);
        stark_verifier_7::init_data_type(signer);
    }

    public entry fun prepush_data_to_verify_proof_and_register(
        signer: &signer,
        proof_params: vector<u256>,
        proof: vector<u256>,
        cairo_aux_input: vector<u256>,
        cairo_verifier_id: u256
    ) acquires TaskMetaData, VparParams {
        let signer_addr = address_of(signer);
        *borrow_global_mut<VparParams>(signer_addr) = VparParams {
            proof_params,
            proof,
            task_metadata: borrow_global<TaskMetaData>(address_of(signer)).inner,
            cairo_aux_input,
            cairo_verifier_id
        };
    }
    /*
        This function is used to push `task_metadata` before calling the function `verify_proof_and_register` due to
        Aptos' function parameter size limit
    */
    public entry fun prepush_task_metadata(signer: &signer, task_metadata: vector<u256>) acquires TaskMetaData {
        *borrow_global_mut<TaskMetaData>(address_of(signer)) = TaskMetaData {
            inner: task_metadata
        };
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
        signer: &signer
    ) acquires ConstructorConfig,
    VparParams,
    VparCheckpoint,
    VparCache,
    RpmmpCheckpoint,
    Cache3,
    Cache4 {
        let signer_addr = address_of(signer);
        let VparParams {
            proof_params,
            proof,
            task_metadata,
            cairo_aux_input,
            cairo_verifier_id
        } = borrow_global_mut<VparParams>(signer_addr);

        let VparCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<VparCheckpoint>(signer_addr);
        if (*checkpoint == REGISTER_PUBLIC_MEMORY_MAIN_PAGE) {
            // Aptos has no abstract contract, so we set `cairo_verifier_id` to 7, as shown in these transactions
            // https://etherscan.io/address/0x47312450b3ac8b5b8e247a6bb6d523e7605bdb60
            // Todo: Consider this function with another `cairo_verifier_id`
            assert!(*cairo_verifier_id == 7, WRONG_CAIRO_VERIFIER_ID);

            // The values z and alpha are used only for the fact registration of the main page.
            // They are not part of the public input of CpuVerifier as they are computed there.
            // Take the relevant slice from 'cairoAuxInput'.
            // let cairo_public_input = cairo_aux_input[0..length(cairo_aux_input) - 2]; // z and alpha.
            if (borrow_global<VparCache>(signer_addr).first_invoking) {
                let tmp = length(cairo_aux_input) - 2;
                let cairo_public_input = slice(cairo_aux_input, 0, tmp); // z and alpha.

                let (public_memory_offset, selected_builtins) = get_layout_info();
                assert!(length(cairo_aux_input) > (public_memory_offset as u64), INVALID_CAIROAUXINPUT_LENGTH);
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
                    (length(&public_memory_pages) as u256) == n_pages * (PAGE_INFO_SIZE + 1),
                    INVALID_PUBLIC_MEMORY_PAGES_LENGTH
                );
                *borrow_global_mut<VparCache>(signer_addr) = VparCache {
                    selected_builtins,
                    cairo_public_input,
                    public_memory_pages,
                    n_pages,
                    first_invoking: false
                };
            };
            let VparCache {
                selected_builtins,
                cairo_public_input,
                public_memory_pages,
                n_pages,
                first_invoking: first_invoking_2
            } = borrow_global_mut<VparCache>(signer_addr);
            // Process public memory.
            let tmp = register_public_memory_main_page(
                signer,
                task_metadata,
                cairo_aux_input,
                *selected_builtins
            );
            // The function has not finished running yet
            if (option::is_none(&tmp)) {
                return
            } else {
                let tmp = option::borrow(&tmp);
                let (public_memory_length, memory_hash, prod) = (*borrow(tmp, 0), *borrow(tmp, 1), *borrow(tmp, 2));
                // Make sure the first page is valid.
                // If the size or the hash are invalid, it may indicate that there is a mismatch
                // between the prover and the verifier on the bootloader program or bootloader config.
                assert!(
                    *borrow(public_memory_pages, (PAGE_INFO_SIZE_OFFSET as u64)) == public_memory_length,
                    INVALID_SIZE_FOR_MEMORY_PAGE_0
                );
                assert!(
                    *borrow(public_memory_pages, (PAGE_INFO_HASH_OFFSET as u64)) == memory_hash,
                    INVALID_HASH_FOR_MEMORY_PAGE_0
                );
                assert!(
                    *borrow(public_memory_pages, (*n_pages * PAGE_INFO_SIZE as u64)) == prod,
                    INVALID_CUMULATIVE_PRODUCT
                );
            };
            *checkpoint = VERIFY_PROOF_EXTERNAL;
            return
        };

        let VparCache {
            selected_builtins,
            cairo_public_input,
            public_memory_pages,
            n_pages,
            first_invoking
        } = borrow_global_mut<VparCache>(signer_addr);
        // NOLINTNEXTLINE: reentrancy-benign.
        if (*checkpoint == VERIFY_PROOF_EXTERNAL) {
            if (verify_proof_external(signer, proof_params, proof, cairo_public_input)) {
                *checkpoint = REGISTER_GPS_FACT;
            };
            return
        };

        if (*checkpoint == REGISTER_GPS_FACT) {
            if (register_gps_facts(
                signer, 
                task_metadata, 
                public_memory_pages, 
                *borrow(cairo_aux_input, OFFSET_OUTPUT_BEGIN_ADDR)
            )) {
                *checkpoint = REGISTER_PUBLIC_MEMORY_MAIN_PAGE;
                return
            };
        };
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
        task_metadata: &vector<u256>,
        cairo_aux_input: &vector<u256>,
        selected_builtins: u256
    ): Option<vector<u256>> acquires ConstructorConfig, RpmmpCheckpoint, Cache3, Cache4 {
        let signer_addr = address_of(signer);
        let RpmmpCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<RpmmpCheckpoint>(signer_addr);
        if (*checkpoint == RPMMP_CHECKPOINT1) {
            let n_tasks = *borrow(task_metadata, 0);
            // Ensure 'n_tasks' is bounded as a sanity check (the bound is somewhat arbitrary).
            // assert!(n_tasks < (1 << 30), INVALID_NUMBER_OF_TASKS);

            // Public memory length.
            let public_memory_length = (PROGRAM_SIZE +
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

            let public_memory = assign(0u256, (MEMORY_PAIR_SIZE * public_memory_length as u64));
            let offset = 0u64;

            // Write public memory, which is a list of pairs (address, value).
            {
                let bootloader_program = get_compiled_program(signer);
                let n = length(&bootloader_program);
                for (i in 0..n) {
                    *borrow_mut(&mut public_memory, offset) = (i + INITIAL_PC as u256);
                    *borrow_mut(&mut public_memory, offset + 1) = *borrow(&bootloader_program, i);
                    offset = offset + 2;
                }
            };

            {
                // Execution segment - Make sure [initial_fp - 2] = initial_fp and .
                // This is required for the safe call feature (that is, all call instructions will
                // return, even if the called function is malicious).
                // It guarantees that it's not possible to create a cycle in the call stack.
                let initial_fp = *borrow(cairo_aux_input, OFFSET_EXECUTION_BEGIN_ADDR);
                // assert!(initial_fp >= 2, INVALID_EXECUTION_BEGIN_ADDRESS);
                *borrow_mut(&mut public_memory, offset + 0) = initial_fp - 2;
                *borrow_mut(&mut public_memory, offset + 1) = initial_fp;
                // Make sure [initial_fp - 1] = 0.
                *borrow_mut(&mut public_memory, offset + 2) = initial_fp - 1;
                *borrow_mut(&mut public_memory, offset + 3) = 0;
                offset = offset + 4;

                // Execution segment: Enforce main's arguments and return values.
                // Note that the page hash depends on the order of the (address, value) pair in the
                // public_memory and consequently the arguments must be written before the return values.
                let return_values_address = *borrow(cairo_aux_input, OFFSET_EXECUTION_STOP_PTR) - N_BUILTINS;
                let builtin_segment_info_offset = OFFSET_OUTPUT_BEGIN_ADDR;

                for (i in 0..N_BUILTINS) {
                    // Write argument address.
                    set_el(&mut public_memory, offset, initial_fp + i);
                    let return_value_offset = offset + (2 * N_BUILTINS as u64);

                    // Write return value address.
                    set_el(&mut public_memory, return_value_offset, return_values_address + i);

                    // Write values.
                    if ((selected_builtins & 1) != 0) {
                        // Set the argument to the builtin start pointer.
                        set_el(
                            &mut public_memory,
                            offset + 1,
                            *borrow(cairo_aux_input, builtin_segment_info_offset)
                        );
                        // Set the return value to the builtin stop pointer.
                        set_el(&mut public_memory, return_value_offset + 1, *borrow(cairo_aux_input,
                            builtin_segment_info_offset + 1
                        ));
                        builtin_segment_info_offset = builtin_segment_info_offset + 2;
                    } else {
                        // Builtin is not present in layout, set the argument value and return value to 0.
                        set_el(&mut public_memory, offset + 1, 0);
                        set_el(&mut public_memory, return_value_offset + 1, 0);
                    };
                    offset = offset + 2;
                    selected_builtins = selected_builtins >> 1;
                };
                // assert!(selected_builtins == 0, SELECTED_BUILTINS_VECTOR_IS_TOO_LONG);
                // Skip the return values which were already written.
                offset = offset + (2 * N_BUILTINS as u64);
            };
            *checkpoint = RPMMP_CHECKPOINT2;
            *borrow_global_mut<Cache3>(signer_addr) = Cache3 {
                public_memory,
                offset,
                n_tasks,
                public_memory_length
            };
            return option::none<vector<u256>>()
        };

        let Cache3 {
            public_memory,
            offset,
            n_tasks,
            public_memory_length
        } = borrow_global_mut<Cache3>(signer_addr);

        if (*checkpoint == RPMMP_CHECKPOINT2) {
            // Program output.
            {
                if (borrow_global<Cache4>(signer_addr).first_invoking) {
                    let ConstructorConfig {
                        hashed_supported_cairo_verifiers,
                        simple_bootloader_program_hash
                    } = borrow_global<ConstructorConfig>(address_of(signer));
                    let output_address = *borrow(cairo_aux_input, OFFSET_OUTPUT_BEGIN_ADDR);
                    // Force that memory[outputAddress] and memory[outputAddress + 1] contain the
                    // bootloader config (which is 2 words size).
                    set_el(public_memory, *offset + 0, output_address);
                    set_el(public_memory, *offset + 1, *simple_bootloader_program_hash);
                    set_el(public_memory, *offset + 2, output_address + 1);
                    set_el(public_memory, *offset + 3, *hashed_supported_cairo_verifiers);
                    // Force that memory[outputAddress + 2] = nTasks.
                    set_el(public_memory, *offset + 4, output_address + 2);
                    set_el(public_memory, *offset + 5, *n_tasks);
                    *offset = *offset + 6;
                    output_address = output_address + 3;

                    let task_metadata_slice = slice(task_metadata,
                        METADATA_TASKS_OFFSET, length(task_metadata));
                    *borrow_global_mut<Cache4>(signer_addr) = Cache4 {
                        ptr: 0,
                        task_metadata_slice,
                        output_address,
                        first_invoking: false
                    };
                };

                let Cache4 {
                    ptr,
                    task_metadata_slice,
                    output_address,
                    first_invoking: first_invoking_cache4
                } = borrow_global_mut<Cache4>(signer_addr);
                let end_ptr = min(*ptr + ITERATION_LENGTH, (*n_tasks as u64));
                for (task in *ptr..end_ptr) {
                    let output_size = *borrow(task_metadata_slice, METADATA_OFFSET_TASK_OUTPUT_SIZE);

                    // Ensure 'outputSize' is at least 2 and bounded from above as a sanity check
                    // (the bound is somewhat arbitrary).
                    assert!(2 <= output_size && output_size < (1 << 30), INVALID_TASK_OUTPUT_SIZE);
                    let program_hash = *borrow(task_metadata_slice, METADATA_OFFSET_TASK_PROGRAM_HASH);
                    let n_tree_pairs = *borrow(task_metadata_slice, METADATA_OFFSET_TASK_N_TREE_PAIRS);

                    // Ensure 'nTreePairs' is at least 1 and bounded from above as a sanity check
                    // (the bound is somewhat arbitrary).
                    assert!(
                        1 <= n_tree_pairs && n_tree_pairs < (1 << 20),
                        INVALID_NUMBER_OF_PAIRS_IN_MERKLE_TREE_STRUCTURE
                    );
                    // Force that memory[outputAddress] = outputSize.
                    set_el(public_memory, *offset + 0, *output_address);
                    set_el(public_memory, *offset + 1, output_size);
                    // Force that memory[outputAddress + 1] = programHash.
                    set_el(public_memory, *offset + 2, *output_address + 1);
                    set_el(public_memory, *offset + 3, program_hash);
                    *offset = *offset + 4;
                    *output_address = *output_address + output_size;
                    let tmp = length(task_metadata_slice);
                    *task_metadata_slice = slice(task_metadata_slice,
                        METADATA_TASK_HEADER_SIZE + (2 * n_tree_pairs as u64), tmp);
                };
                *ptr = end_ptr;
                if (*ptr == (*n_tasks as u64)) {
                    assert!(length(task_metadata_slice) == 0, INVALID_LENGTH_OF_TASK_METADATA);

                    assert!(
                        *borrow(cairo_aux_input, OFFSET_OUTPUT_STOP_PTR) == *output_address,
                        INCONSISTENT_PROGRAM_OUTPUT_LENGTH
                    );
                    *checkpoint = RPMMP_CHECKPOINT3;
                    *first_invoking_cache4 = true;
                };

                return option::none<vector<u256>>()
            };
        };

        if (*checkpoint == RPMMP_CHECKPOINT3) {
            assert!(length(public_memory) == *offset, NOT_ALL_CAIRO_PUBLIC_INPUTS_WERE_WRITTEN);
            let z = *borrow(cairo_aux_input, length(cairo_aux_input) - 2);
            let alpha = *borrow(cairo_aux_input, length(cairo_aux_input) - 1);
            let tmp = register_regular_memorypage(
                signer,
                public_memory,
                z,
                alpha
            );
            if (option::is_none(&tmp)) {
                return option::none<vector<u256>>()
            };
            let tmp = option::borrow(&tmp);
            let (memory_hash, prod) = (*borrow(tmp, 1), *borrow(tmp, 2));
            let public_memory_length = *public_memory_length;

            *checkpoint = RPMMP_CHECKPOINT1;

            return option::some(vector[public_memory_length, memory_hash, prod])
        };
        option::none<vector<u256>>()
    }

    /// error codes
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

    // Data of the function `verify_proof_and_register`

    // checkpoints
    const REGISTER_PUBLIC_MEMORY_MAIN_PAGE: u8 = 1;
    const VERIFY_PROOF_EXTERNAL: u8 = 2;
    const REGISTER_GPS_FACT: u8 = 3;

    struct TaskMetaData has key, drop {
        inner: vector<u256>
    }

    struct VparParams has key, drop {
        proof_params: vector<u256>,
        proof: vector<u256>,
        task_metadata: vector<u256>,
        cairo_aux_input: vector<u256>,
        cairo_verifier_id: u256
    }

    struct VparCheckpoint has key, drop {
        inner: u8
    }

    struct VparCache has key, drop {
        selected_builtins: u256,
        cairo_public_input: vector<u256>,
        public_memory_pages: vector<u256>,
        n_pages: u256,
        first_invoking: bool
    }

    // Data of the function `register_public_memory_main_page`
    // checkpoints
    const RPMMP_CHECKPOINT1: u8 = 1;
    const RPMMP_CHECKPOINT2: u8 = 2;
    const RPMMP_CHECKPOINT3: u8 = 3;

    struct RpmmpCheckpoint has key, drop {
        inner: u8
    }

    struct Cache3 has key, drop {
        public_memory: vector<u256>,
        offset: u64,
        n_tasks: u256,
        public_memory_length: u256
    }

    const ITERATION_LENGTH: u64 = 50;

    struct Cache4 has key, drop {
        ptr: u64,
        task_metadata_slice: vector<u256>,
        output_address: u256,
        first_invoking: bool
    }
}

#[test_only]
module verifier_addr::test_gps {

    use verifier_addr::gps_statement_verifier_test_data::{task_meta_data_, proof_params_, proof_, cairo_aux_input_};
    use verifier_addr::constructor::init_all;
    use verifier_addr::gps_statement_verifier::{prepush_data_to_verify_proof_and_register, prepush_task_metadata,
        verify_proof_and_register
    };

    #[test(signer = @test_signer)]
    fun test_verify_proof_and_register(signer: &signer) {
        init_all(signer);
        prepush_task_metadata(signer, task_meta_data_());
        prepush_data_to_verify_proof_and_register(
            signer,
            proof_params_(),
            proof_(),
            cairo_aux_input_(),
            7u256
        );
        // register_public_memory_main_page
        // console.log(`register_public_memory_main_page::checkpoint1`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::checkpoint2, loop 1`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::checkpoint2, loop 2`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::checkpoint2, loop 3`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::checkpoint2, loop 4`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::checkpoint2, loop 5`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::checkpoint2, loop 6`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::CHECKPOINT3::register_regular_memorypage::compute_fact_hash::CFH_CHECKPOINT1`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::CHECKPOINT3::register_regular_memorypage::compute_fact_hash::long_vec_to_bytes_be, loop 1`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::CHECKPOINT3::register_regular_memorypage::compute_fact_hash::long_vec_to_bytes_be, loop 2`)
        verify_proof_and_register(signer);
        // console.log(`register_public_memory_main_page::CHECKPOINT3::register_regular_memorypage::compute_fact_hash::long_vec_to_bytes_be, loop 3, finish REGISTER_PUBLIC_MEMORY_MAIN_PAGE`)
        verify_proof_and_register(signer);
        
        // verify_proof_external
        // console.log(`verify_proof_external::VP_CHECKPOINT1`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT2`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT3`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT4::oods_consistency_check::OCC_CHECKPOINT1::verify_memory_page_facts, loop 1`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT4::oods_consistency_check::OCC_CHECKPOINT1::verify_memory_page_facts, loop 2`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT4::oods_consistency_check::OCC_CHECKPOINT1::verify_memory_page_facts, loop 3`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT4::oods_consistency_check::OCC_CHECKPOINT2, finish oods_consistency_check + VP_CHECKPOINT4`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT5::compute_first_fri_layer::CFFL_CHECKPOINT1`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT5::compute_first_fri_layer::CFFL_CHECKPOINT2 + cpu_oods_7::fallback::FB_CHECKPOINT1`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT5::compute_first_fri_layer::cpu_oods_7::fallback::FB_CHECKPOINT2, loop 1`)
        verify_proof_and_register(signer);
        // console.log(`verify_proof_external::VP_CHECKPOINT5::compute_first_fri_layer::cpu_oods_7::fallback::FB_CHECKPOINT2, loop 2, finish compute_first_fri_layer + verify_proof_external`)
        verify_proof_and_register(signer);
        
        // register_gps_facts
        // console.log(`register_gps_facts, loop 1`)
        verify_proof_and_register(signer);
        // console.log(`register_gps_facts, loop 2`)
        verify_proof_and_register(signer);
    }

}