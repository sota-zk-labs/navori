module verifier_addr::gps_statement_verifier {
    use std::signer::address_of;
    use std::vector::{borrow, length, push_back, append};
    use aptos_framework::event::emit;

    use cpu_addr::cairo_bootloader_program::get_compiled_program;

    use lib_addr::vector::{trim_head, trim_only};
    use verifier_addr::cairo_verifier_contract::{get_layout_info, verify_proof_external};
    use verifier_addr::gps_output_parser::register_gps_facts;
    use verifier_addr::memory_page_fact_registry::register_regular_memory_page;
    use verifier_addr::stark_verifier_7;

    // This line is used for generating constants DO NOT REMOVE!
    // 10
    const CHECKPOINT1_VPAR: u8 = 0xa;
    // 11
    const CHECKPOINT2_VPAR: u8 = 0xb;
    // 12
    const CHECKPOINT3_VPAR: u8 = 0xc;
    // 14
    const EINCONSISTENT_PROGRAM_OUTPUT_LENGTH: u64 = 0xe;
    // 3
    const EINVALID_CAIROAUXINPUT_LENGTH: u64 = 0x3;
    // 8
    const EINVALID_CUMULATIVE_PRODUCT: u64 = 0x8;
    // 10
    const EINVALID_EXECUTION_BEGIN_ADDRESS: u64 = 0xa;
    // 7
    const EINVALID_HASH_FOR_MEMORY_PAGE_0: u64 = 0x7;
    // 13
    const EINVALID_LENGTH_OF_TASK_METADATA: u64 = 0xd;
    // 4
    const EINVALID_NPAGES: u64 = 0x4;
    // 12
    const EINVALID_NUMBER_OF_PAIRS_IN_MERKLE_TREE_STRUCTURE: u64 = 0xc;
    // 9
    const EINVALID_NUMBER_OF_TASKS: u64 = 0x9;
    // 5
    const EINVALID_PUBLIC_MEMORY_PAGES_LENGTH: u64 = 0x5;
    // 6
    const EINVALID_SIZE_FOR_MEMORY_PAGE_0: u64 = 0x6;
    // 11
    const EINVALID_TASK_OUTPUT_SIZE: u64 = 0xb;
    // 15
    const ENOT_ALL_CAIRO_PUBLIC_INPUTS_WERE_WRITTEN: u64 = 0xf;
    // 10
    const ESELECTED_BUILTINS_VECTOR_IS_TOO_LONG: u64 = 0xa;
    // 2
    const EWRONG_CAIRO_VERIFIER_ID: u64 = 0x2;
    // 1
    const INITIAL_PC: u64 = 0x1;
    // 2
    const MEMORY_PAIR_SIZE: u256 = 0x2;
    // 2
    const METADATA_OFFSET_TASK_N_TREE_PAIRS: u64 = 0x2;
    // 0
    const METADATA_OFFSET_TASK_OUTPUT_SIZE: u64 = 0x0;
    // 1
    const METADATA_OFFSET_TASK_PROGRAM_HASH: u64 = 0x1;
    // 1
    const METADATA_TASKS_OFFSET: u64 = 0x1;
    // 3
    const METADATA_TASK_HEADER_SIZE: u64 = 0x3;
    // 11
    const N_BUILTINS: u256 = 0xb;
    // N_BUILTINS
    const N_MAIN_ARGS: u256 = 0xb;
    // N_BUILTINS
    const N_MAIN_RETURN_VALUES: u256 = 0xb;
    // 7
    const OFFSET_EXECUTION_BEGIN_ADDR: u64 = 0x7;
    // 8
    const OFFSET_EXECUTION_STOP_PTR: u64 = 0x8;
    // 9
    const OFFSET_OUTPUT_BEGIN_ADDR: u64 = 0x9;
    // 10
    const OFFSET_OUTPUT_STOP_PTR: u64 = 0xa;
    // 2
    const PAGE_INFO_HASH_OFFSET: u64 = 0x2;
    // 3
    const PAGE_INFO_SIZE: u64 = 0x3;
    // 1
    const PAGE_INFO_SIZE_OFFSET: u64 = 0x1;
    // 794
    const PROGRAM_SIZE: u256 = 0x31a;
    // End of generating constants!

    struct ConstructorConfig has key {
        hashed_supported_cairo_verifiers: u256,
        simple_bootloader_program_hash: u256,
        applicative_bootloader_program_hash: u256
    }

    public entry fun init_gps_statement_verifier(
        signer: &signer,
        hashed_supported_cairo_verifiers: u256,
        simple_bootloader_program_hash: u256,
        applicative_bootloader_program_hash: u256
    ) {
        move_to(signer, ConstructorConfig {
            hashed_supported_cairo_verifiers,
            simple_bootloader_program_hash,
            applicative_bootloader_program_hash
        });
    }

    public fun init_data_type(signer: &signer) {
        move_to(signer, TaskMetaData {
            inner: vector[]
        });
        move_to(signer, VparParams {
            proof_params: vector[],
            proof: vector[],
            cairo_aux_input: vector[],
            cairo_verifier_id: 0
        });
        move_to(signer, VparCheckpoint {
            inner: CHECKPOINT1_VPAR
        });

        stark_verifier_7::init_data_type(signer);
    }

    public entry fun prepush_data_to_verify_proof_and_register(
        signer: &signer,
        proof_params: vector<u256>,
        proof: vector<u256>,
        cairo_aux_input: vector<u256>,
        cairo_verifier_id: u256
    ) acquires VparParams {
        let signer_addr = address_of(signer);
        *borrow_global_mut<VparParams>(signer_addr) = VparParams {
            proof_params,
            proof,
            cairo_aux_input,
            cairo_verifier_id
        };
    }

    // This function is used to push `task_metadata` before calling the function `verify_proof_and_register` due to
    // Aptos' function parameter size limit
    public entry fun prepush_task_metadata(signer: &signer, task_metadata: vector<u256>) acquires TaskMetaData {
        *borrow_global_mut<TaskMetaData>(address_of(signer)) = TaskMetaData {
            inner: task_metadata
        };
    }

    // Verifies a proof and registers the corresponding facts.
    // For the structure of cairoAuxInput, see cpu/CpuPublicInputOffsets.sol.
    // taskMetadata is structured as follows:
    // 1. Number of tasks.
    // 2. For each task:
    //    1. Task output size (including program hash and size).
    //    2. Program hash.
    public entry fun verify_proof_and_register(
        signer: &signer
    ) acquires ConstructorConfig,
    VparParams,
    VparCheckpoint,
    TaskMetaData {
        let signer_addr = address_of(signer);
        let VparParams {
            proof_params,
            proof,
            cairo_aux_input,
            cairo_verifier_id
        } = borrow_global_mut<VparParams>(signer_addr);

        let TaskMetaData {
            inner: task_metadata
        } = borrow_global_mut<TaskMetaData>(address_of(signer));

        let VparCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<VparCheckpoint>(signer_addr);

        let cairo_aux_input_length = length(cairo_aux_input);
        if (*checkpoint == CHECKPOINT1_VPAR) {
            // Aptos has no abstract contract, so we set `cairo_verifier_id` to 7, as shown in these transactions
            // https://etherscan.io/address/0x47312450b3ac8b5b8e247a6bb6d523e7605bdb60
            // Todo: Consider this function with another `cairo_verifier_id`
            assert!(*cairo_verifier_id == 7, EWRONG_CAIRO_VERIFIER_ID);

            // The values z and alpha are used only for the fact registration of the main page.
            // They are not part of the public input of CpuVerifier as they are computed there.
            // Take the relevant slice from 'cairoAuxInput'.
            // let cairo_public_input = cairo_aux_input[0..length(cairo_aux_input) - 2]; // z and alpha.
            let new_cairo_public_input_length = cairo_aux_input_length - 2;
            let cairo_public_input = *cairo_aux_input;
            trim_only(&mut cairo_public_input, new_cairo_public_input_length); // z and alpha.

            let (public_memory_offset, selected_builtins) = get_layout_info();
            assert!(cairo_aux_input_length > (public_memory_offset as u64), EINVALID_CAIROAUXINPUT_LENGTH);

            let public_memory_pages = cairo_public_input;
            trim_head(&mut public_memory_pages, (public_memory_offset as u64));

            let n_pages = (*borrow(&public_memory_pages, 0) as u64);
            assert!(n_pages < 10000, EINVALID_NPAGES);

            // Validate publicMemoryPages.length.
            // Each page has a page info and a cumulative product.
            // There is no 'page address' in the page info for page 0, but this 'free' slot is
            // used to store the number of pages.
            assert!(
                length(&public_memory_pages) == n_pages * (PAGE_INFO_SIZE + 1),
                EINVALID_PUBLIC_MEMORY_PAGES_LENGTH
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
                *borrow(&public_memory_pages, PAGE_INFO_SIZE_OFFSET) == public_memory_length,
                EINVALID_SIZE_FOR_MEMORY_PAGE_0
            );
            assert!(
                *borrow(&public_memory_pages, PAGE_INFO_HASH_OFFSET) == memory_hash,
                EINVALID_HASH_FOR_MEMORY_PAGE_0
            );
            assert!(
                *borrow(&public_memory_pages, n_pages * PAGE_INFO_SIZE) == prod,
                EINVALID_CUMULATIVE_PRODUCT
            );
            *checkpoint = CHECKPOINT2_VPAR;
            return
        };

        // NOLINTNEXTLINE: reentrancy-benign.
        if (*checkpoint == CHECKPOINT2_VPAR) {
            let new_cairo_public_input_length = cairo_aux_input_length - 2;
            let cairo_public_input = *cairo_aux_input;
            trim_only(&mut cairo_public_input, new_cairo_public_input_length); // z and alpha.

            if (verify_proof_external(signer, proof_params, proof, &cairo_public_input)) {
                *checkpoint = CHECKPOINT3_VPAR;
            };
            return
        };

        if (*checkpoint == CHECKPOINT3_VPAR) {
            let new_cairo_public_input_length = cairo_aux_input_length - 2;
            let cairo_public_input = *cairo_aux_input;
            trim_only(&mut cairo_public_input, new_cairo_public_input_length); // z and alpha.
            let public_memory_pages = cairo_public_input;
            let (public_memory_offset, _) = get_layout_info();
            trim_head(&mut public_memory_pages, (public_memory_offset as u64));

            register_gps_facts(
                signer,
                task_metadata,
                &public_memory_pages,
                *borrow(cairo_aux_input, OFFSET_OUTPUT_BEGIN_ADDR)
            );
            emit(VparFinished {
                ok: true
            });
            *checkpoint = CHECKPOINT1_VPAR;
        };
    }

    // Registers the fact for memory page 0, which includes:
    // 1. The bootloader program,
    // 2. Arguments and return values of main()
    // 3. Some of the data required for computing the task facts. which is represented in
    //    taskMetadata.
    // Returns information on the registered fact.
    //
    // Arguments:
    //   selectedBuiltins: A bit-map of builtins that are present in the layout.
    //       See CairoVerifierContract.sol for more information.
    //   taskMetadata: Per task metadata.
    //   cairoAuxInput: Auxiliary input for the cairo verifier.
    //
    // Assumptions: cairoAuxInput is connected to the public input, which is verified by
    // cairoVerifierContractAddresses.
    // Guarantees: taskMetadata is consistent with the public memory, with some sanity checks.
    fun register_public_memory_main_page(
        signer: &signer,
        task_metadata: &vector<u256>,
        cairo_aux_input: &vector<u256>,
        selected_builtins: u256
    ): (u256, u256, u256) acquires ConstructorConfig {
        let n_tasks = *borrow(task_metadata, 0);
        // Ensure 'n_tasks' is bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(n_tasks < (1 << 30), EINVALID_NUMBER_OF_TASKS);

        // Public memory length.
        let public_memory_length = (PROGRAM_SIZE +
            // return fp and pc =
            2 +
            N_MAIN_ARGS +
            N_MAIN_RETURN_VALUES +
            // Bootloader config size =
            3 +
            // Number of tasks cell =
            1 +
            2 *
                n_tasks);

        let public_memory = vector[];
        // Write public memory, which is a list of pairs (address, value).
        {
            let bootloader_program = get_compiled_program(address_of(signer));
            let n = length(&bootloader_program);
            for (i in 0..n) {
                push_back(&mut public_memory, (i + INITIAL_PC as u256));
                push_back(&mut public_memory, *borrow(&bootloader_program, i));
            }
        };

        {
            // Execution segment - Make sure [initial_fp - 2] = initial_fp and .
            // This is required for the safe call feature (that is, all call instructions will
            // return, even if the called function is malicious).
            // It guarantees that it's not possible to create a cycle in the call stack.
            let initial_fp = *borrow(cairo_aux_input, OFFSET_EXECUTION_BEGIN_ADDR);
            assert!(initial_fp >= 2, EINVALID_EXECUTION_BEGIN_ADDRESS);
            push_back(&mut public_memory, initial_fp - 2);
            push_back(&mut public_memory, initial_fp);
            push_back(&mut public_memory, initial_fp - 1);
            push_back(&mut public_memory, 0);

            // Execution segment: Enforce main's arguments and return values.
            // Note that the page hash depends on the order of the (address, value) pair in the
            // public_memory and consequently the arguments must be written before the return values.
            let return_values_address = *borrow(cairo_aux_input, OFFSET_EXECUTION_STOP_PTR) - N_BUILTINS;
            let builtin_segment_info_offset = OFFSET_OUTPUT_BEGIN_ADDR;
            let return_values = vector[];
            for (i in 0..N_BUILTINS) {
                // Write argument address.
                push_back(&mut public_memory, initial_fp + i);

                // Write return value address.
                push_back(&mut return_values, return_values_address + i);

                // Write values.
                if ((selected_builtins & 1) != 0) {
                    // Set the argument to the builtin start pointer.
                    push_back(&mut public_memory, *borrow(cairo_aux_input, builtin_segment_info_offset));
                    push_back(&mut return_values, *borrow(cairo_aux_input, builtin_segment_info_offset + 1));
                    // Set the return value to the builtin stop pointer.
                    builtin_segment_info_offset = builtin_segment_info_offset + 2;
                } else {
                    // Builtin is not present in layout, set the argument value and return value to 0.
                    push_back(&mut public_memory, 0);
                    push_back(&mut return_values, 0);
                };
                selected_builtins = selected_builtins >> 1;
            };
            assert!(selected_builtins == 0, ESELECTED_BUILTINS_VECTOR_IS_TOO_LONG);
            append(&mut public_memory, return_values);
            // Skip the return values which were already written.
        };

        // Program output.
        {
            let ConstructorConfig {
                hashed_supported_cairo_verifiers,
                simple_bootloader_program_hash,
                applicative_bootloader_program_hash
            } = borrow_global<ConstructorConfig>(address_of(signer));
            let output_address = *borrow(cairo_aux_input, OFFSET_OUTPUT_BEGIN_ADDR);
            // Force that memory[outputAddress: outputAddress + 3] contain the bootloader config
            // (which is 3 words size).
            push_back(&mut public_memory, output_address);
            push_back(&mut public_memory, *simple_bootloader_program_hash);
            push_back(&mut public_memory, output_address + 1);
            push_back(&mut public_memory, *applicative_bootloader_program_hash);
            push_back(&mut public_memory, output_address + 2);
            push_back(&mut public_memory, *hashed_supported_cairo_verifiers);
            // Force that memory[outputAddress + 3] = nTasks.
            push_back(&mut public_memory, output_address + 3);
            push_back(&mut public_memory, n_tasks);
            output_address = output_address + 4;

            let current_metadata_offset = METADATA_TASKS_OFFSET;

            for (task in 0..n_tasks) {
                let output_size = *borrow(
                    task_metadata,
                    current_metadata_offset + METADATA_OFFSET_TASK_OUTPUT_SIZE
                );

                // Ensure 'outputSize' is at least 2 and bounded from above as a sanity check
                // (the bound is somewhat arbitrary).
                assert!(2 <= output_size && output_size < (1 << 30), EINVALID_TASK_OUTPUT_SIZE);
                let program_hash = *borrow(
                    task_metadata,
                    current_metadata_offset + METADATA_OFFSET_TASK_PROGRAM_HASH
                );
                let n_tree_pairs = *borrow(
                    task_metadata,
                    current_metadata_offset + METADATA_OFFSET_TASK_N_TREE_PAIRS
                );

                // Ensure 'nTreePairs' is at least 1 and bounded from above as a sanity check
                // (the bound is somewhat arbitrary).
                assert!(
                    1 <= n_tree_pairs && n_tree_pairs < (1 << 20),
                    EINVALID_NUMBER_OF_PAIRS_IN_MERKLE_TREE_STRUCTURE
                );
                // Force that memory[outputAddress] = outputSize.
                push_back(&mut public_memory, output_address);
                push_back(&mut public_memory, output_size);
                // Force that memory[outputAddress + 1] = programHash.
                push_back(&mut public_memory, output_address + 1);
                push_back(&mut public_memory, program_hash);

                output_address = output_address + output_size;

                current_metadata_offset = METADATA_TASK_HEADER_SIZE + (2 * n_tree_pairs as u64) + current_metadata_offset;
            };

            assert!(length(task_metadata) == current_metadata_offset, EINVALID_LENGTH_OF_TASK_METADATA);

            assert!(
                *borrow(cairo_aux_input, OFFSET_OUTPUT_STOP_PTR) == output_address,
                EINCONSISTENT_PROGRAM_OUTPUT_LENGTH
            );
        };
        assert!(
            (length(&public_memory) as u256) == MEMORY_PAIR_SIZE * public_memory_length,
            ENOT_ALL_CAIRO_PUBLIC_INPUTS_WERE_WRITTEN
        );
        let cairo_aux_input_length = length(cairo_aux_input);
        let z = *borrow(cairo_aux_input, cairo_aux_input_length - 2);
        let alpha = *borrow(cairo_aux_input, cairo_aux_input_length - 1);
        let (memory_hash, prod) = register_regular_memory_page(
            signer,
            &public_memory,
            z,
            alpha
        );
        return (public_memory_length, memory_hash, prod)
    }

    #[test_only]
    public fun get_vpar_checkpoint(signer: &signer): u8 acquires VparCheckpoint {
        borrow_global<VparCheckpoint>(address_of(signer)).inner
    }
    
    // Data of the function `verify_proof_and_register`
    struct TaskMetaData has key, drop {
        inner: vector<u256>
    }

    struct VparParams has key, drop {
        proof_params: vector<u256>,
        proof: vector<u256>,
        cairo_aux_input: vector<u256>,
        cairo_verifier_id: u256
    }

    struct VparCheckpoint has key, drop {
        inner: u8
    }

    #[event]
    struct VparFinished has store, drop {
        ok: bool
    }
}