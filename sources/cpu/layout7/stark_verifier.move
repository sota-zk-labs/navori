module verifier_addr::stark_verifier_7 {
    use std::option;
    use std::option::{is_some, Option};
    use std::signer::address_of;
    use std::vector::{append, borrow, length, slice};
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::math64::min;

    use cpu_addr::cpu_oods_7;
    use cpu_addr::layout_specific_7;
    use cpu_addr::layout_specific_7::{layout_specific_init, safe_div, prepare_for_oods_check};
    use cpu_addr::memory_access_utils_7::get_fri_step_sizes;
    use cpu_addr::public_memory_offsets_7::{get_offset_page_addr, get_offset_page_hash, get_offset_page_prod,
        get_offset_page_size, get_public_input_length
    };
    use lib_addr::bytes::{num_to_bytes_be, u256_from_bytes_be, vec_to_bytes_be};
    use lib_addr::math_mod::{mod_exp};
    use lib_addr::prime_field_element_0::{fadd, fmul, fpow, fsub, inverse};
    use lib_addr::vector::{append_vector, assign, set_el};

    use verifier_addr::fri_statement_verifier_7;
    use verifier_addr::merkle_statement_verifier;
    use verifier_addr::verifier_channel::{init_channel, read_field_element, read_hash, send_field_elements,
        send_random_queries, verify_proof_of_work
    };

    friend verifier_addr::gps_statement_verifier;

    // This line is used for generating constants DO NOT REMOVE!
    // 3
    const GENERATOR_VAL: u256 = 0x3;
    // 0x800000000000011000000000000000000000000000000000000000000000001
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    // 3
    const FRI_QUEUE_SLOT_SIZE: u64 = 0x3;
    // 5
    const PROOF_PARAMS_FRI_STEPS_OFFSET: u64 = 0x5;
    // 4
    const PROOF_PARAMS_N_FRI_STEPS_OFFSET: u64 = 0x4;
    // 0
    const REGULAR_PAGE: u256 = 0x0;
    // 1
    const CONTINUOUS_PAGE: u256 = 0x1;
    // 4
    const LOG_CPU_COMPONENT_HEIGHT: u256 = 0x4;
    // 42800643258479064999893963318903811951182475189843316
    const LAYOUT_CODE: u256 = 42800643258479064999893963318903811951182475189843316;
    // 192
    const MASK_SIZE: u64 = 0xc0;
    // 2
    const CONSTRAINTS_DEGREE_BOUND: u64 = 0x2;
    // MASK_SIZE + CONSTRAINTS_DEGREE_BOUND
    const N_OODS_VALUES: u64 = 0xc2;
    // 16
    const PUBLIC_MEMORY_STEP: u256 = 0x10;
    // 12
    const N_COLUMNS_IN_MASK: u64 = 0xc;
    // 9
    const N_COLUMNS_IN_TRACE0: u64 = 0x9;
    // 3
    const N_COLUMNS_IN_TRACE1: u64 = 0x3;
    // 6
    const N_INTERACTION_ELEMENTS: u64 = 0x6;
    // 124
    const N_COEFFICIENTS: u256 = 0x7c;
    // N_OODS_VALUES
    const N_OODS_COEFFICIENTS: u64 = 0xc2;
    // 0
    const OFFSET_LOG_N_STEPS: u64 = 0x0;
    // 1
    const OFFSET_RC_MIN: u64 = 0x1;
    // 2
    const OFFSET_RC_MAX: u64 = 0x2;
    // 3
    const OFFSET_LAYOUT_CODE: u64 = 0x3;
    // 4
    const OFFSET_PROGRAM_BEGIN_ADDR: u64 = 0x4;
    // 5
    const OFFSET_PROGRAM_STOP_PTR: u64 = 0x5;
    // 1
    const INITIAL_PC: u64 = 0x1;
    // INITIAL_PC + 4
    const FINAL_PC: u64 = 0x5;
    // 6
    const OFFSET_EXECUTION_BEGIN_ADDR: u64 = 0x6;
    // 7
    const OFFSET_EXECUTION_STOP_PTR: u64 = 0x7;
    // 21
    const OFFSET_PUBLIC_MEMORY: u64 = 0x15;
    // 20
    const OFFSET_N_PUBLIC_MEMORY_PAGES: u64 = 0x14;
    // 18
    const OFFSET_PUBLIC_MEMORY_PADDING_ADDR: u64 = 0x12;
    // 0x13b
    const MM_FRI_LAST_LAYER_DEG_BOUND: u64 = 0x13b;
    // 0x144
    const MM_TRACE_LENGTH: u64 = 0x144;
    // 0x3
    const MM_PROOF_OF_WORK_BITS: u64 = 0x3;
    // 0x1
    const MM_BLOW_UP_FACTOR: u64 = 0x1;
    // 48
    const MAX_N_QUERIES: u64 = 0x30;
    // 0x9
    const MM_N_UNIQUE_QUERIES: u64 = 0x9;
    // 0x2
    const MM_LOG_EVAL_DOMAIN_SIZE: u64 = 0x2;
    // 0x0
    const MM_EVAL_DOMAIN_SIZE: u64 = 0x0;
    // 0x4
    const MM_EVAL_DOMAIN_GENERATOR: u64 = 0x4;
    // 0x15e
    const MM_TRACE_GENERATOR: u64 = 0x15e;
    // 0x4fd
    const MM_CONTEXT_SIZE: u64 = 0x4fd;
    // 0x145
    const MM_OFFSET_SIZE: u64 = 0x145;
    // 0x146
    const MM_HALF_OFFSET_SIZE: u64 = 0x146;
    // 0x4fa
    const MM_LOG_N_STEPS: u64 = 0x4fa;
    // 0x150
    const MM_RANGE_CHECK_MIN: u64 = 0x150;
    // 0x151
    const MM_RANGE_CHECK_MAX: u64 = 0x151;
    // 0x148
    const MM_INITIAL_PC: u64 = 0x148;
    // 0x14a
    const MM_FINAL_PC: u64 = 0x14a;
    // 0x147
    const MM_INITIAL_AP: u64 = 0x147;
    // 0x149
    const MM_FINAL_AP: u64 = 0x149;
    // 0x4fc
    const MM_N_PUBLIC_MEM_PAGES: u64 = 0x4fc;
    // 0x4fb
    const MM_N_PUBLIC_MEM_ENTRIES: u64 = 0x4fb;
    // 0x5
    const MM_PUBLIC_INPUT_PTR: u64 = 0x5;
    // 10
    const MAX_FRI_STEPS: u64 = 0xa;
    // 0x6
    const MM_TRACE_COMMITMENT: u64 = 0x6;
    // 0xa
    const MM_CHANNEL: u64 = 0xa;
    // 0x166
    const MM_COMPOSITION_ALPHA: u64 = 0x166;
    // 0x8
    const MM_OODS_COMMITMENT: u64 = 0x8;
    // 0x15f
    const MM_OODS_POINT: u64 = 0x15f;
    // 0x167
    const MM_OODS_VALUES: u64 = 0x167;
    // 0x160
    const MM_INTERACTION_ELEMENTS: u64 = 0x160;
    // 0x14b
    const MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM: u64 = 0x14b;
    // 0x14c
    const MM_MEMORY__MULTI_COLUMN_PERM__HASH_INTERACTION_ELM0: u64 = 0x14c;
    // 0x14e
    const MM_RANGE_CHECK16__PERM__INTERACTION_ELM: u64 = 0x14e;
    // 0x14d
    const MM_MEMORY__MULTI_COLUMN_PERM__PERM__PUBLIC_MEMORY_PROD: u64 = 0x14d;
    // 0x259
    const MM_OODS_ALPHA: u64 = 0x259;
    // 0x131
    const MM_FRI_COMMITMENTS: u64 = 0x131;
    // 0x127
    const MM_FRI_EVAL_POINTS: u64 = 0x127;
    // 0x6d
    const MM_FRI_QUEUE: u64 = 0x6d;
    // 0x229
    const MM_OODS_EVAL_POINTS: u64 = 0x229;
    // 0xd
    const MM_MERKLE_QUEUE: u64 = 0xd;
    // 0x25a
    const MM_TRACE_QUERY_RESPONSES: u64 = 0x25a;
    // 0x49a
    const MM_COMPOSITION_QUERY_RESPONSES: u64 = 0x49a;
    // 0x13c
    const MM_FRI_LAST_LAYER_PTR: u64 = 0x13c;
    // 2
    const FRI_MIN_STEP_SIZE: u256 = 0x2;
    // 4
    const FRI_MAX_STEP_SIZE: u256 = 0x4;
    // 0x126
    const MM_FRI_STEP_SIZES_PTR: u64 = 0x126;
    // 0x13d
    const MM_CONSTRAINT_POLY_ARGS_START: u64 = 0x13d;
    // 0x227
    const MM_CONSTRAINT_POLY_ARGS_END: u64 = 0x227;
    // 0x227
    const MM_COMPOSITION_OODS_VALUES: u64 = 0x227;
    // End of generating constants!
    // constants
    const PROOF_PARAMS_N_QUERIES_OFFSET: u64 = 0;
    const PROOF_PARAMS_LOG_BLOWUP_FACTOR_OFFSET: u64 = 1;
    const PROOF_PARAMS_PROOF_OF_WORK_BITS_OFFSET: u64 = 2;
    const PROOF_PARAMS_FRI_LAST_LAYER_LOG_DEG_BOUND_OFFSET: u64 = 3;

    struct ConstructorConfig has key, copy {
        /*
          The work required to generate an invalid proof is 2^numSecurityBits.
          Typical values: 80-128.
        */
        num_security_bits: u256,
        /*
          The secuirty of a proof is a composition of bits obtained by PoW and bits obtained by FRI
          queries. The verifier requires at least minProofOfWorkBits to be obtained by PoW.
          Typical values: 20-30.
        */
        min_proof_of_work_bits: u256
    }

    public fun init_stark_verifier(signer: &signer, num_security_bits: u256, min_proof_of_work_bits: u256) {
        move_to(signer, ConstructorConfig {
            num_security_bits,
            min_proof_of_work_bits
        });
    }

    public entry fun init_data_type(signer: &signer) {
        move_to(signer, VerifyProofCheckpoint {
            inner: VP_CHECKPOINT1
        });
        move_to(signer, CtxCache {
            inner: vector[]
        });
        move_to(signer, Checkpoint4Cache {
            ptr: 0,
            first_invoking: true
        });
        move_to(signer, VmpfIterationCache {
            ptr: 0,
            first_invoking: true
        });
        move_to(signer, OccCheckpoint {
            checkpoint: 0,
            first_invoking: true
        });
        move_to(signer, CpmpPtr {
            res: 1,
            ptr: 0,
            first_invoking: true
        });
        move_to(signer, CpmqCheckpoint {
            checkpoint: 0,
            first_invoking: true
        });
        move_to(signer, CacheCpmqCheckpoint1 {
            denominator: 0
        });
        move_to(signer, CacheCpmqCheckpoint3 {
             numerator: 0
        });
        move_to(signer, CfflCheckpoint {
             inner: CFFL_CHECKPOINT1
        });
        layout_specific_7::init_data_type(signer);
        cpu_oods_7::init_data_type(signer);
    }

    /*
      Adjusts the query indices and generates evaluation points for each query index.
      The operations above are independent but we can save gas by combining them as both
      operations require us to iterate the queries array.

      Indices adjustment:
          The query indices adjustment is needed because both the Merkle verification and FRI
          expect queries "full binary tree in array" indices.
          The adjustment is simply adding evalDomainSize to each query.
          Note that evalDomainSize == 2^(#FRI layers) == 2^(Merkle tree hight).

      evalPoints generation:
          for each query index "idx" we compute the corresponding evaluation point:
              g^(bitReverse(idx, log_evalDomainSize).
    */
    fun adjust_query_indices_and_prepare_eval_points(ctx: &mut vector<u256>) {
        let n_unique_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);
        let fri_queue = MM_FRI_QUEUE;
        let fri_queue_end = fri_queue + n_unique_queries * FRI_QUEUE_SLOT_SIZE;
        let eval_points_ptr = MM_OODS_EVAL_POINTS;
        let log_eval_domain_size = (*borrow(ctx, MM_LOG_EVAL_DOMAIN_SIZE) as u8);
        let eval_domain_size = *borrow(ctx, MM_EVAL_DOMAIN_SIZE);
        let eval_domain_generator = *borrow(ctx, MM_EVAL_DOMAIN_GENERATOR);

        while (fri_queue < fri_queue_end) {
            let query_idx = *borrow(ctx, fri_queue);
            // Adjust queryIdx, see comment in function description.
            let adjusted_query_idx = query_idx + eval_domain_size;
            set_el(ctx, fri_queue, adjusted_query_idx);

            // Compute the evaluation point corresponding to the current queryIdx.
            set_el(
                ctx,
                eval_points_ptr,
                mod_exp(eval_domain_generator, bit_reverse(query_idx, log_eval_domain_size), K_MODULUS)
            );
            eval_points_ptr = eval_points_ptr + 1;
            fri_queue = fri_queue + FRI_QUEUE_SLOT_SIZE;
        }
    }

    // Note: After the function verifier_channel::verify_proof_of_work, proof_ptr is incremented by 8 bytes. 
    // Therefore, in this function, we must add 8 to proof_ptr.
    /*
      Reads query responses for n_columns from the channel with the corresponding authentication
      paths. Verifies the consistency of the authentication paths with respect to the given
      merkleRoot, and stores the query values in proofDataPtr.

      n_total_columns is the total number of columns represented in proofDataPtr (which should be
      an array of nUniqueQueries rows of size n_total_columns). n_columns is the number of columns
      for which data will be read by this function.
      The change to the proofDataPtr array will be as follows:
      * The first n_columns cells will be set,
      * The next n_total_columns - n_columns will be skipped,
      * The next n_columns cells will be set,
      * The next n_total_columns - n_columns will be skipped,
      * ...

      To set the last columns for each query simply add an offset to proofDataPtr before calling the
      function.
    */
    fun read_query_responses_and_decommit(
        signer: &signer,
        ctx: &mut vector<u256>,
        proof: &vector<u256>,
        n_total_columns: u64,
        n_columns: u64,
        proof_data_ptr: u64,
        merkle_root: u256
    ) {
        assert!(n_columns <= get_n_columns_in_trace() + get_n_columns_in_composition(), TOO_MANY_COLUMNS);
        let n_unique_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);
        let channel_ptr = MM_CHANNEL;
        let fri_queue = MM_FRI_QUEUE;
        let fri_queue_end = fri_queue + n_unique_queries * FRI_QUEUE_SLOT_SIZE;
        let merkle_queue_ptr = MM_MERKLE_QUEUE;
        let row_size = n_columns;
        let proof_data_skip_bytes = (n_total_columns - n_columns);
        let proof_ptr = (*borrow(ctx, channel_ptr) as u64);
        let merkle_ptr = merkle_queue_ptr;

        while (fri_queue < fri_queue_end) {
            // adding 8 bytes
            let bytes = slice(&num_to_bytes_be<u256>(borrow(proof, proof_ptr)), 8, 32);
            let proof_ptr_offset_val = u256_from_bytes_be(
                &append_vector(bytes, slice(&num_to_bytes_be<u256>(borrow(proof, proof_ptr + 1)), 0, 8))
            );
            append(&mut bytes, vec_to_bytes_be(&slice(proof, proof_ptr + 1, proof_ptr + row_size)));
            append(&mut bytes, slice(&num_to_bytes_be<u256>(borrow(proof, proof_ptr + row_size)), 0, 8));
            assert!(length(&bytes) == row_size * 32, WRONG_BYTES_LENGTH);
            let merkle_leaf = u256_from_bytes_be(
                &keccak256(bytes)
            ) & COMMITMENT_MASK;
            if (row_size == 1) {
                // If a leaf contains only 1 field element we don't hash it.
                merkle_leaf = proof_ptr_offset_val;
            };

            // push(queryIdx, hash(row)) to merkleQueue.
            let tmp = *borrow(ctx, fri_queue);
            set_el(ctx, merkle_ptr, tmp);
            set_el(ctx, merkle_ptr + 1, merkle_leaf);
            merkle_ptr = merkle_ptr + 2;

            // Copy query responses to proofData array.
            // This array will be sent to the OODS contract.
            let proof_data_chunk_end = proof_ptr + row_size;
            while (proof_ptr < proof_data_chunk_end) {
                set_el(ctx, proof_data_ptr, proof_ptr_offset_val);
                proof_data_ptr = proof_data_ptr + 1;
                proof_ptr = proof_ptr + 1;
            };
            proof_data_ptr = proof_data_ptr + proof_data_skip_bytes;
            fri_queue = fri_queue + FRI_QUEUE_SLOT_SIZE;
        };

        set_el(ctx, channel_ptr, (proof_ptr as u256));

        merkle_statement_verifier::verify_merkle(
            signer,
            ctx,
            channel_ptr,
            merkle_queue_ptr,
            merkle_root,
            n_unique_queries
        );
    }

    /*
      Computes the first FRI layer by reading the query responses and calling
      the OODS contract.

      The OODS contract will build and sum boundary constraints that check that
      the prover provided the proper evaluations for the Out of Domain Sampling.

      I.e. if the prover said that f(z) = c, the first FRI layer will include
      the term (f(x) - c)/(x-z).
    */
    fun compute_first_fri_layer(signer: &signer, ctx: &mut vector<u256>, proof: &vector<u256>): bool acquires CfflCheckpoint {
        let CfflCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<CfflCheckpoint>(address_of(signer));
        if (*checkpoint == CFFL_CHECKPOINT1) {
            adjust_query_indices_and_prepare_eval_points(ctx);
            // emit LogGas("Prepare evaluation points", gasleft());
            let tmp = *borrow(ctx, MM_TRACE_COMMITMENT);
            read_query_responses_and_decommit(
                signer,
                ctx,
                proof,
                get_n_columns_in_trace(),
                get_n_columns_in_trace_0(),
                MM_TRACE_QUERY_RESPONSES,
                tmp
            );
            // emit LogGas("Read and decommit trace", gasleft());

            tmp = *borrow(ctx, MM_TRACE_COMMITMENT + 1);
            if (has_interaction()) {
                read_query_responses_and_decommit(
                    signer,
                    ctx,
                    proof,
                    get_n_columns_in_trace(),
                    get_n_columns_in_trace_1(),
                    MM_TRACE_QUERY_RESPONSES + get_n_columns_in_trace_0(),
                    tmp
                );
                // emit LogGas("Read and decommit second trace", gasleft());
            };
            *checkpoint = CFFL_CHECKPOINT2;
            return false
        };

        if (*checkpoint == CFFL_CHECKPOINT2) {
            let tmp = *borrow(ctx, MM_OODS_COMMITMENT);
            read_query_responses_and_decommit(
                signer,
                ctx,
                proof,
                get_n_columns_in_composition(),
                get_n_columns_in_composition(),
                MM_COMPOSITION_QUERY_RESPONSES,
                tmp
            );
            *checkpoint = CFFL_CHECKPOINT3;
        };

        // emit LogGas("Read and decommit composition", gasleft());

        if (cpu_oods_7::fallback(signer, ctx)) {
            *checkpoint = CFFL_CHECKPOINT1;
            true
        } else {
            false
        }
        // emit LogGas("OODS virtual oracle", gasleft());
    }

    /*
      Reads the last FRI layer (i.e. the polynomial's coefficients) from the channel.
      This differs from standard reading of channel field elements in several ways:
      -- The digest is updated by hashing it once with all coefficients simultaneously, rather than
         iteratively one by one.
      -- The coefficients are kept in Montgomery form, as is the case throughout the FRI
         computation.
      -- The coefficients are not actually read and copied elsewhere, but rather only a pointer to
         their location in the channel is stored.
    */
    fun read_last_fri_layer(ctx: &mut vector<u256>, proof: &mut vector<u256>) {
        let lmm_channel = MM_CHANNEL;
        let fri_last_layer_deg_bound = *borrow(ctx, MM_FRI_LAST_LAYER_DEG_BOUND);

        let prime_minus_one = 0x800000000000011000000000000000000000000000000000000000000000000u256;
        let channel_ptr = lmm_channel;
        let last_layer_ptr = (*borrow(ctx, channel_ptr) as u64);

        // Make sure all the values are valid field elements.
        let length = (fri_last_layer_deg_bound as u64);
        let last_layer_end = last_layer_ptr + length;
        for (coefs_ptr in last_layer_ptr..last_layer_end) {
            assert!(*borrow(proof, coefs_ptr) <= prime_minus_one, INVALID_FIELD_ELEMENT);
        };

        // Update prng.digest with the hash of digest + 1 and the last layer coefficient.
        // (digest + 1) is written to the proof area because keccak256 needs all data to be
        // consecutive.
        let new_digest_ptr = last_layer_ptr - 1;
        let digest_ptr = channel_ptr + 1;
        // Overwriting the proof to minimize copying of data.
        set_el(proof, new_digest_ptr, *borrow(ctx, digest_ptr) + 1);

        // prng.digest = keccak256((digest+1)||lastLayerCoefs).
        set_el(
            ctx,
            digest_ptr,
            u256_from_bytes_be(&keccak256(vec_to_bytes_be(&slice(proof, new_digest_ptr, new_digest_ptr + length + 1))))
        );
        // prng.counter = 0.
        set_el(ctx, channel_ptr + 2, 0);

        // Note: proof pointer is not incremented until this point.
        set_el(ctx, channel_ptr, (last_layer_end as u256));

        set_el(ctx, MM_FRI_LAST_LAYER_PTR, (last_layer_ptr as u256));
    }

    public fun verify_proof(
        signer: &signer,
        proof_params: &vector<u256>,
        proof: &mut vector<u256>,
        public_input: &vector<u256>
    ): bool acquires ConstructorConfig, VerifyProofCheckpoint, CtxCache, Checkpoint4Cache, VmpfIterationCache, OccCheckpoint, CpmpPtr, CpmqCheckpoint, CacheCpmqCheckpoint1, CacheCpmqCheckpoint3, CfflCheckpoint {
        let signer_addr = address_of(signer);
        let VerifyProofCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<VerifyProofCheckpoint>(signer_addr);
        if (*checkpoint == VP_CHECKPOINT1) {
            *borrow_global_mut<CtxCache>(signer_addr) = CtxCache {
                inner: init_verifier_params(signer, public_input, proof_params)
            };
            *checkpoint = VP_CHECKPOINT2;
            return false
        };

        let CtxCache {
            inner: ctx
        } = borrow_global_mut<CtxCache>(signer_addr);
        let channel_ptr = MM_CHANNEL;

        if (*checkpoint == VP_CHECKPOINT2) {
            init_channel(ctx, channel_ptr, get_public_input_hash(public_input));
            // Read trace commitment.
            let hash = read_hash(ctx, proof, channel_ptr, true);
            set_el(ctx, MM_TRACE_COMMITMENT, hash);

            if (has_interaction()) {
                // Send interaction elements.
                send_field_elements(
                    ctx,
                    channel_ptr,
                    get_n_interaction_elements(),
                    get_mm_interaction_elements()
                );

                // Read second trace commitment.
                let tmp = read_hash(ctx, proof, channel_ptr, true);
                set_el(ctx, MM_TRACE_COMMITMENT + 1, tmp);
            };
            // Send constraint polynomial random element.
            send_field_elements(ctx, channel_ptr, 1, MM_COMPOSITION_ALPHA);
            // emit LogGas("Generate coefficients", gasleft());

            hash = read_hash(ctx, proof, channel_ptr, true);
            set_el(ctx, MM_OODS_COMMITMENT, hash);

            // Send Out of Domain Sampling point.
            send_field_elements(ctx, channel_ptr, 1, MM_OODS_POINT);
            *checkpoint = VP_CHECKPOINT4;
            return false
        };
        // emit LogGas(Initializations, gasleft());

        if (*checkpoint == VP_CHECKPOINT4) {
            // Read the answers to the Out of Domain Sampling.
            let lmm_oods_values = MM_OODS_VALUES;
            let Checkpoint4Cache {
                ptr,
                first_invoking
            } = borrow_global_mut<Checkpoint4Cache>(signer_addr);
            if (*first_invoking) {
                *ptr = lmm_oods_values;
                *first_invoking = false;
            };
            let end_ptr = min(lmm_oods_values + N_OODS_VALUES, *ptr + CHECKPOINT4_ITERATION_LENGTH);
            for (i in *ptr..end_ptr) {
                let tmp = read_field_element(ctx, proof, channel_ptr, true);
                set_el(ctx, i, tmp);
            };
            *ptr = end_ptr;
            if (end_ptr == lmm_oods_values + N_OODS_VALUES) {
                *checkpoint = VP_CHECKPOINT5;
                *first_invoking = true;
            };
            return false
        };
        // emit LogGas("Read OODS commitments", gasleft());
        if (*checkpoint == VP_CHECKPOINT5) {
            if (oods_consistency_check(signer, ctx, public_input)) {
                *checkpoint = VP_CHECKPOINT6;
            };
            return false
        };
        if (*checkpoint == VP_CHECKPOINT6) {
            // emit LogGas("OODS consistency check", gasleft());
            send_field_elements(ctx, channel_ptr, 1, MM_OODS_ALPHA);
            // emit LogGas("Generate OODS coefficients", gasleft());
            let hash = read_hash(ctx, proof, channel_ptr, true);
            set_el(ctx, MM_FRI_COMMITMENTS, hash);

            let n_fri_steps = length(&get_fri_step_sizes(proof_params));
            let fri_eval_point_ptr = MM_FRI_EVAL_POINTS;
            for (i in 1..(n_fri_steps - 1)) {
                send_field_elements(ctx, channel_ptr, 1, fri_eval_point_ptr + i);
                hash = read_hash(ctx, proof, channel_ptr, true);
                set_el(ctx, MM_FRI_COMMITMENTS + i, hash);
            };

            // Send last random FRI evaluation point.
            send_field_elements(
                ctx,
                channel_ptr,
                1,
                MM_FRI_EVAL_POINTS + n_fri_steps - 1
            );

            // Read FRI last layer commitment.
            read_last_fri_layer(ctx, proof);

            // Generate queries.
            // emit LogGas("Read FRI commitments", gasleft());
            let tmp = (*borrow(ctx, MM_PROOF_OF_WORK_BITS) as u8);
            verify_proof_of_work(ctx, proof, channel_ptr, tmp);

            let tmp1 = *borrow(ctx, MM_N_UNIQUE_QUERIES);
            let tmp2 = *borrow(ctx, MM_EVAL_DOMAIN_SIZE);
            let tmp = send_random_queries(
                ctx,
                channel_ptr,
                tmp1,
                tmp2 - 1,
                MM_FRI_QUEUE,
                FRI_QUEUE_SLOT_SIZE,
            );
            set_el(ctx, MM_N_UNIQUE_QUERIES, tmp);
            
            *checkpoint = VP_CHECKPOINT7;
            return false
        };
        // emit LogGas("Send queries", gasleft());

        if (*checkpoint == VP_CHECKPOINT7) {
            if (compute_first_fri_layer(signer, ctx, proof)) {
                *checkpoint = VP_CHECKPOINT8;
            };
            return false
        };

        fri_statement_verifier_7::fri_verify_layers(signer, ctx, proof, proof_params);
        // option::some(true)
        *checkpoint = VP_CHECKPOINT1;
        true
    }

    public fun init_verifier_params(
        signer: &signer,
        public_input: &vector<u256>,
        proof_params: &vector<u256>
    ): vector<u256> acquires ConstructorConfig {
        let ConstructorConfig {
            min_proof_of_work_bits,
            num_security_bits
        } = *borrow_global<ConstructorConfig>(address_of(signer));
        assert!(length(proof_params) > PROOF_PARAMS_FRI_STEPS_OFFSET, INVALID_PROOF_PARAMS);
        assert!(
            length(proof_params) == PROOF_PARAMS_FRI_STEPS_OFFSET + (*borrow(
                proof_params,
                PROOF_PARAMS_N_FRI_STEPS_OFFSET
            ) as u64),
            INVALID_PROOF_PARAMS
        );
        let log_blowup_factor = *borrow(proof_params, PROOF_PARAMS_LOG_BLOWUP_FACTOR_OFFSET);
        // Ensure 'logBlowupFactor' is bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(log_blowup_factor <= 16, LOG_BLOWUP_FACTOR_MUST_BE_AT_MOST_16);
        assert!(log_blowup_factor >= 1, LOG_BLOWUP_FACTOR_MUST_BE_AT_LEAST_1);

        let proof_of_work_bits = *borrow(proof_params, PROOF_PARAMS_PROOF_OF_WORK_BITS_OFFSET);
        // Ensure 'proofOfWorkBits' is bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(proof_of_work_bits <= 50, PROOF_OF_WORK_BITS_MUST_BE_AT_MOST_50);
        assert!(proof_of_work_bits >= min_proof_of_work_bits, MINIMUM_PROOF_OF_WORK_BITS_NOT_SATISFIED);
        assert!(proof_of_work_bits < num_security_bits, PROOFS_MAY_NOT_BE_PURELY_BASED_ON_POW);

        let log_fri_last_layer_deg_bound = *borrow(proof_params, PROOF_PARAMS_FRI_LAST_LAYER_LOG_DEG_BOUND_OFFSET);
        assert!(log_fri_last_layer_deg_bound <= 10, LOG_FRI_LAST_LAYER_DEG_BOUND_MUST_BE_AT_MOST_10);

        let n_fri_steps = *borrow(proof_params, PROOF_PARAMS_N_FRI_STEPS_OFFSET);
        assert!(n_fri_steps <= (MAX_FRI_STEPS as u256), TOO_MANY_FRI_STEPS);
        assert!(n_fri_steps > 1, NOT_ENOUGH_FRI_STEPS);

        let fri_step_sizes = get_fri_step_sizes(proof_params);

        let (ctx, log_trace_length) = air_specific_init(public_input);

        validate_fri_params(&fri_step_sizes, log_trace_length, log_fri_last_layer_deg_bound);

        // This assignment is required for the function `getFriStepSizes` in original contract, but we don't need it here 
        // set_el(&mut ctx, MM_FRI_STEP_SIZES_PTR, (length(&fri_step_sizes) as u256));

        set_el(&mut ctx, MM_FRI_LAST_LAYER_DEG_BOUND, (1u256 << (log_fri_last_layer_deg_bound as u8)));
        set_el(&mut ctx, MM_TRACE_LENGTH, (1u256 << (log_trace_length as u8)));

        set_el(&mut ctx, MM_BLOW_UP_FACTOR, (1u256 << (log_blowup_factor as u8)));
        set_el(&mut ctx, MM_PROOF_OF_WORK_BITS, proof_of_work_bits);

        let n_queries = *borrow(proof_params, PROOF_PARAMS_N_QUERIES_OFFSET);
        assert!(n_queries > 0, NUMBER_OF_QUERIES_MUST_BE_AT_LEAST_ONE);
        assert!(n_queries <= (MAX_N_QUERIES as u256), TOO_MANY_QUERIES);
        assert!(
            n_queries * log_blowup_factor + proof_of_work_bits >= num_security_bits,
            PROOF_PARAMS_DO_NOT_SATISFY_SECURITY
        );

        set_el(&mut ctx, MM_N_UNIQUE_QUERIES, n_queries);

        // We start with logEvalDomainSize = logTraceSize and update it here.
        set_el(&mut ctx, MM_LOG_EVAL_DOMAIN_SIZE, log_trace_length + log_blowup_factor);
        let tmp = (1u256 << (*borrow(&ctx, MM_LOG_EVAL_DOMAIN_SIZE) as u8));
        set_el(
            &mut ctx,
            MM_EVAL_DOMAIN_SIZE,
            tmp
        );

        // Compute the generators for the evaluation and trace domains.
        let gen_eval_domain = fpow(GENERATOR_VAL, (K_MODULUS - 1) / *borrow(&ctx, MM_EVAL_DOMAIN_SIZE));
        set_el(&mut ctx, MM_EVAL_DOMAIN_GENERATOR, gen_eval_domain);
        tmp = *borrow(&ctx,
            MM_BLOW_UP_FACTOR
        );
        set_el(&mut ctx, MM_TRACE_GENERATOR, fpow(gen_eval_domain, tmp));

        ctx
    }

    fun validate_fri_params(
        fri_step_sizes: &vector<u256>,
        log_trace_length: u256,
        log_fri_last_layer_deg_bound: u256
    ) {
        assert!(*borrow(fri_step_sizes, 0) == 0, ONLY_ETA0_IS_CURRENTLY_SUPPORTED);
        let expected_log_deg_bound = log_fri_last_layer_deg_bound;
        let n_fri_steps = length(fri_step_sizes);
        for (i in 1..n_fri_steps) {
            let fri_step_size = *borrow(fri_step_sizes, i);
            assert!(fri_step_size >= FRI_MIN_STEP_SIZE, MIN_SUPPORTED_FRI_STEP_SIZE_IS_2);
            assert!(fri_step_size <= FRI_MAX_STEP_SIZE, MAX_SUPPORTED_FRI_STEP_SIZE_IS_4);
            expected_log_deg_bound = expected_log_deg_bound + fri_step_size;
        };

        // FRI starts with a polynomial of degree 'traceLength'.
        // After applying all the FRI steps we expect to get a polynomial of degree less
        // than friLastLayerDegBound.
        assert!(expected_log_deg_bound == log_trace_length, FRI_PARAMS_DO_NOT_MATCH_TRACE_LENGTH);
    }

    // In Starknet's contracts, this function is implemented in `CpuVerifier.sol`
    // * The `ctx` returned is not the same as the `ctx` in the original contract.
    fun air_specific_init(public_input: &vector<u256>): (vector<u256>, u256) {
        assert!(length(public_input) >= OFFSET_PUBLIC_MEMORY, PUBLIC_INPUT_IS_TOO_SHORT);
        let ctx = assign(0u256, MM_CONTEXT_SIZE);

        // Context for generated code.
        set_el(&mut ctx, MM_OFFSET_SIZE, 1 << 16);
        set_el(&mut ctx, MM_HALF_OFFSET_SIZE, 1 << 15);

        // Number of steps.
        let log_n_steps = *borrow(public_input, OFFSET_LOG_N_STEPS);
        assert!(log_n_steps < 50, NUMBER_OF_STEPS_IS_TOO_LARGE);
        set_el(&mut ctx, MM_LOG_N_STEPS, log_n_steps);
        let log_trace_length = log_n_steps + LOG_CPU_COMPONENT_HEIGHT;

        // Range check limits.
        set_el(&mut ctx, MM_RANGE_CHECK_MIN, *borrow(public_input, OFFSET_RC_MIN));
        set_el(&mut ctx, MM_RANGE_CHECK_MAX, *borrow(public_input, OFFSET_RC_MAX));
        assert!(
            *borrow(&ctx, MM_RANGE_CHECK_MIN) <= *borrow(&ctx, MM_RANGE_CHECK_MAX),
            RC_MIN_MUST_BE_LESS_THAN_OR_EQUAL_TO_RC_MAX
        );
        assert!(*borrow(&ctx, MM_RANGE_CHECK_MAX) < *borrow(&ctx, MM_OFFSET_SIZE), RC_MAX_OUT_OF_RANGE);

        // Layout.
        assert!(*borrow(public_input, OFFSET_LAYOUT_CODE) == LAYOUT_CODE, LAYOUT_CODE_MISMATCH);

        // Initial and final pc ("program" memory segment).
        set_el(&mut ctx, MM_INITIAL_PC, *borrow(public_input, OFFSET_PROGRAM_BEGIN_ADDR));
        set_el(&mut ctx, MM_FINAL_PC, *borrow(public_input, OFFSET_PROGRAM_STOP_PTR));
        // Invalid final pc may indicate that the program end was moved, or the program didn't
        // complete.
        assert!(*borrow(&ctx, MM_INITIAL_PC) == (INITIAL_PC as u256), INVALID_INITIAL_PC);
        assert!(*borrow(&ctx, MM_FINAL_PC) == (FINAL_PC as u256), INVALID_FINAL_PC);

        // Initial and final ap ("execution" memory segment).
        set_el(&mut ctx, MM_INITIAL_AP, *borrow(public_input, OFFSET_EXECUTION_BEGIN_ADDR));
        set_el(&mut ctx, MM_FINAL_AP, *borrow(public_input, OFFSET_EXECUTION_STOP_PTR));

        // Public memory.
        assert!(
            *borrow(public_input, OFFSET_N_PUBLIC_MEMORY_PAGES) >= 1 &&
                *borrow(public_input, OFFSET_N_PUBLIC_MEMORY_PAGES) < 100000, INVALID_NUMBER_OF_MEMORY_PAGES
        );
        set_el(&mut ctx, MM_N_PUBLIC_MEM_PAGES, *borrow(public_input, OFFSET_N_PUBLIC_MEMORY_PAGES));

        {
            // Compute the total number of public memory entries.
            let n_public_memory_entries = 0;
            let n_pages = *borrow(&ctx, MM_N_PUBLIC_MEM_PAGES);
            for (page in 0..n_pages) {
                let n_page_entries = *borrow(public_input, (get_offset_page_size(page) as u64));
                assert!(n_page_entries < (1 << 30), TOO_MANY_PUBLIC_MEMORY_ENTRIES_IN_ONE_PAGE);
                n_public_memory_entries = n_public_memory_entries + n_page_entries;
            };
            set_el(&mut ctx, MM_N_PUBLIC_MEM_ENTRIES, n_public_memory_entries);
        };

        let expected_public_input_length = get_public_input_length(*borrow(&ctx, MM_N_PUBLIC_MEM_PAGES));
        assert!(expected_public_input_length == (length(public_input) as u256), PUBLIC_INPUT_LENGTH_MISMATCH);

        let lmm_public_input_ptr = MM_PUBLIC_INPUT_PTR;
        // store 0 instead of the address of public_input[0] as in original contract
        set_el(&mut ctx, lmm_public_input_ptr, 0);

        layout_specific_init(&mut ctx, public_input);

        (ctx, log_trace_length)
    }

    // In Starknet's contracts, this function is implemented in `CpuVerifier.sol`
    /*
      Verifies that all the information on each public memory page (size, hash, prod, and possibly
      address) is consistent with z and alpha, by checking that the corresponding facts were
      registered on memoryPageFactRegistry.
    */
    fun verify_memory_page_facts(
        signer: &signer,
        ctx: &mut vector<u256>,
        public_input: &vector<u256>
    ): bool acquires VmpfIterationCache {
        let signer_addr = address_of(signer);
        let VmpfIterationCache {
            ptr,
            first_invoking
        } = borrow_global_mut<VmpfIterationCache>(signer_addr);
        if (*first_invoking) {
            *ptr = 0;
            *first_invoking = false;
        };
        let n_public_memory_pages = *borrow(ctx, MM_N_PUBLIC_MEM_PAGES);

        let end_ptr = (min((n_public_memory_pages as u64), (*ptr + VMPF_ITERATION_LENGTH as u64)) as u256);
        for (page in *ptr..end_ptr) {
            let mm_public_input_ptr = *borrow(ctx, MM_PUBLIC_INPUT_PTR);
            // Fetch page values from the public input (hash, product and size).
            let memory_hash = *borrow(public_input, (mm_public_input_ptr + get_offset_page_hash(page) as u64));
            let prod = *borrow(public_input,
                (mm_public_input_ptr + get_offset_page_prod(page, n_public_memory_pages) as u64)
            );
            let page_size = *borrow(public_input, (mm_public_input_ptr + get_offset_page_size(page) as u64));

            let page_addr = 0;
            if (page > 0) {
                page_addr = *borrow(public_input, (mm_public_input_ptr + get_offset_page_addr(page) as u64));
            };

            // Verify that a corresponding fact is registered attesting to the consistency of the page
            // information with z and alpha.
            let fact_hash = u256_from_bytes_be(&keccak256(vec_to_bytes_be<u256>(&vector[
                if (page == 0) { REGULAR_PAGE } else { CONTINUOUS_PAGE },
                K_MODULUS,
                page_size,
                /*z=*/
                *borrow(ctx, MM_INTERACTION_ELEMENTS),
                /*alpha=*/
                *borrow(ctx, MM_INTERACTION_ELEMENTS + 1),
                prod,
                memory_hash,
                page_addr
            ])));

            // assert!(is_valid(signer, fact_hash), MEMORY_PAGE_FACT_NOT_REGISTERED);
        };
        *ptr = end_ptr;
        if (end_ptr == n_public_memory_pages) {
            *first_invoking = true;
            true
        } else {
            false
        }
    }

    // In Starknet's contracts, this function is implemented in `CpuVerifier.sol`
    fun get_public_input_hash(public_input: &vector<u256>): u256 {
        // The initial seed consists of the first part of publicInput. Specifically, it does not
        // include the page products (which are only known later in the process, as they depend on
        // the values of z and alpha).
        let n_pages = *borrow(public_input, OFFSET_N_PUBLIC_MEMORY_PAGES);
        let public_input_size_for_hash = get_offset_page_prod(0, n_pages);

        u256_from_bytes_be(&keccak256(vec_to_bytes_be(&slice(public_input, 0, (public_input_size_for_hash as u64)))))
    }

    /*
          Computes the value of the public memory quotient:
            numerator / (denominator * padding)
          where:
            numerator = (z - (0 + alpha * 0))^S,
            denominator = \prod_i( z - (addr_i + alpha * value_i) ),
            padding = (z - (padding_addr + alpha * padding_value))^(S - N),
            N is the actual number of public memory cells,
            and S is the number of cells allocated for the public memory (which includes the padding).
    */
    fun compute_public_memory_quotient(
        signer: &signer,
        ctx: &mut vector<u256>,
        public_input: &vector<u256>
    ): Option<u256> acquires CpmpPtr, CpmqCheckpoint, CacheCpmqCheckpoint1, CacheCpmqCheckpoint3 {
        let signer_addr = address_of(signer);
        let CpmqCheckpoint {
            checkpoint,
            first_invoking
        } = borrow_global_mut<CpmqCheckpoint>(signer_addr);
        if (*first_invoking) {
            *checkpoint = CPMQ_CHECKPOINT1;
            *first_invoking = false;
        };
        if (*checkpoint == CPMQ_CHECKPOINT1) {
            let n_public_memory_pages = *borrow(ctx, MM_N_PUBLIC_MEM_PAGES);
            let cumulative_prods_ptr = *borrow(ctx, MM_PUBLIC_INPUT_PTR) + get_offset_page_prod(
                0,
                n_public_memory_pages
            );
            let denominator = compute_public_memory_prod(
                signer,
                public_input,
                (cumulative_prods_ptr as u64),
                (n_public_memory_pages as u64)
            );
            if (option::is_none(&denominator)) {
                return option::none<u256>()
            };
            *borrow_global_mut<CacheCpmqCheckpoint1>(signer_addr) = CacheCpmqCheckpoint1 {
                denominator: *option::borrow(&denominator)
            };

            *checkpoint = CPMQ_CHECKPOINT2;
            // return option::none<u256>()
        };

        let CacheCpmqCheckpoint1 {
            denominator
        } = borrow_global_mut<CacheCpmqCheckpoint1>(signer_addr);

        if (*checkpoint == CPMQ_CHECKPOINT2) {
            let n_values = *borrow(ctx, MM_N_PUBLIC_MEM_ENTRIES);
            let z = *borrow(ctx, MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM);
            let alpha = *borrow(ctx, MM_MEMORY__MULTI_COLUMN_PERM__HASH_INTERACTION_ELM0);
            // The size that is allocated to the public memory.
            let public_memory_size = safe_div(*borrow(ctx, MM_TRACE_LENGTH), PUBLIC_MEMORY_STEP);

            // Ensure 'nValues' is bounded as a sanity check
            // (the bound is somewhat arbitrary).
            assert!(n_values < 0x1000000, OVERFLOW_PROTECTION_FAILED);
            assert!(n_values <= public_memory_size, NUMBER_OF_VALUES_OF_PUBLIC_MEMORY_IS_TOO_LARGE);
            // Compute address + alpha * value for the first address-value pair for padding.
            let public_input_ptr = (*borrow(ctx, MM_PUBLIC_INPUT_PTR) as u64);
            let padding_addr_ptr = public_input_ptr + OFFSET_PUBLIC_MEMORY_PADDING_ADDR;
            let padding_addr = *borrow(public_input, padding_addr_ptr);
            let padding_value = *borrow(public_input, padding_addr_ptr + 1);
            let hash_first_address_value = fadd(padding_addr, fmul(padding_value, alpha));

            // Pad the denominator with the shifted value of hash_first_address_value.
            let denom_pad = fpow(fsub(z, hash_first_address_value), public_memory_size - n_values);
            *denominator = fmul(*denominator, denom_pad);

            *checkpoint = CPMQ_CHECKPOINT3;
            // return option::none<u256>()
        };

        if (*checkpoint == CPMQ_CHECKPOINT3) {
            let z = *borrow(ctx, MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM);
            let public_memory_size = safe_div(*borrow(ctx, MM_TRACE_LENGTH), PUBLIC_MEMORY_STEP);
            // Calculate the numerator.
            let numerator = fpow(z, public_memory_size);
            *borrow_global_mut<CacheCpmqCheckpoint3>(signer_addr) = CacheCpmqCheckpoint3 {
                numerator
            };
            *checkpoint = CPMQ_CHECKPOINT4;
            // return option::none<u256>()
        };

        // Compute the final result: numerator * denominator^(-1).
        option::some(fmul(borrow_global<CacheCpmqCheckpoint3>(signer_addr).numerator, inverse(*denominator)))
    }

    /*
          Computes the cumulative product of the public memory cells:
            \prod_i( z - (addr_i + alpha * value_i) ).

          publicMemoryPtr is an array of nValues pairs (address, value).
          z and alpha are the perm and hash interaction elements assert!d to calculate the product.
    */
    fun compute_public_memory_prod(
        signer: &signer,
        public_input: &vector<u256>,
        cumulative_prods_ptr: u64,
        n_public_memory_pages: u64
    ): Option<u256> acquires CpmpPtr {
        let CpmpPtr {
            res,
            ptr,
            first_invoking
        } = borrow_global_mut<CpmpPtr>(address_of(signer));
        if (*first_invoking) {
            *res = 1;
            *ptr = cumulative_prods_ptr;
            *first_invoking = false;
        };
        let end_ptr = min(cumulative_prods_ptr + n_public_memory_pages, *ptr + CPMP_ITERATION_LENGTH);
        for (i in *ptr..end_ptr) {
            *res = fmul(*res, *borrow(public_input, i));
        };
        *ptr = end_ptr;
        if (end_ptr == cumulative_prods_ptr + n_public_memory_pages) {
            *first_invoking = true;
            option::some(*res)
        } else {
            option::none<u256>()
        }
    }

    // In Starknet's contracts, this function is implemented in `CpuVerifier.sol`
    fun oods_consistency_check(
        signer: &signer,
        ctx: &mut vector<u256>,
        public_input: &vector<u256>
    ): bool acquires VmpfIterationCache, OccCheckpoint, CpmpPtr, CpmqCheckpoint, CacheCpmqCheckpoint1, CacheCpmqCheckpoint3 {
        let signer_addr = address_of(signer);
        let OccCheckpoint {
            checkpoint,
            first_invoking
        } = borrow_global_mut<OccCheckpoint>(signer_addr);
        if (*first_invoking) {
            *checkpoint = OCC_CHECKPOINT1;
            *first_invoking = false;
        };
        if (*checkpoint == OCC_CHECKPOINT1) {
            if (verify_memory_page_facts(signer, ctx, public_input)) {
                let temp = *borrow(ctx, MM_INTERACTION_ELEMENTS);
                set_el(ctx, MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM, temp);
                let temp = *borrow(ctx, MM_INTERACTION_ELEMENTS + 1);
                set_el(ctx, MM_MEMORY__MULTI_COLUMN_PERM__HASH_INTERACTION_ELM0, temp);
                let temp = *borrow(ctx, MM_INTERACTION_ELEMENTS + 2);
                set_el(ctx, MM_RANGE_CHECK16__PERM__INTERACTION_ELM, temp);
                *checkpoint = OCC_CHECKPOINT2;
            };
            return false
        };
        if (*checkpoint == OCC_CHECKPOINT2) {
            let public_memory_prod = compute_public_memory_quotient(signer, ctx, public_input);
            if (is_some(&public_memory_prod)) {
                let public_memory_prod = *option::borrow(&public_memory_prod);
                set_el(ctx, MM_MEMORY__MULTI_COLUMN_PERM__PERM__PUBLIC_MEMORY_PROD, public_memory_prod);
                *checkpoint = OCC_CHECKPOINT3;
            };
            return false
        };
        if (*checkpoint == OCC_CHECKPOINT3) {
            if (prepare_for_oods_check(signer, ctx)) {
                *checkpoint = OCC_CHECKPOINT4;
            };
            return false
        };

        // Todo
        // let composition_from_trace_value;
        // address
        // lconstraintPoly = address(constraintPoly);
        // let offset = 1 + MM_CONSTRAINT_POLY_ARGS_START;
        // let size = MM_CONSTRAINT_POLY_ARGS_END - MM_CONSTRAINT_POLY_ARGS_START;
        // assembly {
        //     // Call CpuConstraintPoly contract.
        //     let p = mload(0x40)
        //     if iszero(staticcall(not(0), lconstraintPoly, add(ctx, offset), size, p, 0x20)) {
        //     returndatacopy(0, 0, returndatasize())
        //     revert(0, returndatasize())
        //     }
        //     compositionFromTraceValue = mload(p)
        // }

        // let claimed_composition = fadd(
        //     *borrow(ctx, MM_COMPOSITION_OODS_VALUES),
        //     fmul(*borrow(ctx, MM_OODS_POINT), *borrow(ctx, MM_COMPOSITION_OODS_VALUES + 1))
        // );

        // assert!(
        //     composition_from_trace_value == claimed_composition,
        //     CLAIMED_COMPOSITION_DOES_NOT_MATCH_TRACE
        // );
        *first_invoking = true;
        true
    }

    fun get_n_columns_in_trace(): u64 {
        N_COLUMNS_IN_MASK
    }

    fun get_n_columns_in_trace_0(): u64 {
        N_COLUMNS_IN_TRACE0
    }

    fun get_n_columns_in_trace_1(): u64 {
        N_COLUMNS_IN_TRACE1
    }

    fun get_n_columns_in_composition(): u64 {
        CONSTRAINTS_DEGREE_BOUND
    }

    fun get_mm_interaction_elements(): u64 {
        MM_INTERACTION_ELEMENTS
    }

    fun get_mm_oods_values(): u256 {
        (MM_OODS_VALUES as u256)
    }

    fun get_n_interaction_elements(): u64 {
        N_INTERACTION_ELEMENTS
    }

    fun get_n_coefficients(): u256 {
        N_COEFFICIENTS
    }

    fun get_n_oods_values(): u64 {
        N_OODS_VALUES
    }

    fun get_n_oods_coefficients(): u64 {
        N_OODS_COEFFICIENTS
    }

    fun get_public_memory_offset(): u64 {
        OFFSET_PUBLIC_MEMORY
    }

    fun has_interaction(): bool {
        get_n_columns_in_trace_1() > 0
    }

    fun bit_reverse(value: u256, number_of_bits: u8): u256 {
        // Bit reverse value by swapping 1 bit chunks then 2 bit chunks and so forth.
        // A swap can be done by masking the relevant chunks and shifting them to the
        // correct location.
        // However, to save some shift operations we shift only one of the chunks by twice
        // the chunk size, and perform a single right shift at the end.
        let res = value;
        // Swap 1 bit chunks.
        res = ((res & 0x5555555555555555) << 2) | (res & 0xaaaaaaaaaaaaaaaa);
        // Swap 2 bit chunks.
        res = ((res & 0x6666666666666666) << 4) | (res & 0x19999999999999998);
        // Swap 4 bit chunks.
        res = ((res & 0x7878787878787878) << 8) | (res & 0x78787878787878780);
        // Swap 8 bit chunks.
        res = ((res & 0x7f807f807f807f80) << 16) | (res & 0x7f807f807f807f8000);
        // Swap 16 bit chunks.
        res = ((res & 0x7fff80007fff8000) << 32) | (res & 0x7fff80007fff80000000);
        // Swap 32 bit chunks.
        res = ((res & 0x7fffffff80000000) << 64) | (res & 0x7fffffff8000000000000000);
        // Shift right the result.
        // Note that we combine two right shifts here:
        // 1. On each swap above we skip a right shift and get a left shifted result.
        //    Consequently, we need to right shift the final result by
        //    1 + 2 + 4 + 8 + 16 + 32 = 63.
        // 2. The step above computes the bit-reverse of a 64-bit input. If the goal is to
        //    bit-reverse only numberOfBits then the result needs to be right shifted by
        //    64 - numberOfBits.
        res = res >> (127 - number_of_bits);
        res
    }


    // Data of the function `verify_proof`
    // checkpoints
    const VP_CHECKPOINT1: u8 = 1;
    const VP_CHECKPOINT2: u8 = 2;
    const VP_CHECKPOINT3: u8 = 3;
    const VP_CHECKPOINT4: u8 = 4;
    const VP_CHECKPOINT5: u8 = 5;
    const VP_CHECKPOINT6: u8 = 6;
    const VP_CHECKPOINT7: u8 = 7;
    const VP_CHECKPOINT8: u8 = 8;

    struct VerifyProofCheckpoint has key, drop {
        inner: u8
    }

    struct CtxCache has key, drop {
        inner: vector<u256>
    }

    // Checkpoint 4 cache
    const CHECKPOINT4_ITERATION_LENGTH: u64 = 100;

    struct Checkpoint4Cache has key, drop {
        ptr: u64,
        first_invoking: bool
    }

    // Data of the function `verify_memory_page_facts`
    const VMPF_ITERATION_LENGTH: u256 = 120;

    struct VmpfIterationCache has key, drop {
        ptr: u256,
        first_invoking: bool
    }

    // Data of the function `oods_consistency_check`
    // checkpoints
    const OCC_CHECKPOINT1: u8 = 1;
    const OCC_CHECKPOINT2: u8 = 2;
    const OCC_CHECKPOINT3: u8 = 3;
    const OCC_CHECKPOINT4: u8 = 4;

    struct OccCheckpoint has key, drop {
        checkpoint: u8,
        first_invoking: bool
    }

    // Data of the function `compute_public_memory_prod`
    const CPMP_ITERATION_LENGTH: u64 = 120;

    struct CpmpPtr has key, drop {
        res: u256,
        ptr: u64,
        first_invoking: bool
    }

    // Data of the function `compute_public_memory_quotient`
    // checkpoints
    const CPMQ_CHECKPOINT1: u8 = 1;
    const CPMQ_CHECKPOINT2: u8 = 2;
    const CPMQ_CHECKPOINT3: u8 = 3;
    const CPMQ_CHECKPOINT4: u8 = 4;

    struct CpmqCheckpoint has key, drop {
        checkpoint: u8,
        first_invoking: bool
    }

    struct CacheCpmqCheckpoint1 has key, drop {
        denominator: u256
    }

    struct CacheCpmqCheckpoint3 has key, drop {
        numerator: u256
    }

    // Data of the function `compute_first_fri_layer`
    // checkpoints
    const CFFL_CHECKPOINT1: u8 = 1;
    const CFFL_CHECKPOINT2: u8 = 2;
    const CFFL_CHECKPOINT3: u8 = 3;
    
    struct CfflCheckpoint has key {
        inner: u8
    }
    
    // assertion code
    const INVALID_PROOF_PARAMS: u64 = 1;
    const LOG_BLOWUP_FACTOR_MUST_BE_AT_MOST_16: u64 = 2;
    const LOG_BLOWUP_FACTOR_MUST_BE_AT_LEAST_1: u64 = 3;
    const PROOF_OF_WORK_BITS_MUST_BE_AT_MOST_50: u64 = 4;
    const MINIMUM_PROOF_OF_WORK_BITS_NOT_SATISFIED: u64 = 5;
    const PROOFS_MAY_NOT_BE_PURELY_BASED_ON_POW: u64 = 6;
    const LOG_FRI_LAST_LAYER_DEG_BOUND_MUST_BE_AT_MOST_10: u64 = 7;
    const TOO_MANY_FRI_STEPS: u64 = 8;
    const NOT_ENOUGH_FRI_STEPS: u64 = 9;
    const NUMBER_OF_QUERIES_MUST_BE_AT_LEAST_ONE: u64 = 10;
    const TOO_MANY_QUERIES: u64 = 11;
    const PROOF_PARAMS_DO_NOT_SATISFY_SECURITY: u64 = 12;
    const ONLY_ETA0_IS_CURRENTLY_SUPPORTED: u64 = 13;
    const FRI_PARAMS_DO_NOT_MATCH_TRACE_LENGTH: u64 = 14;
    const MIN_SUPPORTED_FRI_STEP_SIZE_IS_2: u64 = 15;
    const MAX_SUPPORTED_FRI_STEP_SIZE_IS_4: u64 = 16;
    const PUBLIC_INPUT_IS_TOO_SHORT: u64 = 17;
    const NUMBER_OF_STEPS_IS_TOO_LARGE: u64 = 18;
    const RC_MIN_MUST_BE_LESS_THAN_OR_EQUAL_TO_RC_MAX: u64 = 19;
    const RC_MAX_OUT_OF_RANGE: u64 = 20;
    const LAYOUT_CODE_MISMATCH: u64 = 21;
    const INVALID_INITIAL_PC: u64 = 22;
    const INVALID_FINAL_PC: u64 = 23;
    const INVALID_NUMBER_OF_MEMORY_PAGES: u64 = 24;
    const TOO_MANY_PUBLIC_MEMORY_ENTRIES_IN_ONE_PAGE: u64 = 25;
    const PUBLIC_INPUT_LENGTH_MISMATCH: u64 = 26;
    const MEMORY_PAGE_FACT_NOT_REGISTERED: u64 = 27;
    const OVERFLOW_PROTECTION_FAILED: u64 = 28;
    const NUMBER_OF_VALUES_OF_PUBLIC_MEMORY_IS_TOO_LARGE: u64 = 29;
    const CLAIMED_COMPOSITION_DOES_NOT_MATCH_TRACE: u64 = 30;
    const TOO_MANY_COLUMNS: u64 = 31;
    const INVALID_FIELD_ELEMENT: u64 = 32;
    const WRONG_BYTES_LENGTH: u64 = 33;
}

#[test_only]
module verifier_addr::test_stark_verifier_7 {
    use std::vector::length;
    use aptos_std::debug::print;
    use verifier_addr::stark_verifier_7::init_data_type;

    #[test(signer = @test_signer)]
    fun test_init_verifier_params(signer: &signer) {
        // init_stark_verifier(signer, 96, 30);
        // let ctx = init_verifier_params(public_input_(), proof_params_());
        // assert!(ctx == ctx_(), 1);
        init_data_type(signer);
        print(&length(&public_input_()))
    }

    fun public_input_(): vector<u256> {
        vector[
            22u256,
            0,
            65535,
            42800643258479064999893963318903811951182475189843316,
            1,
            5,
            731,
            2266515,
            2266515,
            2275839,
            2275839,
            2313321,
            2374143,
            2473930,
            2898431,
            3739191,
            5519871,
            5592285,
            1,
            290341444919459839,
            316,
            1325,
            3738486017942147354074018955379605676380083248664771915059705441906271431260,
            2266520,
            13,
            17547433874568682364848743965628382726429958981359604444957274631418163566655,
            2266535,
            13,
            7749116299797804088782267083740692628522862646799994425166213362944845351795,
            2266550,
            31,
            87554665547788902652191211055552226292573802503575884354337098466019513989161,
            2266583,
            13,
            16423204365463446208451886498635606282964612473735287676559025469370460789388,
            2266598,
            13,
            97660122090897676532976515536327685597178575392752118881746790001570319873489,
            2266613,
            21,
            15965293420646717632864890657656682147622030860431407741801362099169557217709,
            2266636,
            13,
            77829889301625120538273005884313576598117954809598182291464062324272311851508,
            2266651,
            13,
            11778056442410921545249586642918560827771268787305038501308366172627797709355,
            2266666,
            13,
            18364277121799742307672296674198834436703612301135900164520182929833498436739,
            2266681,
            13,
            21735447457064466173789256559509900293066787207553930468556444172373225281461,
            2266696,
            13,
            22523711334875090006439121766082922691595913204702125885692194992296419047826,
            2266711,
            13,
            83624106647297961694100343609754693980591162537481165480406799232614728629864,
            2266726,
            18,
            12486902211487510464343379655038142220436001470959615777475506675720761639871,
            2266746,
            13,
            20368200422104918220519150850184338115948143567048556895605142949756303382836,
            2266761,
            21,
            113854322277280286702186143613114340856969339550867337189315522099690118807628,
            2266784,
            13,
            31870597192008675990789996732130802915269720314152591261375941749709282920042,
            2266799,
            29,
            78382287317814472613239610149858545458010980340439738349488415526720261028545,
            2266830,
            384,
            9604218879067086476450192001546736143005731221600403399601510368417734636675,
            2267216,
            13,
            108197861132473313249010672006165508360866429075008462995213606270743445529443,
            2267231,
            13,
            66455774903168871171775447035719286712818684437227643871113694350175053599259,
            2267246,
            13,
            113089238278051186666329417209709318846936850786968743510017013481312171697258,
            2267261,
            13,
            67300239502169829984827395910149621987908120813874487937762978716235919128774,
            2267276,
            13,
            1319479363738867415310423366591370060174080372736046678750889716055912908869,
            2267291,
            13,
            50341686347463363975540907088317675866497103246666224706270212848355710053249,
            2267306,
            23,
            53385008667300485454352502235295700900313479021440159070204738203587876213815,
            2267331,
            13,
            47952981617598173204861359590160150882829120273191290014690019036497533355420,
            2267346,
            13,
            29519829429459552726331414080679705228047802739300994349547441016589236612958,
            2267361,
            13,
            4062667582948901981125064593866651847854399257395388836917295081179780010419,
            2267376,
            13,
            77552672658804527886622009595958277477338765289709038331221320726845995570224,
            2267391,
            370,
            87176638373429881563771645808207478092744372113238562113310463087785928676223,
            2267763,
            141,
            48064734020692671281681583947507149069905407499460852865177568341956674539391,
            2267904,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2267908,
            29,
            55020604747999751144766410071495837706391593304816802067600654139344476472302,
            2267939,
            29,
            38069407101166142589186488872691045214678860535725877323685482716309627272853,
            2267968,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2267972,
            13,
            44970084016831525541570776319152382257812079308583480796258135444484613981097,
            2267987,
            13,
            59603688867327028912595477755667343640430387301033490625265021919473611285520,
            2268002,
            21,
            112822960997405385250880865172546852662002745233424121099627244148901664382691,
            2268025,
            21,
            59628663938955621477784530808098673749845708264989579564619840394146696195260,
            2268048,
            13,
            17949273684339190294337900335309548739518897736989935008854829935178883751151,
            2268063,
            13,
            59090163270784393647497955222477046385041081282189003095794136150866230106173,
            2268078,
            13,
            49994288545631855436389578568567951181692086323179687017564411955572764850227,
            2268093,
            13,
            107755674082549605593455841646298997364609393127720581007320654455074001117114,
            2268108,
            13,
            53375535463579479009722567978732540420534839369019031140437462362571150012504,
            2268123,
            13,
            78178855365907429141169985361665480054207121267550887149338497257672211414532,
            2268138,
            13,
            46952556118908061533885795492790521753380889087260133576836576454813203516133,
            2268153,
            25,
            65505401367081327828932196628708715608735259056446170881570707614857075765429,
            2268180,
            13,
            66026361140859557541008850650466709875963212091612367158332178247107839518916,
            2268195,
            13,
            107829965356734395629855344211653560164573781413614607235772505599388207683848,
            2268210,
            13,
            47788005912333847330029912808563183895034631365400945745335507500311468346122,
            2268225,
            13,
            67097593983398640255167993896281494296807532312522342136901066105309779400809,
            2268240,
            13,
            66420507535419775976095280336359771823704045946479200814130315195703991328481,
            2268255,
            13,
            16101592567572099802258242269752106492460917275051456854102468577257503200525,
            2268270,
            13,
            8216914045633627635302660948386070992614456000204188124777614757064223091991,
            2268285,
            32,
            8249043304272555286383677937581365286849505296414458278799771542306309708354,
            2268319,
            31,
            14448283915147148090721060764299709837384068077654347287803008805520651873069,
            2268352,
            13,
            63620408241887794436708548307677866819562529926322073154982043971282555238076,
            2268367,
            13,
            40775361516480445645928872142071563084052839066150511676312787604993166027176,
            2268382,
            71,
            81428569813509542871211713748051351028867604297100493265050464642642328771229,
            2268455,
            25,
            88754086850511571257566892242699603077236826049312766737019092497484382382654,
            2268482,
            369,
            23654506707858200740506342004476864923902189622928950125779369066913145575662,
            2268853,
            13,
            96208148133995054905102420138122451420246586398511887337527574742531702470486,
            2268868,
            13,
            113580635962155504213985295208618498406180863096226059830568771794861181155798,
            2268883,
            13,
            15131752458185413449864157052139300410518252387356086659475433480661225043965,
            2268898,
            52,
            23292176179045539781094344551380243030756494413337668722244515255672054637467,
            2268950,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2268954,
            13,
            57153597448868926539855853259434541268978238846106320683353613318997514641125,
            2268969,
            21,
            101934626186394811002215974973967070319928197907754643548771079104417124673451,
            2268992,
            13,
            90273910915094742302208054546284628459686672579135471102191495914048843751896,
            2269007,
            15,
            10517329873685287928347917452554263006484835250651675277402969825090693879091,
            2269022,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2269026,
            13,
            32026386706763484826260746686598106487693280486851488027571476178437691385322,
            2269041,
            13,
            23773726363363889882063090755216308036304380843201433744947905016392994838657,
            2269056,
            13,
            41030362719810092683936274861450690350552465887466419308301904892257547233654,
            2269071,
            23,
            43941438731016487879152402389159872199639416703899443666740619174832009465853,
            2269096,
            32,
            64262148212514546925252206696334335492506587371076276693676160603339172930660,
            2269130,
            13,
            68341019389705627980778368317494788023562860879287409751129335977589469383175,
            2269145,
            13,
            105387488867899480423644778850592712967009719216306825976651608464991419450128,
            2269160,
            33,
            13591654946129562002126815849765202989478154191387850999585354603681987556608,
            2269195,
            13,
            34270444613361640342413800364934734339012567552276261799984462745479619954700,
            2269210,
            15,
            41505602055864495605599765308553890615017909984116535819894217270687541833396,
            2269225,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2269229,
            13,
            3769287855047212670746572370221712130308489579424507215803811578866267898712,
            2269244,
            13,
            31370787985741923543987162524256894942054258596652034598712511104865600444974,
            2269259,
            32,
            34630032254591326189593478112278114576012885618625550621676339357910707072768,
            2269293,
            185,
            83385977172841354803010250811967014891455960772752491520365105313848269196944,
            2269478,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2269482,
            47,
            40040710529486463528160309423888679749598092331568072034784758397540908659408,
            2269531,
            13,
            71612927899092120281646356542123617181923889912794580826450400800692036713006,
            2269546,
            13,
            44012142378419477750713609346157284295753679742209888754526411900039665857693,
            2269561,
            13,
            101843670418999456948427896406373492501821426286997839388750200399233238851189,
            2269576,
            13,
            28069551324574210136584999023693559816928302893113954505255164861429813301816,
            2269591,
            13,
            60175915174506209947472820473705896360935259759680169086237455133563322456952,
            2269606,
            13,
            41096248539080902012335908903629976797268443829389275819032147119815537030757,
            2269621,
            13,
            110172376562109234563576542816780235176526300459897105622376991879209519467060,
            2269636,
            13,
            69579800812617228639975727002282320280970416517447717937145151344094549941734,
            2269651,
            13,
            62386842416018343607951302144487056964043593374773699385206155027294300711440,
            2269666,
            43,
            20871429405776545914229403370773660140457373936402646322219872837579579821238,
            2269711,
            18,
            81863837939287035754254393824982882478413491085191273481277469436776945463741,
            2269729,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2269733,
            13,
            33524573947235248159031667742931922584539051986897345494862764207129288050319,
            2269748,
            13,
            69521000597239388942372657320674767194907555617754681109956726791473658443605,
            2269763,
            23,
            19333004966186931025290210878917055376746563238947430820528204421600490397764,
            2269788,
            33,
            114538966562508480487306343703514606823959763866639996944378894505183253199316,
            2269821,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2269825,
            13,
            23236918250172311602781477328388532201735037001805541327865365168585411214842,
            2269840,
            13,
            105851611282041282513707883601256324522689411261384600746651542387186342808480,
            2269855,
            21,
            38197667859649411000933830685010063810574316966869325032581897279942887585954,
            2269878,
            15,
            35286812457174555875797358524458990887912628413423846628850954885701346229990,
            2269893,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2269897,
            13,
            9512427045245182242115231663553009124511054318334034076587958558290302487891,
            2269912,
            23,
            1865492192868670323762985258715873222797206408856588641103318564553555534330,
            2269937,
            61,
            66131895278688795224924961547421010783264442512377881130698816194287616015304,
            2270000,
            396,
            107740934040042529506042050940342987633499028376421113701731846542377195833346,
            2270398,
            13,
            1409894499338718311294081048510373269919784393236879434635482247077277969566,
            2270413,
            13,
            27737204604813478263586254532546870980777853392293252569614338867416992810044,
            2270428,
            13,
            79832665129243348758748415009326940971010959505579980076313438578999760992399,
            2270443,
            13,
            102478941373693375549956812878110788122021892505473864300770875588150313734259,
            2270458,
            13,
            102012951842710597862104186156947376854037776965882991185148952165890002586085,
            2270473,
            13,
            76417106370236909197698632830251002752640107513140805673821788821848914531605,
            2270488,
            13,
            22435116408947348327245372133214018721152854778436903019268345353280913011456,
            2270503,
            13,
            105705119183636876264718310030378962194781350046315627498090284580495264370027,
            2270518,
            13,
            102766566643346153656602938271234186934905554932621998168803365409410211928359,
            2270533,
            13,
            9121952504245628783421233306095476353441981972713852108173642399482807715362,
            2270548,
            27,
            73962617910028455031750644930484898213642860638335615505960304395715369766787,
            2270575,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2270579,
            13,
            8831422292954978039820857396332222926832474211950777587716620825000083972572,
            2270594,
            13,
            40572365482736356093128943044181419120902273798347181151252205407631489241195,
            2270609,
            23,
            89250748423108410433426805530288370741296549548481331392390410131674645550761,
            2270634,
            24,
            81549167029416228276298291834761499942693222494464278511836160118839531888493,
            2270658,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2270662,
            13,
            50617150871833309590669450601767195305257359442043990275346253785921825685523,
            2270677,
            13,
            33430900398633986517281079257144137252508017497740903641363497653974577820811,
            2270692,
            15,
            50230332337520685819185379138149452056832273984668817287076054372737095794497,
            2270707,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2270711,
            13,
            26060925092766365537594808786411019471359171000744630748109876443668095574495,
            2270726,
            72,
            59459343261488222241516647373960842913983844065521095207405120949305175621737,
            2270800,
            23,
            108755407944954751424523955182999093272333942296063567678673195334683898056168,
            2270825,
            13,
            22018963762857268261670859061450709880770233577299661065335739506114948260887,
            2270840,
            13,
            27410879735734622901935339387522081912852630802358973783531965565496342592994,
            2270855,
            13,
            115051908501650433486349656472921125208288198903694481169626026310325357961367,
            2270870,
            13,
            60740395827095520779518889177055275450153884591539634076336325020431564259180,
            2270885,
            13,
            107608543370604485897185172608940593045601889266102192628086906595657461680354,
            2270900,
            13,
            54301232650620405282150921550704173106940321772844823253577771145810237274572,
            2270915,
            23,
            71001026239654102627783021045192028004378429518001617729030071341791993700678,
            2270940,
            13,
            39710331032306793130081840425783792614983779976172544992206655537207962881684,
            2270955,
            368,
            86228116464310301360748609286259135771787178854372648849330443378803188365171,
            2271325,
            13,
            90934068311573248722739105736697871875321060266296858867995899289609929170760,
            2271340,
            13,
            60305257785916118467838148903191765734542105780958274452012125448613510492887,
            2271355,
            13,
            51401161016891800236336681251420895859620859407315871435682395575461292037667,
            2271370,
            13,
            114177592566358431801118905052278585803747165624180204340602079186159186337997,
            2271385,
            13,
            35661633721065798164415647656008442441357723199639894901776828568429795199717,
            2271400,
            13,
            82349699136419260729230443597024633782650419044899208188595644723534136245953,
            2271415,
            23,
            69025101069346951954891138790729467561911682541231331355337876983949834338135,
            2271440,
            13,
            43406849504705766813672330637076814332626783947908226980978492522256322052223,
            2271455,
            13,
            15440490610290693769667909648934087358334865811320491223180387657859650330565,
            2271470,
            13,
            101964713174837234807848138856280220588136366074194237516902136033462236404731,
            2271485,
            13,
            105997758417939381780729164461854539956541824706340289421408142190097348892967,
            2271500,
            13,
            28293664940003478151276898044436426309475362961994627383454087843703219197093,
            2271515,
            13,
            81086627291954452130349548412898875706733522636406240105554011765340971112443,
            2271530,
            23,
            72640942761827334315861408342746491750707228201961321011312224914716610059208,
            2271555,
            381,
            33840524889259858333414022007684051439677150456073715913529506418358116235769,
            2271938,
            13,
            105946227983176322453887267764053751256522172809891671893946446751718853485449,
            2271953,
            13,
            22595354440732576425392828562541577548198859376250894026241317624038577550319,
            2271968,
            13,
            20735080705311195214497435069522671791599589004785685625907346304577792655026,
            2271983,
            13,
            3717365762107344560916051106621169961692354235759971629760655354282473666703,
            2271998,
            13,
            68683489074338144235560823860661221782129418929397392812363463286742922180268,
            2272013,
            13,
            45258559815785269488947491982280695712012831886878261760888502847292198939068,
            2272028,
            13,
            49068331313789774651664260109136845019112371397057062280767095425530508166733,
            2272043,
            15,
            42866694272843561216655084552054463702253369532658098965305760590461982875458,
            2272058,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2272062,
            23,
            13452234504386868024300380086452624521173045180735000414201203996374969250888,
            2272087,
            21,
            2516882355477689653480682651720422432222384971628206685919721968375084071062,
            2272110,
            13,
            67717854541806545879146558135668960658860285830505493770541267993000707799711,
            2272125,
            21,
            3180885961777905706120335813868067672297872833147344016828642602716765871269,
            2272148,
            13,
            105307210864548887535573007835558722068888893367639633587387049012908019345652,
            2272163,
            13,
            12768134566470995582764057350320150021729292616888699505893840628128007306324,
            2272178,
            15,
            61703941465235564090047569048521242612613733115950745635386679977961219640467,
            2272193,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2272197,
            13,
            352304168337812887967785102338327453972413431901628724773838900526380570280,
            2272212,
            13,
            21541427396646134104803824239554169320998824022482996201192644633993070817844,
            2272227,
            13,
            108712839909786098570999032775030610237052542651863731737221776493023558897377,
            2272242,
            13,
            30842377896707169066580849364607582142751707568073630837035141746986942573021,
            2272257,
            36,
            101631606894952747928372667614118201532579869183378626517739816407383121950103,
            2272293,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2272297,
            13,
            45992099988025865683067625033591460925902090396260789334126711471367000425997,
            2272312,
            18,
            47526585918989854830900804799384412735007966826051680446979175520559887998269,
            2272330,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2272334,
            155,
            92238284230275447675689003164036098486344446477384991430151443302770981428325,
            2272489,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2272493,
            13,
            75688085463112208987088477207381799661566839388531332561869644310083419771368,
            2272508,
            13,
            38163259503195403483842107750655621268609759837719564316535701393517188341763,
            2272523,
            13,
            51766413065712307825083095337541457781748304925116889398730811632539318687662,
            2272538,
            13,
            112551939080843303612511427122817842705674423188167498554341087120877783058051,
            2272553,
            13,
            105193811535542580637141816563277261137448564736345686805730683730741937888195,
            2272568,
            33,
            51185566474189321079313199641437131414920591732012712663071165309052890118227,
            2272603,
            13,
            76805679156363176957868890394140638133137778067104912738980399695263567714328,
            2272618,
            39,
            14093333600073593206250191256484550401514721317905141272317990813291797983934,
            2272659,
            13,
            90663817623605477526523143748596942518048077680062674853633824120631801114734,
            2272674,
            13,
            92378620427750605893727407350914891874123798377571678369049494973984675668282,
            2272689,
            13,
            81462533139870796175988831623605870310507911484871454579175552094369268197623,
            2272704,
            23,
            94831642400111668134733198591158936503505226287851557955034619473829492960395,
            2272729,
            23,
            15715011832978093245173673088951410696365572592972865536997607200576513473583,
            2272754,
            13,
            37959794424869967671951520859647034208937186725511979995416396185083474107343,
            2272769,
            364,
            73570037145074924376207425203414313098792984669962494219074542839904305812896,
            2273135,
            21,
            71912149988373534823333988897472062516110733476742624890118857409811302951862,
            2273158,
            13,
            92969431474449877997398271052720817776072602622303207897078411022490784600039,
            2273173,
            13,
            48223322899725661350216931143894854270789074290575038068815920112319896331367,
            2273188,
            13,
            24239842023625090742969717664583781733191293590703146593722243108162882505419,
            2273203,
            21,
            33797590529267400952470162676299880380103524729131606187233717840791323063611,
            2273226,
            13,
            85611908204867317363822548712877315799126060413495968584985583396976699439462,
            2273241,
            13,
            78055971213963855639433611741110131187637742103309386310586422272275843159653,
            2273256,
            13,
            44190694051865475145065411445671264701129711527715868275063855205720681168689,
            2273271,
            13,
            63109263541026814562695058501020054865604595058251352380318982771988237069808,
            2273286,
            13,
            85655342575202947367370764520717270539203408476043033343200674408269517419482,
            2273301,
            13,
            29330667365919874889580466549096210989402190893561358829896558417040601140318,
            2273316,
            15,
            92933721621340465162882999919496681751235238531175328260883889634561014604041,
            2273331,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2273335,
            15,
            75157105369245749776371848651135377732836746923748035041854729254077404496747,
            2273350,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2273354,
            13,
            99115721182987437908544511893189109380896577022455105558435746207832874036961,
            2273369,
            13,
            55181072994394712004725464108442580865822629026721778724207251703051165063461,
            2273384,
            13,
            49733592482627140815925535804823062589660936915003869798979654868429388357071,
            2273399,
            13,
            83879074632355062725941412228032871981899178275860482478822445576264155966325,
            2273414,
            23,
            87026141828509190413825465867999132191037286739113986633690485453098163927336,
            2273439,
            13,
            86311137709250797179230410727173416152320919703493094786908172589923629237476,
            2273454,
            27,
            91588853178519344831378494523223543948574728059102328366124983294203037985685,
            2273481,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2273485,
            13,
            59593668697032315490297292319850195112423621694974593388044049940624855417869,
            2273500,
            13,
            48206249183093295241511205280607891755818981062481119386123186268834564027115,
            2273515,
            13,
            103884090596045256649230952255995802297388154076335965769462190868831845158956,
            2273530,
            15,
            55071995515677942005477831570690270849578796434844850529546813104988971533660,
            2273545,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2273549,
            22,
            61677704043528762498668908741230755680401772683700568567609217935818023782514,
            2273573,
            13,
            88665894235731545806950637121015068548450374559749572699273666264185932257793,
            2273588,
            13,
            42342702638299191831072664123033132552756854514857603184894032046371883700603,
            2273603,
            13,
            42616428035343920816127850359824775019056586820051892019804076622058170589491,
            2273618,
            60,
            49660383232157800684891069272942641642755493180329243823499709362831363963390,
            2273680,
            13,
            82553507209180094877025148987428519469606410378324633698936423414710482732585,
            2273695,
            13,
            89765262767149696096031027169709122177426545865308614656506108435620404257975,
            2273710,
            13,
            44117247516472028516514196015322826197928068047992230749704026425558477644612,
            2273725,
            13,
            81455047520890812473163880114381906923195178177981741856936829261230035339568,
            2273740,
            13,
            91029927454867114709944443207985795767635544697527735492257867603973629254603,
            2273755,
            13,
            64634409512883308393731056542786258701069863267512254943889811204553538330140,
            2273770,
            13,
            8916470997323035504684138105114930962163923347346480321385750229806805588686,
            2273785,
            13,
            115390033550027412757993675183284780322511226856183920035626476334524069887581,
            2273800,
            13,
            89414587084100759176733110910823765359298720486127967829372126690063379493255,
            2273815,
            13,
            94101559349895398750339966655654135139453588861464609548572231592265122222669,
            2273830,
            13,
            71895358833990320556028528261998029462372620142058487339736001137062228821962,
            2273845,
            31,
            64905071884767670368638853556324805624646874704147066334927950462141728677715,
            2273878,
            21,
            111189087266794143158150421864191886535037543331909665606147691508907076715207,
            2273901,
            13,
            552683344713332275705658562291580644656610294627976405720649299230770672476,
            2273916,
            13,
            5419504063454618218843523901623816760002091898232477461287622052497744154633,
            2273931,
            23,
            36357252912472128365648121532283241506260417763224945559430262131343665082625,
            2273956,
            13,
            52728844592367855688730073033225390296963652590724170054648368711008652429253,
            2273971,
            15,
            6513439748644590633698485335307501633364564643196625204634754513655932171130,
            2273986,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2273990,
            13,
            53664486155040811623892370859894368461765217414215090858245043609980714971614,
            2274005,
            13,
            80750356051770599757143477317538840431479750414049020139450031095413315493420,
            2274020,
            13,
            44170059243939309615583402817213692517473429337866964922656866918317407644883,
            2274035,
            13,
            86761180335930791761296312146191897465700311051952904315972026105382853633530,
            2274050,
            13,
            3148257962744337082464638354611990422327497099896932111625811098525137986186,
            2274065,
            13,
            41238638637924119446298556899127714478382605267193578761734383482787892434952,
            2274080,
            13,
            3827914826917535469988788169354447227672970869086890122867846023570859221257,
            2274095,
            366,
            64713531846529596169973662360823053840661115927619674642606872754470697712978,
            2274463,
            13,
            34073704140565111185233666845273346453543063974668778726888441414152868976177,
            2274478,
            42,
            9741801428700007924023553406832493590361244759989138329835076204236698573426,
            2274520,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2274524,
            13,
            33157678654524600432967932881325894506693514427078003676872947920205383816131,
            2274539,
            13,
            82274285243027927135163362250458313620077337412481259315033696816695071962966,
            2274554,
            13,
            61905219055703587310447922381444603538224067455052180693739170161646317344206,
            2274569,
            13,
            109295591946199220713406463851822499518788146799399441146461127612624918109264,
            2274584,
            13,
            9679321425811673395243733849728728609910614284480804106377304172420445162841,
            2274599,
            15,
            77400580104748839600557012666185292075103759369095124524925691511007992983385,
            2274614,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2274618,
            13,
            17096237184588200685930185547059017625148073597210419901114122531607911043328,
            2274633,
            13,
            38468640427359885474552077323549074312308474788673662403318883371618841119343,
            2274648,
            13,
            97300780751369013566574705493094200434690844456167134140578862101840669057677,
            2274663,
            13,
            54636958088154111396724725812747377193726067759113012872115294394596445183853,
            2274678,
            21,
            65098396101912539352142601547637724172446574104574279088308808851886818878174,
            2274701,
            13,
            109802353012223215534633344130642902994307831223840801331799072199894294698292,
            2274716,
            13,
            2523700439463386419856910650254922830347173429208128775446580318548709984247,
            2274731,
            13,
            3948853393212046138164091772190649816773588195037970838604236455322659667814,
            2274746,
            13,
            99701624586582659967015121878716402265831949118220456023839676146604265683365,
            2274761,
            13,
            76391199978499573397453547496444186813855042569132542395238662836767782642444,
            2274776,
            13,
            53098026581408757586483226758389788785283864033165077314484568808161625551654,
            2274791,
            21,
            31749371499604142890178874833447706424161534124574105802604183989805254590196,
            2274814,
            13,
            112164381360247602594933306593823699138443817899283537992935931075813827047855,
            2274829,
            13,
            75636609247336213688178201473074569997497991430252526973306837976687551786686,
            2274844,
            13,
            37473963826752474771999309524081310447125644757540982160355720460970669753800,
            2274859,
            225,
            94877924725905917245976254298586867589924113738102489802615448399020691187081,
            2275084,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2275088,
            13,
            21424322251915011760457304058352897466514553363086817736093030455333485033287,
            2275103,
            15,
            35304760090550459700485563552543791950577403744278669997998979886418858759901,
            2275118,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2275122,
            31,
            76690686068159581513339381992667303049520214491463793263413097445363180516689,
            2275153,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2275157,
            13,
            38071302992902672670217620456140697088438581820198908983897690272977669005669,
            2275172,
            21,
            74062772662687791403197544986696686370932855968369635839156922067251311544383,
            2275195,
            13,
            46700405563823858749014678713554494319834011121907170089010399099756454317278,
            2275210,
            13,
            8360197310869401138898747984436519789425270006761454573364425154425397294061,
            2275225,
            13,
            37345737471962928321646795650221154936533218694709409582188888245924105284562,
            2275240,
            13,
            76329176045853327397827066926153425233263539377240458185231327522368659884668,
            2275255,
            13,
            51165095216412898665266098383199195993466108420832609966696157533973658887512,
            2275270,
            39,
            8694770951800705147288602006997578261088660472545167497867993454986774215525,
            2275311,
            15,
            2232998850732757996026835613652542242994469471222165064133301466852118947076,
            2275326,
            2,
            78338746147236970124700731725183845421594913511827187288591969170390706184117,
            2275330,
            13,
            56959477025172224455209639691228449581961339654408633081171384561252864362634,
            2275345,
            13,
            10893688972514420983117987293954356290386359441336972240383861536511860934194,
            2275360,
            399,
            53274788599268239546529822773925978916092142455549074124681282311879153182890,
            2275761,
            13,
            74299798615312998618478698245393781612899652464720274055652198245543220767597,
            2275776,
            13,
            92382115381821907922215673753072855145247673959821648259633950587471687917866,
            2275791,
            18,
            30172024673412102830121284456785764211979110438579097758830557403781776009323,
            2275811,
            13,
            36936527765950551676412164956756148227556267624811854840240040265229057689385,
            2275826,
            13,
            68419931065524346375303390552415953520841885773146565506619908716585705071710,
            861188609419564084015083556068676459166478778038881359457809452673842858492,
            142169183933652432380336624393897576851073070152193201252544990504594771245,
            3469611596332664218008507347870182155450945120872578171781621929919427297542,
            1120783225105500472886960707578856680524451699826408436808377624124459660804,
            3109412906550742373552260327593879584368267517865428559029589769160129002541,
            3243015875726958762897512282413425159040780330160415570645061436015993367756,
            2818177121361950092924800583196987650373841278319041492446377342321998652588,
            3026764980178574262222400636234638800181176342699805475714570982070282949979,
            550258153495008696661163036876812516525820967976066034994164769862516405820,
            416230735957070076441464414259160370865161595055510852601185576999032668223,
            363396650917283632181085178556077467549785065665433532524390812312011986350,
            3571297215599978199753087183833552560212724085727624994174662358904076635445,
            3202180765366681681299897553177352596039525911979182989539709446744568064417,
            2816977406181882372518626780849235479682916369335124865385603133614143752342,
            406592581932948285871592003286338979441279378428577342904106294745242755237,
            2383117637623135039657023767738790009854472901781671216340466928219542250961,
            478255279029967512224971320973143919374743701172368175727298367018241621807,
            2182585426434601707205492756477582277326526101185378732600770356004041810515,
            1222019694889770534963155149230951568090687448161383130526209150939783559152,
            2680780664537925978125503409174749238058535341332208959653559871549377030307,
            374337815963302084233382772039623608873075796940464245403650215830862222434,
            1494346327877591323134473742310434385695875446731862588284394068263255564212,
            642432568764147748591929734504195578406494764698542287643097285236249754744,
            1716868821333285070508982056691099191130906481275434356227562814747464613333,
            1251883991644952235549668171896829896820163225596644480680205788613431884636,
            1893207860042646798515101002703647088433427160068190981566349510553351972841,
            1146623148113124044615500954975749825786565292091391956725728380527171218948,
            810887733765759682831659580200238018996898940356558894659319201168420184361,
            1127103456941127679640348313742637629159290150436921991829022438606530256101,
            1716777801251652087993637374734275602212701547772866985632857690318635391741,
            2123895083757203596615040341098116758704155874955022431693045405135268726534,
            196568201005436923907044163927471611657789320612771531029076553558749654538,
            2936843461702900664933903606184290556828093876295442494769142357697108416825,
            3404305683532880034723798159037615212818659428073237353220185452679443733461,
            3393082602495152474126365926446991301599644697703144825691831280418466896665,
            1698603095046899192614569727641305963107176354227883071899839179061051826667,
            581847092499259015759035618673554986643663921729966197258143128306509779030,
            6710941353317542144541092667280849039693782493897957976061487176689942739,
            3061208232461674415218178326756345732408525194477397555793889395944111543,
            78856689713439591325909351765867990632796120058252883496361430249241332229,
            2511691852597988372209628188276609157336876551967975615350141341028099961461,
            1736355849000948534762651901635784302315550284057718769860747556699991694992,
            1068766622234613034208947310823919391697612574820827082976322734521167672963,
            244963516346766472510084835312603963239931928314614553570509095465528521648,
            2180733676293685867021179332443928495123972617804499355642274335091279358424,
            542431924236813677186724418323781046190424908329918861145840794400883874426,
            2551865283700752159237246162547864255771850941426743041352579017023618739545,
            310468010165055573926005567764274404782628189118021060330211550709104940361,
            140713772188804039847396337009134767591052110641975861816054621361000993173,
            2525226834592916959442393115378999183741656091501611133029330186192942843001,
            3212375519952365594243790907169599319681444370255987881456960371115719544622,
            567216303243442533194491670074381853118278735053887913407759255942312126322,
            1149185159326395029688630904925131469865638676476950027814142188273950180807,
            821820633082175265529194850164923651608617033162160031925347151019959101338,
            2935637088003399861563444809734099112949430299124865999374825434781861830620,
            1296947871509179871850043775278632097843685580675185198753771026885640727913,
            1573379742107982990727353922328000041826221372272014138568549290151945866991,
            394263145194521198352953229125913130988676607507566550397597440847448331386,
            437636362495576215040869956166471235864907721399533097668519285634741048918,
            2132677312674762857700150415399458886863108249730954652237929114978270111666,
            1642775369794069196479402911807153843567293618805455393017044512589422690251,
            942426450007951984392192518489622693591676006189251124100410682940938152006,
            1827907891968373889853027127372552236278229476140088058599427575974162229298,
            3354654977748220898199961468885812250363595669385088829787437394585961528317,
            2414253707697157190073454073585060616611824585124165552440404689163179888552,
            1650923232610209048646048765331314451833213723963088038196918339998167602887,
            113397139624633067633156422392410986513051598787077295869474052017943647167,
            609800328691744828410932737655983509359953128502675482761115364792378307459,
            243470528834137630788812617229740872592160129672441417060836905815720263878,
            2812364936821307249109539801075390289287077005652649771139659641438528529807,
            1692248309389430937135851295194988032115171677092177489452765802698504239092,
            1434253818636229821546897896352855897794349797959770470121327018154284149800,
            2010682451246294606734765618876503210280606839741293277430270051582816002888,
            1221576437511647981962606632093295582017856636222427289286502790227498576113,
            630768165082481412967237324400121001656500607983340003935478666043973159373,
            804550778255486359721534448038497007139100824549572392219025451401366654571,
            2509405422579278993467464802987442883923997756314350093904754698655272281435,
            230322511138199514444432916410872573354392476025877843612257669508718156168,
            434096614508797479463291690518814504168086788605958962461649211197925570692,
            1501811813258361604071078006468632491988688644702953825498108954920519520008,
            2882982445519693408857052804061410678843841563008654228812807663226439561752,
            518869548748741950356062444028433245632475224810625612452721570315254285154,
            2595229702210972170795870914076768975618309054211788285044916702359112663819,
            2789475747320341346714869090990098730825471290243867544939257356032422631927,
            3021423904136100399420564756125538866649443384218345759132762767488927121901,
            3470072539146028737697831059922285349625921745686943456098631834736538513230,
            296832114912645368383858205207698130752073611255689118024692618517239185691,
            2562673875044080168939281665245533457996357295390300507103545024746030199615,
            3572176640836192239415456157280369916561273295658442093353040206706054951045,
            2848158501354991175021646799538038067563488282479904337827371395065278495157,
            102950434812874625402097083157182824861858194414063711174166419600553014181,
            1486323433493324402524888070458829882551243518422048250698374833559089260820,
            3208814801214087779688248916776721010687354077056081723931202672773878888941,
            2791567775849532297181476147696583719220230115011530058335644680117172080123,
            2235032008321774486325763532722701935219503936929081481682516227864367568407,
            592284390184751479985931280444783054260246785281850795678418559337548629734,
            390683870566096622968833817313745177669500468120625014424115528998810399779,
            3110691796330732484439006901404700651354694372816443484753104198586884384651,
            2444614225556616965677631614072556335440465173131661092997431343602506179484,
            2386506893371035367797010929557965767594569328487056274732669316394593214090,
            985718089293755807100092882514673037718074802425850404888611296905880615735,
            2365313498788565081614723939935710915555438624324335421229411011850664978462,
            2751609933031503045570717838909537391508339073565113369646306686587414634645,
            709418963298017268861363387108720702487826680412475179177944279942789785420,
            1907361680299590730675954600213074559334267264715916003088596512463555159119,
            3276563199475151306050538563091086553070251481701780021983716540769405628800,
            2972642734182643475394568567170312432365860846563755432529810857275455081499,
            425164320957393025437358755230063011507729374914138588988244646111343301823,
            3559707156732813327444472961623408136363819685273216405824028443892009501595,
            1627154000312260994431362465796048237259205663643677826240173075754304409976,
            978917089820616846266957253956461358728442465542876496262477450769874236376,
            346355236078510422426265313193171280607329136716705847231631007951611512698,
            316179610607211928380094103319534007928433340147182435947697504273517696615,
            2769473235676236857837052240478468885386654130708654974522904007205212947198,
            3273703505418872921921958863206735880229665688062763137606839754576556254611,
            3397427904428479816149340714385029180783089428338888559696506253876730991035,
            273396532134878085479258931108469249048622026285347764422481613061299287009,
            3565069599248317153452884864831279625076552078403945764722732447257084736088,
            3051414564343916789546958768334277845488736407740466494549809448179734756312,
            146750697919270022094432517700325927863514826787632368889893659520102633886,
            701885260756582344676704802559552925454358940676394084440223717957719805026,
            3428007399814096673254036282132435555425508460792469804428790971897733462163,
            914185908163270002133628759218993144034609160669792554111753479796045908313,
            524364526989685374907470318832186811437138954579977221453380381545518003033,
            1750700714903697708789718769124617152122195697123766484866944410868161971334,
            3287364644433022347116471045093230276031351368680760941129736750525087364830,
            2936398610182025614221594764943387849186676585211507577448788438498363417741,
            2353806544362665801840851354402231997471386461910141989996204623012395190376,
            1970141484971479373367527464449730593831874109262958782830543219487755255549,
            2393001591091529634760775424274881106661161797787191264296704494135080081377,
            2986606227259797722728369872804687298312253404217711972276159885672395255781,
            1895946695404106706947665326066559408208472176175703435285956512475957975543,
            1762356880044076889133856391675955384742710633798060761092994744648803681186,
            2376332339438019949540406736683284669215436558764141646234289425872250407714,
            1454976756676506843834296852446961771834473533454679073022417832857844894280,
            3548717794036887389548126075656668467057503009362313380257306181680385432581,
            965241988315227716419528016626328013623255115148047367598661016235428881472,
            364880470834340305656935466216573841491934395424487640998741517728075702652,
            2943398669550548190119897431262450183350472258799776593046925981023716929613,
            1448893857877452099597797155990678455277492286196553328412559163460378406221,
            1967481703172034532302291358157585036772430714320826461895477504253467787953,
            1325116985943935753797887026630510021999397105461424798371959688253221720342,
            2244622584920201730469439979893779654797150697429908221750550695114727636643,
            169421573908055569991679575627836830771160548739798159322462977095419291543,
            3095353763021763132566808185927306376406441767197745234247623641668407026312,
            1637340732530826646685902483519187879128294395545641724746044080108537320120,
            2294638457073272537380020652695805717451239479365560694926997691483900522709,
            1511366086802150243381238347922537557119352659921740484743601427611619799947,
            449428874493014357689284337690118381073239027368218521143371134362111769967,
            789682299596422945430069482574964319996794394882071176174058195011249469236,
            1084646862036354820409677700650699471864689661540217570329038731766739745205,
            78313880568815415355689662768930383042413140407006907408827845898228459940,
            356730105053361007857946113733839271044570452187014785515057265402328900429,
            234447037302476071968955219443368291760842844044519645486061976938132001423,
            2864422421311223063065427107781164541105240179822943356994920660882030317191,
            3220645513991770454830495359216702225738943217482751372374718117330072393321,
            35463109005973856944267069961705373986481909202559901998341156287817035506,
            952685587725119719066600350420803913063772382660689573594377138248265145726,
            752278194749177501493207399775926786061969166389064447953421142385745746087,
            2407348891063562262340882487501047709565400595257319006697201502933032707705,
            2463236356334325311251324372658459484411355441347448855372618996173032798473,
            2238179254064346364750464242776610666087953652801062085815768413875346396670,
            2802067085290870597935376309647815417818438178673940519081066667085272619330,
            2850335204360184195160225792945229847649912882393119826243003484121732080190,
            2470906391011157074848813029116011314321612957249816861338213895656078721145,
            2719124002389172942986323146717035094528812523569546471352767152752445448963,
            2231066334653800932432384670741847975321040198568834250178859804516478952571,
            2007545335999051836581333921231488913131319511359925956916354095167897717684,
            900055562911287563940939510518487860351444667545109216940154217563401258097,
            1785540044869890181738962662522696257112879586388985307150812891597163215144,
            3124957575510209676082035971129521944842511675997179494828222629358951850767,
            1043583892633525799267826910378029686330928692101917134824866886797301795924,
            2263814851238579887064085298532078321704597461027488639412693726621149012246,
            2178509090720733389462854288103494638309930461144580510806584326405126010226,
            3476125633826865086547635951618454636451132068386227939577574613425245274771,
            2259455312626966012641202975060147344918171603610064951002792385026849505887,
            305098219340569262959057929565627812075087945751515521330521567108712996106,
            2181302674128260211904148775356825065078036339592813338196413555567742282640,
            760001455233186214410668552162505595305171111386683529356117224501683716324,
            354000225697404900870934738845677552563144002135569724070635649184053068105,
            399746424720372601138503667692569207016506368222915655998246787269616563724,
            554038204075908614213636945466743711617750620995687318831362470141508850409,
            2414771763935056185515481317306102708097824540261617925672175647015584206638,
            436746505235351055124662611865059320594057790450596556503388308755572767601,
            1904032220774100883797625565070536195320261418193481759584640157146933348823,
            1585439592880267412357132988830450467294429187320155238313804981684103525304,
            2322641174567695905841903688399071847554604969491382105191878122061642897018,
            602944564805727049733612211740339068742069094439594360678132608096168984979,
            1208816517344716362456642101212950321451690046312184637589966461797871634826,
            1163748913684498566654974106370875829814517662801941919875773020671871445098,
            959518410079127715364330421000746491444338089403401618253019546230069982226,
            1675448091199059377170355681736783139463972613557485608633727295912202124848,
            1338461125234499703535531840041244336562142530765501780376258549778937873027,
            316789915981552919902716897538992166283892819738045579523670056652962656888,
            227955266610905211997334709807725722601588305008304119214249131018436323179,
            3381709505301028886192008685347707064024982525465981014487000424583724835047,
            451365838752100251651348038508237755501866172396086100168483912659280171734,
            1699997412555572818497550806208645583147667168198229131308436528170087009843,
            1465618277854710037531614366862433171917180117646667450615728687783059195833,
            381563838882669571134823269935860235474773812088273508885326290803258788424,
            3229122275928244842779644396992588751080818603473878466826718848082184225800,
            545387606087798164201110498513880963313000432429739921745585781892827620714,
            1208843514159268800663356459448970743482977805309097336706069141333928090126,
            3081663276582045868670977015875591027712331446847140634196640892417602385042,
            2291459491084933902041971665587536796091610110151808783511318573418867613127,
            2579771028898170514367854798207663546250691197248404002132166532149500283094,
            1777677994552518087374208961183375546840369438269188915624159194157076605380,
            422750871133655539833057120264959405545699402290245738869892411959027543551,
            492105516878092234407177319016174343957353422311138711424918171234565348986,
            1997967498961771614767095518974654922072224379745382308582938497617164686599,
            2304519903845617059363343833017194483031025019549672838855236609160222467365,
            2037374818970872092183633157023568593809011066091700956119322729105523014752,
            636153306624412577699280395923794564102367218463095219467229164563422015965,
            1328970312319045443911038331054000465835381334923381537091318109029345297339,
            1082674288667004001861638703121367025882049837457398286907762890864425846595,
            1543133337879949191106127951281603263108678831179403122875709477973408634234,
            1905375318811423424712042847444525894516840487996533927079091730368193537367,
            2651452647531898083081421692466881636074162574420661632112604368377034534873,
            3439901802466664016217956018725281603223385619234730842239164643504294950421,
            1443707951733771578508504623874685583067806190341928981999870884162098791029,
            19187465678615367566037675296367650342991516934889422972543839982073838308,
            3159344563370380045122321632113041403581194950834353484256587676167443492473,
            2535058710022946254196420242835973894386237482165006464554303013112854234308,
            2533404330028318305658063438235289234738359608848155038189233299207833719466,
            247140142821206022719057061597808887064858561859040104053312898890139793605,
            2515475874044065763107644236201597744513003147172500758001764952901826639170,
            1606182728937939913503915284073016241541643250868645854306908600376258372854,
            2704345336818944808163488926211595770342366650429972372904237916877697933890,
            3477809458907892176598592002154905922508759789345810763617372614186434974879,
            1353070205347713666351222548360697785337466176163739008008203029676702241524,
            2486995756785466441560055616765927902119197147714703044730735680601235679713,
            2676016451894542161844447636669903736203432411684743089788676004126118646443,
            2398895504226657284425306915928410731335098952170094535121452722159706389076,
            2239569092251890704279258123611921328787842267278251340748069435550379098577,
            2564330015787539727359700428301176920917076956693456991714848982708804202178,
            2892003336524304503545781706362133757665371608867888384068674117354306183774,
            1903443365794668136223397001294311391096789080380048487334795513758317962655,
            1845213504315532531064618105258155515949624940429872146623399030317040750435,
            1572059801848264322896597464575753794067171900058472370000596282550420744260,
            6799394487666764881370838689361824361195279802524726680585941417312696717,
            3497800705422481130531985782551507934273110167710848792228344934912929059019,
            2039451191166655550961667769072671543028963574744944718127079086545241018123,
            1381611106704896200142046525539531778217780460040076466592167235185869223523,
            2284837010474970189156574090064312845595668863684423526506998525924184226942,
            2853634638693036507172406509231762001156732526154224301004576497686958171868,
            115361031826947783113569769012489635432051339124039379484672548872245117930,
            2758790354713409492048663080335963047613400294462365114741343950961217313373,
            1418033626146774244049004361471532687712701849587621784444624364295939734899,
            795261739013585270722925143244842683567622304320596485343541001696326805409,
            975036563637557276193061080456064217187689026982310633242626933360145174991,
            1341234347475160929733826826982973681419938456208862179841623721756763932164,
            2451440061706370067883702393073771679325794890860375459204301869186893679177,
            1980903426900734452211358520187861857298342051445852122163213552218694767781,
            2122646717105342807380734101698698825216226769742570741618932185473597891170,
            1446307280231779270014643473172919715425826105025476020078029270709450229973,
            2432030101786106351553013637665908340613427075909648499685419582078117461484,
            240863509881275778911612615140219342484299816835792356948243889225183584998,
            2640497825282391992894113737542622435936690904631354045597848233846740849201,
            2957842877858826718564636415880893029786492524571917343268496216484818447454,
            1107572147290276598511260800766004476775289192116241104664234707914144984522,
            2929022399969869417658883061182255351433026349027286013934562886835852304805,
            2015954564455252396117910517671968966657174893041698274583685548761989465869,
            1047232942496770226131072810890531616863788923606886694941294090055331083297,
            2603165995764421054266947249597916356455949374049327099629110196805599690398,
            3178438030933303030296314146514319337448377010888123585240676253016848544924,
            1205036124728126013443049262820495401935766458617781953075081357123366373358,
            2859071470903123215941379173616378765201138164489966743921998749898784038260,
            495629542948242330406793497348190807517544509817118954026760747106255957843,
            2485968859119873746753392015904479404142774373000270829706421244984290479229,
            1109938482118692492079335381688463364857692544498421523494146971183482279398,
            3467942464842524535447312618038774425601167550490936041206414140186281753555,
            1697094864697730934551685518599365314517885702791790177430086252698604132625,
            1182522281365162709665580610038546439203976792105772581138557260282413339226,
            3602750309865719399531612416079109940347494444518133603094383879808771533878,
            726162074880131088492127584761223503250140802961950104590801495971920783324,
            2702711139218570391989114447285447716528174571087566071101996482939011620583,
            626918669206429324146316130074740537497468312715039913892232997294678254482,
            1173634494310687204996944643080826184642119267303996441290549321256778832310,
            2236028653577525715587031077010201854858546916782669302107650836994224782362,
            1406284570482579351411295180877941322895051278168578202813022614699763019785,
            3582714780704727321154655511991682460660998075499719278312356603861359304241,
            745754906463186079309916658460224416697349781327698908552453469527113060685,
            3108484778555354241102246010985306823216416374250779070070282861250540745099,
            1473460922097070038404187709358028262948785219277892941528673113402833339413,
            1933051635790941272072407214641350282116556087285958257450309399223640754222,
            2214807174148262592184483089027274211735313220687115252715771700415773617091,
            2685995859199255735908931833227218111970218952013763995869390604684794213360,
            2076946837981690174016457284072413597786014029624352945870476579904117265731,
            1411592527736154033597614685133849488044445632571645914052068241835307426655,
            9144483735458468465869145251434357970770374538461244223904262638033354716,
            3046516396230573134330664409547084681796979465193022532488546214762559533560,
            1269880941960518141121487029271360252283761921819689106740884103406851081193,
            167919751045922404470403821095219172832068346192445578106780616576745571952,
            490473839282914456610657040790181292799816203427869870111950927042219165359,
            1872638411447472972998138987397795894653212492570434463817786355427301454595,
            1093199526301354028293336415723351778627940319301628190945691077485785004611,
            1520936286506615456350667809541660910065200949163459142701762137750817293073,
            2790679280848501832107568777301296835751977659482291965921382563508358074274,
            675473802100924139654691630254806397954815518786006019121910233568774810804,
            2433396182903790226479160672278353366013121312445713562886171704351781750097,
            3260013426325476537931435767983411651603999651030224847777480176107129898714,
            1438148345761987421561558574735843211494706875722043389711513221682081904215,
            624154737344416215382306902613934981314994424462002321816823740770873052810,
            3364301920688053143551586712567939689977855041388070008552185235325830012062,
            2742607410429140355505366222756016022624428305509523620471032129641760085291,
            834240928133332873967572763960120336410554032725539634170571207479303927637,
            2693551910222869100808470627750063997576571726544082775086617714497310627108,
            2496672517668546063801485485101257007469619195579455116580093831122412148295,
            649544699826039218830738029380235641854027202144223059213775638936251543855,
            1290615906997290748208255360740731454289981570772397658879970024524871460003,
            632567800935459049740744098083221187821104059314788313978689913263252688789,
            2348437863095261407316568167910979152453013572595655851042083255625006891624,
            2481215200769461327932558612643415039838457081027256604870638707666156202850,
            57122707881135124965534576605147904075123889890659190204392608475906841103,
            2439476559823258978320004142231553407228843241022947558491415430683059942123,
            2561322912744615171166894324106518420053898199929890610436084715445762908107
        ]
    }

    fun proof_params_(): vector<u256> {
        vector[11, 6, 30, 6, 8, 0, 3, 3, 3, 3, 3, 3, 2]
    }

    fun ctx_(): vector<u256> {
        vector[
            4294967296,
            64,
            32,
            30,
            2274283650448687101415851970593711626031105468891204880928373412733104589202,
            14368,
            0,
            0,
            0,
            11,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            55456,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            64,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            67108864,
            65536,
            32768,
            731,
            1,
            2266515,
            5,
            0,
            0,
            0,
            0,
            1,
            0,
            65535,
            0,
            1,
            0,
            0,
            0,
            0,
            2089986280348253421170679821480865132823066470938446095505822317253594081284,
            1713931329540660377023406109199410414810705867260802078187082345529207694986,
            2275839,
            2374143,
            2898431,
            5519871,
            1740032260176861730069282301706899931803609121779848595553493302998775290819,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            22,
            10072,
            316
        ]
    }
}