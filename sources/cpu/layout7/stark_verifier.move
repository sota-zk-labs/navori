module verifier_addr::stark_verifier_7 {
    use std::signer::address_of;
    use std::vector::{append, borrow, length, slice};
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::math64::min;

    use cpu_addr::cpu_oods_7;
    use cpu_addr::layout_specific_7::{layout_specific_init, safe_div, prepare_for_oods_check};
    use cpu_addr::memory_access_utils_7::get_fri_step_sizes;
    use cpu_addr::public_memory_offsets_7::{get_offset_page_addr, get_offset_page_hash, get_offset_page_prod,
        get_offset_page_size, get_public_input_length
    };
    use lib_addr::bytes::{num_to_bytes_be, u256_from_bytes_be, vec_to_bytes_be};
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
        move_to(signer, VpCheckpoint {
            inner: VP_CHECKPOINT1
        });
        move_to(signer, CtxCache {
            inner: vector[]
        });
        move_to(signer, VmpfIterationCache {
            ptr: 0,
            first_invoking: true
        });
        move_to(signer, OccCheckpoint {
            inner: OCC_CHECKPOINT1
        });
        move_to(signer, CfflCheckpoint {
            inner: CFFL_CHECKPOINT1
        });
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
                fpow(eval_domain_generator, bit_reverse(query_idx, log_eval_domain_size))
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
    fun compute_first_fri_layer(
        signer: &signer,
        ctx: &mut vector<u256>,
        proof: &vector<u256>
    ): bool acquires CfflCheckpoint {
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
    ): bool acquires ConstructorConfig, VpCheckpoint, CtxCache, VmpfIterationCache, OccCheckpoint, CfflCheckpoint {
        let signer_addr = address_of(signer);
        let VpCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<VpCheckpoint>(signer_addr);
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

            *checkpoint = VP_CHECKPOINT3;
            return false
        };
        // emit LogGas(Initializations, gasleft());

        if (*checkpoint == VP_CHECKPOINT3) {
            // Read the answers to the Out of Domain Sampling.
            let lmm_oods_values = MM_OODS_VALUES;
            for (i in lmm_oods_values..(lmm_oods_values + N_OODS_VALUES)) {
                let tmp = read_field_element(ctx, proof, channel_ptr, true);
                set_el(ctx, i, tmp);
            };
            *checkpoint = VP_CHECKPOINT4;
            return false
        };

        // emit LogGas("Read OODS commitments", gasleft());
        if (*checkpoint == VP_CHECKPOINT4) {
            if (oods_consistency_check(signer, ctx, public_input)) {
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
                
                *checkpoint = VP_CHECKPOINT5;
            };
            return false
        };
        // emit LogGas("Send queries", gasleft());

        if (*checkpoint == VP_CHECKPOINT5) {
            if (compute_first_fri_layer(signer, ctx, proof)) {
                *checkpoint = VP_CHECKPOINT6;
            };
            // return false
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
    fun compute_public_memory_quotient(ctx: &mut vector<u256>, public_input: &vector<u256>): u256 {
        let n_values = *borrow(ctx, MM_N_PUBLIC_MEM_ENTRIES);
        let z = *borrow(ctx, MM_MEMORY__MULTI_COLUMN_PERM__PERM__INTERACTION_ELM);
        let alpha = *borrow(ctx, MM_MEMORY__MULTI_COLUMN_PERM__HASH_INTERACTION_ELM0);
        // The size that is allocated to the public memory.
        let public_memory_size = safe_div(*borrow(ctx, MM_TRACE_LENGTH), PUBLIC_MEMORY_STEP);

        // Ensure 'nValues' is bounded as a sanity check
        // (the bound is somewhat arbitrary).
        assert!(n_values < 0x1000000, OVERFLOW_PROTECTION_FAILED);
        assert!(n_values <= public_memory_size, NUMBER_OF_VALUES_OF_PUBLIC_MEMORY_IS_TOO_LARGE);

        let n_public_memory_pages = *borrow(ctx, MM_N_PUBLIC_MEM_PAGES);
        let cumulative_prods_ptr = *borrow(ctx, MM_PUBLIC_INPUT_PTR) + get_offset_page_prod(0, n_public_memory_pages);
        let denominator = compute_public_memory_prod(
            public_input,
            (cumulative_prods_ptr as u64),
            (n_public_memory_pages as u64)
        );

        // Compute address + alpha * value for the first address-value pair for padding.
        let public_input_ptr = (*borrow(ctx, MM_PUBLIC_INPUT_PTR) as u64);
        let padding_addr_ptr = public_input_ptr + OFFSET_PUBLIC_MEMORY_PADDING_ADDR;
        let padding_addr = *borrow(public_input, padding_addr_ptr);
        let padding_value = *borrow(public_input, padding_addr_ptr + 1);
        let hash_first_address_value = fadd(padding_addr, fmul(padding_value, alpha));

        // Pad the denominator with the shifted value of hash_first_address_value.
        let denom_pad = fpow(fsub(z, hash_first_address_value), public_memory_size - n_values);
        denominator = fmul(denominator, denom_pad);

        // Calculate the numerator.
        let numerator = fpow(z, public_memory_size);

        // Compute the final result: numerator * denominator^(-1).
        fmul(numerator, inverse(denominator))
    }

    /*
          Computes the cumulative product of the public memory cells:
            \prod_i( z - (addr_i + alpha * value_i) ).

          publicMemoryPtr is an array of nValues pairs (address, value).
          z and alpha are the perm and hash interaction elements assert!d to calculate the product.
    */
    fun compute_public_memory_prod(
        public_input: &vector<u256>,
        cumulative_prods_ptr: u64,
        n_public_memory_pages: u64
    ): u256 {
        let res = 1u256;
        for (i in cumulative_prods_ptr..(cumulative_prods_ptr + n_public_memory_pages)) {
            res = fmul(res, *borrow(public_input, i));
        };
        res
    }

    // In Starknet's contracts, this function is implemented in `CpuVerifier.sol`
    fun oods_consistency_check(
        signer: &signer,
        ctx: &mut vector<u256>,
        public_input: &vector<u256>
    ): bool acquires VmpfIterationCache, OccCheckpoint {
        let signer_addr = address_of(signer);
        let OccCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<OccCheckpoint>(signer_addr);
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
            let public_memory_prod = compute_public_memory_quotient(ctx, public_input);
            set_el(ctx, MM_MEMORY__MULTI_COLUMN_PERM__PERM__PUBLIC_MEMORY_PROD, public_memory_prod);

            prepare_for_oods_check(ctx);
            *checkpoint = OCC_CHECKPOINT3;
            // return false
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
        *checkpoint = OCC_CHECKPOINT1;
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

    struct VpCheckpoint has key, drop {
        inner: u8
    }

    struct CtxCache has key, drop {
        inner: vector<u256>
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
        inner: u8
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