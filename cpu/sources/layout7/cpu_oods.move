module cpu_addr::cpu_oods_7 {
    use std::signer::address_of;
    use std::vector::{borrow, for_each_ref, push_back};

    use lib_addr::prime_field_element_0::{fadd, fmul, inverse};
    use lib_addr::vector::{assign, set_el};

    // This line is used for generating constants DO NOT REMOVE!
    // 1
    const EBATCH_INVERSE_PRODUCT_IS_ZERO: u64 = 0x1;
    // 3
    const FRI_QUEUE_SLOT_SIZE: u64 = 0x3;
    // 3
    const GENERATOR_VAL: u256 = 0x3;
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // 113078212145816603762751633895895194930089271709401121343797004406777446400
    const K_MONTGOMERY_R_INV: u256 = 0x40000000000001100000000000012100000000000000000000000000000000;
    // 1178
    const MM_COMPOSITION_QUERY_RESPONSES: u64 = 0x49a;
    // 109
    const MM_FRI_QUEUE: u64 = 0x6d;
    // 9
    const MM_N_UNIQUE_QUERIES: u64 = 0x9;
    // 601
    const MM_OODS_ALPHA: u64 = 0x259;
    // 553
    const MM_OODS_EVAL_POINTS: u64 = 0x229;
    // 351
    const MM_OODS_POINT: u64 = 0x15f;
    // 350
    const MM_TRACE_GENERATOR: u64 = 0x15e;
    // 602
    const MM_TRACE_QUERY_RESPONSES: u64 = 0x25a;
    // 98
    const N_ROWS_IN_MASK: u256 = 0x62;
    // End of generating constants!

    const DENOMINATORS_PTR_OFFSET: vector<vector<u64>> = vector[
        vector[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        vector[0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 19, 20, 22, 23, 25, 26, 27, 28, 42, 43, 57, 59, 61, 62, 63, 64, 71, 73, 75, 77],
        vector[0, 1],
        vector[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 20, 21, 23, 24, 29, 30, 31, 32, 38, 44, 45, 46, 47, 55, 56, 60, 65, 66, 73, 74, 78, 79, 80, 81, 94, 95, 97],
        vector[0, 1, 2, 3],
        vector[0, 1, 2, 3, 4, 5, 6, 73, 75, 77],
        vector[0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 25, 33, 39, 48, 61, 67, 75, 88, 90, 92, 93, 96],
        vector[0, 1, 2, 3, 4, 5, 7, 9, 11, 13, 49, 51, 52, 53, 54, 56, 58, 82, 83, 84, 85, 86, 87, 89, 91],
        vector[0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 20, 22, 26, 34, 35, 36, 37, 40, 41, 43, 44, 50, 68, 69, 70, 72, 76, 77],
        vector[0, 1],
        vector[0, 1],
        vector[0, 1, 2, 5]
    ];
    // For each query point we want to invert (2 + N_ROWS_IN_MASK) items:
    //  The query point itself (x).
    //  The denominator for the constraint polynomial (x-z^constraintDegree)
    //  [(x-(g^rowNumber)z) for rowNumber in mask].
    // uint256 constant internal BATCH_INVERSE_CHUNK = (2 + N_ROWS_IN_MASK);
    const BATCH_INVERSE_CHUNK: u64 = (2 + 98);

    public fun init_data_type(signer: &signer) {
        let signer_addr = address_of(signer);
        if (!exists<FbCheckpoint>(signer_addr)) {
            move_to(signer, FbCheckpoint {
                inner: FB_CHECKPOINT1
            });
            move_to(signer, FbCache {
                n_queries: 0,
                batch_inverse_array: vector[]
            });
            move_to(signer, FbCheckpoint2Cache {
                fri_queue: 0,
                fri_queue_end: 0,
                trace_query_responses: 0,
                denominators_ptr: 0,
                composition_query_responses: 0,
                first_invoking: true
            });
        };
    }

    //  Builds and sums boundary constraints that check that the prover provided the proper evaluations
    //  out of domain evaluations for the trace and composition columns.
    //  The inputs to this function are:
    //    The verifier ctx.
    //
    //   The boundary constraints for the trace enforce claims of the form f(g^k*z) = c by
    //   requiring the quotient (f(x) - c)/(x-g^k*z) to be a low degree polynomial.
    //   The boundary constraints for the composition enforce claims of the form h(z^d) = c by
    //   requiring the quotient (h(x) - c)/(x-z^d) to be a low degree polynomial.
    //   Where:
    //   f is a trace column.
    //   h is a composition column.
    //   z is the out of domain sampling point.
    //   g is the trace generator
    //   k is the offset in the mask.
    //   d is the degree of the composition polynomial.
    //   c is the evaluation sent by the prover.
    //
    public fun fallback(
        signer: &signer,
        ctx: &mut vector<u256>
    ): bool acquires FbCheckpoint, FbCache, FbCheckpoint2Cache {
        let signer_addr = address_of(signer);
        let FbCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<FbCheckpoint>(signer_addr);
        let FbCache {
            n_queries,
            batch_inverse_array
        } = borrow_global_mut<FbCache>(signer_addr);
        if (*checkpoint == FB_CHECKPOINT1) {
            *n_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);
            *batch_inverse_array = assign(0u256, 2 * *n_queries * BATCH_INVERSE_CHUNK);

            oods_prepare_inverses(ctx, batch_inverse_array, *n_queries);
            *checkpoint = FB_CHECKPOINT2;
            return false
        };

        let FbCheckpoint2Cache {
            fri_queue,
            fri_queue_end,
            trace_query_responses,
            denominators_ptr,
            composition_query_responses,
            first_invoking
        } = borrow_global_mut<FbCheckpoint2Cache>(signer_addr);
        if (*first_invoking) {
            *first_invoking = false;
            *fri_queue = /*fri_queue*/ MM_FRI_QUEUE;
            *fri_queue_end = *fri_queue + *n_queries * FRI_QUEUE_SLOT_SIZE;
            *trace_query_responses = /*traceQueryQesponses*/ MM_TRACE_QUERY_RESPONSES;
            *composition_query_responses = /*composition_query_responses*/ MM_COMPOSITION_QUERY_RESPONSES;
            // Set denominators_ptr to point to the batchInverseOut array.
            // The content of batchInverseOut is described in oodsPrepareInverses.
            *denominators_ptr = 0u64;
        };
        let cnt = 0;
        let prime = K_MODULUS;

        while (*fri_queue < *fri_queue_end && cnt < CP2_ITERATION_LENGTH) {
            cnt = cnt + 1;
            // res accumulates numbers modulo prime. Since 31*prime < 2**256, we may add up to
            // 31 numbers without fear of overflow, and use mod_add modulo prime only every
            // 31 iterations, and once more at the very end.
            let res = 0u256;

            // Trace constraints.
            let oods_alpha_pow = 1;
            let oods_alpha = /*oods_alpha*/ *borrow(ctx, MM_OODS_ALPHA);

            let odds_values_offset = 0;
            for (trace_query_responses_offset in 0..12) {
                // Read the next element.
                let column_value = fmul(
                    *borrow(ctx, *trace_query_responses + trace_query_responses_offset),
                    K_MONTGOMERY_R_INV
                );

                for_each_ref(borrow(&DENOMINATORS_PTR_OFFSET, trace_query_responses_offset), |i| {
                    res = fadd(
                        res,
                        fmul(
                            fmul(
                                *borrow(batch_inverse_array, *denominators_ptr + *i),
                                oods_alpha_pow
                            ),
                            column_value + prime - /*oods_values[0]*/ *borrow(ctx, 359 + odds_values_offset)
                        )
                    );
                    oods_alpha_pow = fmul(oods_alpha_pow, oods_alpha);
                    odds_values_offset = odds_values_offset + 1;
                });
            };

            // Advance trace_query_responses by amount read (0x20 * nTraceColumns).
            *trace_query_responses = *trace_query_responses + 12;

            // Composition constraints.

            {
                // Read the next element.
                let column_value = fmul(*borrow(ctx, *composition_query_responses), K_MONTGOMERY_R_INV);
                // res += c_192*(h_0(x) - C_0(z^2)) / (x - z^2).
                res =
                    res +
                        fmul(fmul(/*(x - z^2)^(-1)*/ *borrow(batch_inverse_array, *denominators_ptr + 98),
                            oods_alpha_pow),
                            column_value + (prime - /*composition_oods_values[0]*/ *borrow(ctx, 359 + 192)))
                ;
                oods_alpha_pow = fmul(oods_alpha_pow, oods_alpha);
            };

            {
                // Read the next element.
                let column_value = fmul(*borrow(ctx, *composition_query_responses + 1), K_MONTGOMERY_R_INV);
                // res += c_193*(h_1(x) - C_1(z^2)) / (x - z^2).
                res =
                    res +
                        fmul(fmul(/*(x - z^2)^(-1)*/ *borrow(batch_inverse_array, *denominators_ptr + 98),
                            oods_alpha_pow),
                            column_value + (prime - /*composition_oods_values[1]*/ *borrow(ctx, 359 + 193)))
                ;
                oods_alpha_pow = fmul(oods_alpha_pow, oods_alpha);
            };

            // Advance composition_query_responses by amount read (0x20 * constraintDegree).
            *composition_query_responses = *composition_query_responses + 2;

            // Append the friValue, which is the sum of the out-of-domain-sampling boundary
            // constraints for the trace and composition polynomials, to the fri_queue array.
            set_el(ctx, *fri_queue + 1, res % prime);

            // print(&(res % prime));

            // Append the friInvPoint of the current query to the fri_queue array.
            set_el(ctx, *fri_queue + 2, *borrow(batch_inverse_array, *denominators_ptr + 99));

            // Advance denominators_ptr by chunk size (0x20 * (2+N_ROWS_IN_MASK)).
            *denominators_ptr = *denominators_ptr + 100;

            *fri_queue = *fri_queue + 3;
        };

        if (*fri_queue >= *fri_queue_end) {
            *first_invoking = true;
            *checkpoint = FB_CHECKPOINT1;
            true
        } else {
            false
        }
    }

    // Computes and performs batch inverse on all the denominators required for the out of domain
    // sampling boundary constraints.
    //
    // Since the frieval_points are calculated during the computation of the denominators
    // this function also adds those to the batch inverse in prepartion for the fri that follows.
    //
    // After this function returns, the batch_inverse_out array holds #queries
    // chunks of size (2 + N_ROWS_IN_MASK) with the following structure:
    // 0..(N_ROWS_IN_MASK-1):   [(x - g^i * z)^(-1) for i in rowsInMask]
    // N_ROWS_IN_MASK:          (x - z^constraintDegree)^-1
    // N_ROWS_IN_MASK+1:        frieval_pointInv.
    fun oods_prepare_inverses(ctx: &vector<u256>, batch_inverse_array: &mut vector<u256>, n_queries: u64) {
        let eval_coset_offset_ = GENERATOR_VAL;
        // The array expmods_and_points stores subexpressions that are needed
        // for the denominators computation.
        // The array is segmented as follows:
        //    expmods_and_points[0:13] (.expmods) expmods used during calculations of the points below.
        //    expmods_and_points[13:111] (.points) points used during the denominators calculation.
        let expmods_and_points = &mut vector[];
        {
            let trace_generator = /*trace_generator*/ *borrow(ctx, MM_TRACE_GENERATOR);
            let prime = K_MODULUS;

            // Prepare expmods for computations of trace generator powers.

            let tg2 = fmul(trace_generator, trace_generator);
            let tg3 = fmul(tg2, trace_generator);
            let tg4 = fmul(tg3, trace_generator);
            let tg5 = fmul(tg4, trace_generator);
            let tg7 = fmul(tg4, tg3);
            let tg12 = fmul(tg7, tg5);
            let tg13 = fmul(tg12, trace_generator);
            let tg24 = fmul(tg12, tg12);
            let tg28 = fmul(tg24, tg4);
            let tg48 = fmul(tg24, tg24);
            let tg96 = fmul(tg48, tg48);
            let tg192 = fmul(tg96, tg96);
            let tg216 = fmul(tg24, tg192);
            let tg245 = fmul(trace_generator, fmul(tg216, tg28));
            let tg320 = fmul(tg216, fmul(tg48, fmul(tg28, tg28)));
            let tg1010 = fmul(tg2, fmul(tg48, fmul(tg320, fmul(tg320, tg320))));

            let oods_point = /*oods_point*/ *borrow(ctx, MM_OODS_POINT);
            {
                // point = -z.
                let point = prime - oods_point;
                // Compute denominators for rows with nonconst mask expression.
                // We compute those first because for the const rows we modify the point variable.

                // Compute denominators for rows with const mask expression.

                // expmods_and_points.points[0] = -z.
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[1] = -(g * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[2] = -(g^2 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[3] = -(g^3 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[4] = -(g^4 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[5] = -(g^5 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[6] = -(g^6 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[7] = -(g^7 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[8] = -(g^8 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[9] = -(g^9 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[10] = -(g^10 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[11] = -(g^11 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[12] = -(g^12 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[13] = -(g^13 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[14] = -(g^14 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[15] = -(g^15 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[16] = -(g^16 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[17] = -(g^17 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[18] = -(g^18 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[19] = -(g^20 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[20] = -(g^22 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[21] = -(g^23 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[22] = -(g^24 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[23] = -(g^26 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[24] = -(g^27 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[25] = -(g^28 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[26] = -(g^30 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[27] = -(g^32 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[28] = -(g^33 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = fmul(point, tg5);
                // expmods_and_points.points[29] = -(g^38 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[30] = -(g^39 * z).
                push_back(expmods_and_points, point);

                // point *= g^3.
                point = fmul(point, tg3);
                // expmods_and_points.points[31] = -(g^42 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[32] = -(g^43 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[33] = -(g^44 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = fmul(point, tg5);
                // expmods_and_points.points[34] = -(g^49 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = fmul(point, tg4);
                // expmods_and_points.points[35] = -(g^53 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[36] = -(g^54 * z).
                push_back(expmods_and_points, point);

                // point *= g^3.
                point = fmul(point, tg3);
                // expmods_and_points.points[37] = -(g^57 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[38] = -(g^58 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                push_back(expmods_and_points, point);
                // expmods_and_points.points[39] = -(g^60 * z).

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[40] = -(g^61 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[41] = -(g^62 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[42] = -(g^64 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[43] = -(g^65 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = fmul(point, tg5);
                // expmods_and_points.points[44] = -(g^70 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[45] = -(g^71 * z).
                push_back(expmods_and_points, point);

                // point *= g^3.
                point = fmul(point, tg3);
                // expmods_and_points.points[46] = -(g^74 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[47] = -(g^75 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[48] = -(g^76 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[49] = -(g^77 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[50] = -(g^78 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[51] = -(g^79 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[52] = -(g^81 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[53] = -(g^83 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[54] = -(g^85 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[55] = -(g^86 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[56] = -(g^87 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[57] = -(g^88 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[58] = -(g^89 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[59] = -(g^90 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[60] = -(g^91 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[61] = -(g^92 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[62] = -(g^94 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[63] = -(g^96 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[64] = -(g^97 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = fmul(point, tg5);
                // expmods_and_points.points[65] = -(g^102 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[66] = -(g^103 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = fmul(point, tg5);
                // expmods_and_points.points[67] = -(g^108 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = fmul(point, tg5);
                // expmods_and_points.points[68] = -(g^113 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = fmul(point, tg4);
                // expmods_and_points.points[69] = -(g^117 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[70] = -(g^118 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[71] = -(g^120 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[72] = -(g^121 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[73] = -(g^122 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[74] = -(g^123 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[75] = -(g^124 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[76] = -(g^125 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[77] = -(g^126 * z).
                push_back(expmods_and_points, point);

                // point *= g^28.
                point = fmul(point, tg28);
                // expmods_and_points.points[78] = -(g^154 * z).
                push_back(expmods_and_points, point);

                // point *= g^48.
                point = fmul(point, tg48);
                // expmods_and_points.points[79] = -(g^202 * z).
                push_back(expmods_and_points, point);

                // point *= g^320.
                point = fmul(point, tg320);
                // expmods_and_points.points[80] = -(g^522 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[81] = -(g^523 * z).
                push_back(expmods_and_points, point);

                // point *= g^245.
                point = fmul(point, tg245);
                // expmods_and_points.points[82] = -(g^768 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = fmul(point, tg4);
                // expmods_and_points.points[83] = -(g^772 * z).
                push_back(expmods_and_points, point);

                // point *= g^12.
                point = fmul(point, tg12);
                // expmods_and_points.points[84] = -(g^784 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = fmul(point, tg4);
                // expmods_and_points.points[85] = -(g^788 * z).
                push_back(expmods_and_points, point);

                // point *= g^216.
                point = fmul(point, tg216);
                // expmods_and_points.points[86] = -(g^1004 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = fmul(point, tg4);
                // expmods_and_points.points[87] = -(g^1008 * z).
                push_back(expmods_and_points, point);

                // point *= g^13.
                point = fmul(point, tg13);
                // expmods_and_points.points[88] = -(g^1021 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[89] = -(g^1022 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[90] = -(g^1023 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[91] = -(g^1024 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[92] = -(g^1025 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = fmul(point, tg2);
                // expmods_and_points.points[93] = -(g^1027 * z).
                push_back(expmods_and_points, point);

                // point *= g^7.
                point = fmul(point, tg7);
                // expmods_and_points.points[94] = -(g^1034 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = fmul(point, trace_generator);
                // expmods_and_points.points[95] = -(g^1035 * z).
                push_back(expmods_and_points, point);

                // point *= g^1010.
                point = fmul(point, tg1010);
                // expmods_and_points.points[96] = -(g^2045 * z).
                push_back(expmods_and_points, point);

                // point *= g^13.
                point = fmul(point, tg13);
                // expmods_and_points.points[97] = -(g^2058 * z).
                push_back(expmods_and_points, point);
            };

            let eval_points_ptr = /*oodseval_points*/ MM_OODS_EVAL_POINTS;
            let eval_points_end_ptr = eval_points_ptr + (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);

            // The batchInverseArray is split into two halves.
            // The first half is used for cumulative products and the second half for values to invert.
            // Consequently the products and values are half the array size apart.
            let products_ptr = 0;
            // Compute an offset in bytes to the middle of the array.
            let products_to_values_offset = n_queries * BATCH_INVERSE_CHUNK;
            let values_ptr = products_to_values_offset;
            let partial_product = 1;
            let minus_point_pow = prime - fmul(oods_point, oods_point);
            for (eval_points_ptr in eval_points_ptr..eval_points_end_ptr) {
                let eval_point = *borrow(ctx, eval_points_ptr);

                // Shift eval_point to evaluation domain coset.
                let shifted_eval_point = fmul(eval_point, eval_coset_offset_);

                for (offset in 0..98) {
                    let denominator = shifted_eval_point + *borrow(expmods_and_points, offset);
                    set_el(batch_inverse_array, products_ptr + offset, partial_product);
                    set_el(batch_inverse_array, values_ptr + offset, denominator);
                    partial_product = fmul(partial_product, denominator);
                };

                {
                    // Calculate the denominator for the composition polynomial columns: x - z^2.
                    let denominator = shifted_eval_point + minus_point_pow;
                    set_el(batch_inverse_array, products_ptr + 98, partial_product);
                    set_el(batch_inverse_array, values_ptr + 98, denominator);
                    partial_product = fmul(partial_product, denominator);
                };

                // Add eval_point to batch inverse inputs.
                // inverse(eval_point) is going to be used by FRI.
                set_el(batch_inverse_array, products_ptr + 99, partial_product);
                set_el(batch_inverse_array, values_ptr + 99, eval_point);
                partial_product = fmul(partial_product, eval_point);

                // Advance pointers.
                products_ptr = products_ptr + 100;
                values_ptr = values_ptr + 100;
            };

            let first_partial_product_ptr = 0;
            // Compute the inverse of the product.
            let prod_inv = inverse(partial_product);

            assert!(prod_inv != 0, EBATCH_INVERSE_PRODUCT_IS_ZERO);

            // Compute the inverses.
            // Loop over denominator_invs in reverse order.
            // currentpartial_productPtr is initialized to one past the end.
            let current_partial_product_ptr = products_ptr;
            // Loop in blocks of size 8 as much as possible: we can loop over a full block as long as
            // currentpartial_productPtr >= first_partial_product_ptr + 8*0x20, or equivalently,
            // currentpartial_productPtr > first_partial_product_ptr + 7*0x20.
            // We use the latter comparison since there is no >= evm opcode.
            while (current_partial_product_ptr > first_partial_product_ptr) {
                current_partial_product_ptr = current_partial_product_ptr - 1;
                // Store 1/d_{i} = (d_0 * ... * d_{i-1}) * 1/(d_0 * ... * d_{i}).
                let tmp = fmul(*borrow(batch_inverse_array, current_partial_product_ptr), prod_inv);
                set_el(batch_inverse_array, current_partial_product_ptr, tmp);

                // Update prodInv to be 1/(d_0 * ... * d_{i-1}) by multiplying by d_i.
                prod_inv = fmul(
                    prod_inv,
                    *borrow(batch_inverse_array, current_partial_product_ptr + products_to_values_offset)
                );
            };
        };
    }

    #[test_only]
    public fun get_cpu_oods_fb_checkpoint(signer: &signer): u8 acquires FbCheckpoint {
        borrow_global<FbCheckpoint>(address_of(signer)).inner
    }

    // Data of the function `fallback`
    // checkpoints
    const FB_CHECKPOINT1: u8 = 1;
    const FB_CHECKPOINT2: u8 = 2;

    struct FbCheckpoint has key {
        inner: u8
    }

    struct FbCache has key {
        n_queries: u64,
        batch_inverse_array: vector<u256>
    }

    const CP2_ITERATION_LENGTH: u64 = 8;

    struct FbCheckpoint2Cache has key {
        fri_queue: u64,
        fri_queue_end: u64,
        trace_query_responses: u64,
        denominators_ptr: u64,
        composition_query_responses: u64,
        first_invoking: bool
    }
}

#[test_only]
module cpu_addr::test_cpu_oods_7 {
    use cpu_addr::cpu_oods_7::{fallback, init_data_type};
    use cpu_addr::cpu_oods_7_test_data::{ctx_input, ctx_output};

    #[test(signer = @cpu_addr)]
    fun test_fallback(signer: &signer) {
        let ctx = ctx_input();
        init_data_type(signer);
        fallback(signer, &mut ctx);
        fallback(signer, &mut ctx);
        fallback(signer, &mut ctx);
        assert!(ctx == ctx_output(), 1);
    }
}