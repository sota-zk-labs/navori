module cpu_addr::cpu_oods_6 {
    use std::signer::address_of;
    use std::vector::{borrow, borrow_mut, for_each_ref, length, push_back};

    use lib_addr::prime_field_element_0::{fadd, fmul, inverse};
    use lib_addr::vector::{assign, set_el};

    // This line is used for generating constants DO NOT REMOVE!
    // 2 + N_ROWS_IN_MASK
    const BATCH_INVERSE_CHUNK: u64 = 0xc3;
    // 4
    const CHECKPOINT1_FB: u8 = 0x4;
    // 20
    const CHECKPOINT1_OPI: u8 = 0x14;
    // 5
    const CHECKPOINT2_FB: u8 = 0x5;
    // 21
    const CHECKPOINT2_OPI: u8 = 0x15;
    // 6
    const CPU_OODS_CP2_ITERATION_LENGTH: u64 = 0x6;
    // 2600
    const CPU_OODS_OPI_ITERATION_LENGTH: u64 = 0xa28;
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
    // 0x492
    const MM_COMPOSITION_QUERY_RESPONSES: u64 = 0x492;
    // 109
    const MM_FRI_QUEUE: u64 = 0x6d;
    // 9
    const MM_N_UNIQUE_QUERIES: u64 = 0x9;
    // 0x2b1
    const MM_OODS_ALPHA: u64 = 0x2b1;
    // 0x281
    const MM_OODS_EVAL_POINTS: u64 = 0x281;
    // 0x168
    const MM_OODS_POINT: u64 = 0x168;
    // 0x167
    const MM_TRACE_GENERATOR: u64 = 0x167;
    // 0x2b2
    const MM_TRACE_QUERY_RESPONSES: u64 = 0x2b2;
    // 193
    const N_ROWS_IN_MASK: u64 = 0xc1;
    // End of generating constants!

    const DENOMINATORS_PTR_OFFSET: vector<vector<u64>> = vector[
        vector[0, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100, 0x120, 0x140, 0x160, 0x180, 0x1a0, 0x1c0, 0x1e0],
        vector[0, 0x20, 0xc20, 0xc40, 0x1040],
        vector[0, 0x20, 0xc20, 0xc40],
        vector[0, 0x20, 0x9a0, 0x9c0, 0xa00, 0xa20, 0xbc0, 0xbe0, 0xc40],
        vector[0, 0xc20],
        vector[0, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100, 0x120, 0x180, 0x1a0, 0x200, 0x3c0, 0x3e0, 0x5c0, 0x5e0, 0x720, 0x740, 0x840, 0x860, 0x900, 0x920, 0xa40, 0xa60, 0xc80, 0xca0, 0xd00, 0xd20, 0xdc0, 0xe40, 0xe60, 0xe80, 0xea0, 0xec0, 0xee0, 0xf20, 0x1080, 0x10e0, 0x11a0, 0x11c0, 0x1200, 0x1220, 0x12a0, 0x12c0, 0x12e0, 0x1300, 0x1320, 0x1340, 0x1360, 0x1380, 0x13a0, 0x13c0, 0x13e0, 0x1480, 0x14a0, 0x14c0, 0x14e0, 0x16a0, 0x16c0, 0x16e0, 0x1800],
        vector[0, 0x20, 0x40, 0x60],
        vector[0, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100, 0x120, 0x160, 0x180, 0x1a0, 0x1e0, 0x220, 0x240, 0x2a0, 0x300, 0x360, 0x440, 0x4a0, 0x580, 0x620, 0x660, 0x6e0, 0x780, 0x7c0, 0x820, 0x880, 0x8a0, 0x8e0, 0x940, 0x960, 0x9c0, 0xa80, 0xac0, 0xb20, 0xb40, 0xb80, 0xc60, 0xcc0, 0xf80, 0xfc0, 0x1000, 0x1060, 0x10a0, 0x10c0, 0x1100, 0x1120, 0x1140, 0x1160, 0x1180, 0x11e0, 0x1240, 0x1260, 0x1280],
        vector[0, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x100, 0x120, 0x140, 0x160, 0x180, 0x1a0, 0x1c0, 0x200, 0x220, 0x240, 0x260, 0x280, 0x2c0, 0x2e0, 0x300, 0x320, 0x340, 0x360, 0x380, 0x3a0, 0x3c0, 0x400, 0x420, 0x460, 0x480, 0x4a0, 0x4c0, 0x4e0, 0x500, 0x520, 0x540, 0x560, 0x580, 0x5a0, 0x5e0, 0x600, 0x640, 0x660, 0x680, 0x6a0, 0x6c0, 0x6e0, 0x700, 0x760, 0x7a0, 0x7c0, 0x7e0, 0x800, 0x8c0, 0x980, 0x9e0, 0xaa0, 0xae0, 0xb00, 0xb60, 0xba0, 0xc00, 0xce0, 0xd40, 0xd60, 0xd80, 0xda0, 0xdc0, 0xde0, 0xe00, 0xe20, 0xf00, 0xf40, 0xf60, 0xfa0, 0xfe0, 0x1020, 0x1400, 0x1420, 0x1440, 0x1460, 0x1500, 0x1520, 0x1540, 0x1560, 0x1580, 0x15a0, 0x15c0, 0x15e0, 0x1600, 0x1620, 0x1640, 0x1660, 0x1680, 0x1700, 0x1720, 0x1740, 0x1760, 0x1780, 0x17a0, 0x17c0, 0x17e0],
        vector[0, 0x20, 0x40, 0x60, 0xa0, 0xe0, 0x160, 0x1e0]
    ];
    // For each query point we want to invert (2 + N_ROWS_IN_MASK) items:
    //  The query point itself (x).
    //  The denominator for the constraint polynomial (x-z^constraintDegree)
    //  [(x-(g^rowNumber)z) for rowNumber in mask].
    // uint256 constant internal BATCH_INVERSE_CHUNK = (2 + N_ROWS_IN_MASK);

    public fun init_data_type(signer: &signer) {
        let signer_addr = address_of(signer);
        if (!exists<FbCheckpoint>(signer_addr)) {
            move_to(signer, FbCheckpoint {
                inner: CHECKPOINT1_FB
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
            move_to(signer, OpiCache {
                checkpoint: CHECKPOINT1_OPI,
                partial_product: 0,
                products_ptr: 0,
                products_to_values_offset: 0,
                current_partial_product_ptr: 0,
                is_in_iteration: false,
                prod_inv: 0
            })
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
    public fun fallback(
        signer: &signer,
        ctx: &mut vector<u256>
    ): bool acquires FbCheckpoint, FbCache, FbCheckpoint2Cache, OpiCache {
        let signer_addr = address_of(signer);
        let FbCheckpoint {
            inner: checkpoint
        } = borrow_global_mut<FbCheckpoint>(signer_addr);
        let FbCache {
            n_queries,
            batch_inverse_array
        } = borrow_global_mut<FbCache>(signer_addr);
        if (*checkpoint == CHECKPOINT1_FB) {
            *n_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);
            if (oods_prepare_inverses(signer, ctx, *n_queries, batch_inverse_array)) {
                *checkpoint = CHECKPOINT2_FB;
            };
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
        let n_trace_columns = length(&DENOMINATORS_PTR_OFFSET);
        let cnt = 0;
        while (*fri_queue < *fri_queue_end && cnt < CPU_OODS_CP2_ITERATION_LENGTH) {
            cnt = cnt + 1;
            // res accumulates numbers modulo K_MODULUS. Since 31*K_MODULUS < 2**256, we may add up to
            // 31 numbers without fear of overflow, and use mod_add modulo K_MODULUS only every
            // 31 iterations, and once more at the very end.
            let res = 0u256;

            // Trace constraints.
            let oods_alpha_pow = 1;
            let oods_alpha = /*oods_alpha*/ *borrow(ctx, MM_OODS_ALPHA);

            let odds_values_offset = 0;
            for (trace_query_responses_offset in 0..n_trace_columns) {
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
                                *borrow(batch_inverse_array, *denominators_ptr + *i / 32),
                                oods_alpha_pow
                            ),
                            column_value + K_MODULUS - /*oods_values[0]*/ *borrow(ctx, 368 + odds_values_offset)
                        )
                    );
                    oods_alpha_pow = fmul(oods_alpha_pow, oods_alpha);
                    odds_values_offset = odds_values_offset + 1;
                });
            };

            // Advance trace_query_responses by amount read (0x20 * nTraceColumns).
            *trace_query_responses = *trace_query_responses + n_trace_columns;

            // Composition constraints.
            {
                // Read the next element.
                let column_value = fmul(*borrow(ctx, *composition_query_responses), K_MONTGOMERY_R_INV);
                // res += c_271*(h_0(x) - C_0(z^2)) / (x - z^2).
                res =
                    res +
                        fmul(fmul(/*(x - z^2)^(-1)*/ *borrow(batch_inverse_array, *denominators_ptr + 193),
                            oods_alpha_pow),
                            column_value + (K_MODULUS - /*composition_oods_values[0]*/ *borrow(ctx, 639)))
                ;
                oods_alpha_pow = fmul(oods_alpha_pow, oods_alpha);
            };

            {
                // Read the next element.
                let column_value = fmul(*borrow(ctx, *composition_query_responses + 1), K_MONTGOMERY_R_INV);
                // res += c_193*(h_1(x) - C_1(z^2)) / (x - z^2).
                res =
                    res +
                        fmul(fmul(/*(x - z^2)^(-1)*/ *borrow(batch_inverse_array, *denominators_ptr + 193),
                            oods_alpha_pow),
                            column_value + (K_MODULUS - /*composition_oods_values[1]*/ *borrow(ctx, 640)))
                ;
                oods_alpha_pow = fmul(oods_alpha_pow, oods_alpha);
            };

            // Advance composition_query_responses by amount read (0x20 * constraintDegree).
            *composition_query_responses = *composition_query_responses + 2;

            // Append the friValue, which is the sum of the out-of-domain-sampling boundary
            // constraints for the trace and composition polynomials, to the fri_queue array.
            set_el(ctx, *fri_queue + 1, res % K_MODULUS);

            // Append the friInvPoint of the current query to the fri_queue array.
            set_el(ctx, *fri_queue + 2, *borrow(batch_inverse_array, *denominators_ptr + N_ROWS_IN_MASK + 1));

            // Advance denominators_ptr by chunk size (0x20 * (2+N_ROWS_IN_MASK)).
            *denominators_ptr = *denominators_ptr + 2 + N_ROWS_IN_MASK;

            *fri_queue = *fri_queue + 3;
        };

        if (*fri_queue >= *fri_queue_end) {
            *first_invoking = true;
            *checkpoint = CHECKPOINT1_FB;
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
    fun oods_prepare_inverses(
        signer: &signer,
        ctx: &vector<u256>,
        n_queries: u64,
        batch_inverse_array: &mut vector<u256>
    ): bool acquires OpiCache {
        let OpiCache {
            checkpoint,
            partial_product,
            products_ptr,
            products_to_values_offset,
            current_partial_product_ptr,
            is_in_iteration,
            prod_inv
        } = borrow_global_mut<OpiCache>(address_of(signer));
        if (*checkpoint == CHECKPOINT1_OPI) {
            *checkpoint = CHECKPOINT2_OPI;
            *batch_inverse_array = assign(0u256, 2 * n_queries * BATCH_INVERSE_CHUNK);

            // The array expmodsAndPoints stores subexpressions that are needed
            // for the denominators computation.
            // The array is segmented as follows:
            //    expmodsAndPoints[0:33] (.expmods) expmods used during calculations of the points below.
            //    expmodsAndPoints[33:226] (.points) points used during the denominators calculation.

            let expmods_and_points = &mut vector[];
            let g = /*trace_generator*/ *borrow(ctx, MM_TRACE_GENERATOR);

            // Prepare expmods for computations of trace generator powers.
            let tg2 = fmul(g, g);
            let tg3 = fmul(tg2, g);
            let tg4 = fmul(tg3, g);
            let tg5 = fmul(tg4, g);
            let tg6 = fmul(tg5, g);
            let tg7 = fmul(tg6, g);
            let tg8 = fmul(tg7, g);
            let tg10 = fmul(tg5, tg5);
            let tg11 = fmul(tg10, g);
            let tg14 = fmul(tg7, tg7);
            let tg16 = fmul(tg8, tg8);
            let tg20 = fmul(tg16, tg4);
            let tg25 = fmul(tg20, tg5);
            let tg28 = fmul(tg25, tg3);
            let tg31 = fmul(tg28, tg3);
            let tg32 = fmul(tg31, g);
            let tg48 = fmul(tg32, tg16);
            let tg49 = fmul(tg48, g);
            let tg58 = fmul(tg48, tg10);
            let tg64 = fmul(tg58, tg6);
            let tg125 = fmul(tg64, fmul(tg58, tg3));
            let tg176 = fmul(tg125, fmul(tg31, tg20));
            let tg184 = fmul(tg176, tg8);
            let tg192 = fmul(tg184, tg8);
            let tg213 = fmul(tg192, fmul(tg20, g));
            let tg357 = fmul(tg176, fmul(tg176, tg5));
            let tg395 = fmul(tg357, fmul(tg32, tg6));
            let tg1216 = fmul(tg395, fmul(tg395, fmul(tg395, tg31)));
            let tg1358 = fmul(tg1216, fmul(tg125, fmul(tg16, g)));
            let tg1678 = fmul(tg1216, fmul(tg395, fmul(tg64, tg3)));
            let tg2047 = fmul(tg1678, fmul(tg357, fmul(tg11, g)));
            let tg7681 = fmul(tg2047, fmul(tg2047, fmul(tg2047, fmul(tg1358, fmul(tg176, tg6)))));
            let tg8191 = fmul(tg7681, fmul(tg357, fmul(tg125, tg28)));

            let oods_point = /*oods_point*/ *borrow(ctx, MM_OODS_POINT);
            {
                // point = -z.
                let point = K_MODULUS - oods_point;
                // Compute denominators for rows with nonconst mask expression.
                // We compute those first because for the const rows we modify the point variable.

                // Compute denominators for rows with const mask expression.
                let tg_pow = vector[g, g, g, g, g, g, g, g, g, g, g, g, g, g, g, g, g, tg2, tg2, g, g, g, g, tg2, tg2, g, tg3, tg2, tg2, g, g, tg2, tg2, g, g, g, tg3, tg2, tg2, g, tg3, tg2, tg2, tg4, tg4, g, g, tg2, tg3, g, tg4, tg4, tg4, tg2, tg6, tg4, g, g, tg2, tg3, g, tg4, tg4, tg6, tg6, tg5, g, tg5, tg5, tg10, tg6, tg5, g, tg5, tg5, tg10, tg5, g, tg2, g, g, g, g, tg5, g, tg4, tg10, tg2, tg4, tg11, g, tg4, tg4, tg6, g, g, tg2, g, g, tg5, g, tg2, tg4, tg25, g, tg6, tg8, g, tg8, tg8, tg8, tg8, tg8, tg8, g, tg31, g, tg31, g, tg28, tg3, tg7, tg16, tg14, tg2, tg6, tg2, tg6, tg2, tg2, tg2, tg5, tg3, tg184, tg6, tg10, tg16, tg16, tg16, tg8, tg125, g, tg58, tg5, g, tg10, tg16, tg16, tg213, tg1216, g, tg2047, g, tg2047, g, tg2047, g, tg2047, g, tg1678, tg64, tg192, tg64, tg49, g, tg2047, g, tg1358, tg64, tg176, tg6, tg6, tg2, tg16, tg2, tg6, tg6, tg2, tg14, tg32, tg357, g, tg8191, tg7681, tg20, tg48, tg6, tg10, tg16, tg6, tg10, tg395];
                push_back(expmods_and_points, point);
                for_each_ref(&tg_pow, |x| {
                    point = fmul(point, *x);
                    push_back(expmods_and_points, point);
                });
            };

            let eval_points_ptr = /*oodseval_points*/ MM_OODS_EVAL_POINTS;
            let eval_points_end_ptr = eval_points_ptr + (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);

            // The batchInverseArray is split into two halves.
            // The first half is used for cumulative products and the second half for values to invert.
            // Consequently the products and values are half the array size apart.
            *products_ptr = 0;
            // Compute an offset in bytes to the middle of the array.
            *products_to_values_offset = n_queries * BATCH_INVERSE_CHUNK;
            let values_ptr = *products_to_values_offset;
            *partial_product = 1;
            let minus_point_pow = K_MODULUS - fmul(oods_point, oods_point);

            while (eval_points_ptr < eval_points_end_ptr) {
                let eval_point = *borrow(ctx, eval_points_ptr);

                // Shift eval_point to evaluation domain coset.
                let shifted_eval_point = fmul(eval_point, GENERATOR_VAL);

                for (offset in 0..193) {
                    let denominator = shifted_eval_point + *borrow(expmods_and_points, offset);
                    set_el(batch_inverse_array, *products_ptr + offset, *partial_product);
                    set_el(batch_inverse_array, values_ptr + offset, denominator);
                    *partial_product = fmul(*partial_product, denominator);
                };

                {
                    // Calculate the denominator for the composition polynomial columns: x - z^2.
                    let denominator = shifted_eval_point + minus_point_pow;
                    set_el(batch_inverse_array, *products_ptr + 193, *partial_product);
                    set_el(batch_inverse_array, values_ptr + 193, denominator);
                    *partial_product = fmul(*partial_product, denominator);
                };

                // Add eval_point to batch inverse inputs.
                // inverse(eval_point) is going to be used by FRI.
                set_el(batch_inverse_array, *products_ptr + 194, *partial_product);
                set_el(batch_inverse_array, values_ptr + 194, eval_point);
                *partial_product = fmul(*partial_product, eval_point);

                // Advance pointers.
                *products_ptr = *products_ptr + 195;
                values_ptr = values_ptr + 195;
                eval_points_ptr = eval_points_ptr + 1;
            };
            return false
        };
        {
            if (!*is_in_iteration) {
                *is_in_iteration = true;
                // Compute the inverse of the product.
                *prod_inv = inverse(*partial_product);

                assert!(*prod_inv != 0, EBATCH_INVERSE_PRODUCT_IS_ZERO);

                // Compute the inverses.
                // Loop over denominator_invs in reverse order.
                // currentpartial_productPtr is initialized to one past the end.
                *current_partial_product_ptr = *products_ptr;
            };
            // Loop in blocks of size 8 as much as possible: we can loop over a full block as long as
            // currentpartial_productPtr >= first_partial_product_ptr + 8*0x20, or equivalently,
            // currentpartial_productPtr > first_partial_product_ptr + 7*0x20.
            // We use the latter comparison since there is no >= evm opcode.
            let cnt = 0;
            while (*current_partial_product_ptr > 0 && cnt < CPU_OODS_OPI_ITERATION_LENGTH) {
                cnt = cnt + 1;
                *current_partial_product_ptr = *current_partial_product_ptr - 1;
                // Store 1/d_{i} = (d_0 * ... * d_{i-1}) * 1/(d_0 * ... * d_{i}).
                let tmp = borrow_mut(batch_inverse_array, *current_partial_product_ptr);
                *tmp = fmul(*tmp, *prod_inv);

                // Update prodInv to be 1/(d_0 * ... * d_{i-1}) by multiplying by d_i.
                *prod_inv = fmul(
                    *prod_inv,
                    *borrow(batch_inverse_array, *current_partial_product_ptr + *products_to_values_offset)
                );
            };
            if (*current_partial_product_ptr > 0) {
                return false
            };
        };
        *checkpoint = CHECKPOINT1_OPI;
        *is_in_iteration = false;
        true
    }

    #[test_only]
    public fun get_cpu_oods_fb_checkpoint(signer: &signer): u8 acquires FbCheckpoint {
        borrow_global<FbCheckpoint>(address_of(signer)).inner
    }

    #[test_only]
    public fun get_opi_checkpoint(signer: &signer): u8 acquires OpiCache {
        borrow_global<OpiCache>(address_of(signer)).checkpoint
    }

    // Data of the function `fallback`
    struct FbCheckpoint has key {
        inner: u8
    }

    struct FbCache has key {
        n_queries: u64,
        batch_inverse_array: vector<u256>
    }

    struct FbCheckpoint2Cache has key {
        fri_queue: u64,
        fri_queue_end: u64,
        trace_query_responses: u64,
        denominators_ptr: u64,
        composition_query_responses: u64,
        first_invoking: bool
    }

    // Data of the function `oods_prepare_inverses`
    struct OpiCache has key {
        checkpoint: u8,
        partial_product: u256,
        products_ptr: u64,
        products_to_values_offset: u64,
        current_partial_product_ptr: u64,
        is_in_iteration: bool,
        prod_inv: u256,
    }
}

#[test_only]
module cpu_addr::test_cpu_oods_6 {
    use cpu_addr::cpu_oods_6::{fallback, get_cpu_oods_fb_checkpoint, get_opi_checkpoint, init_data_type};
    use cpu_addr::cpu_oods_6_test_data::{ctx_input, ctx_output};

    #[test(signer = @cpu_addr)]
    fun test_fallback(signer: &signer) {
        let ctx = ctx_input();
        init_data_type(signer);
        let cnt = 0;
        while (!fallback(signer, &mut ctx)) {
            cnt = cnt + 1;
        };
        let ctx_output_ = ctx_output();
        assert!(ctx == ctx_output_, 1);
        assert!(cnt + 1 == 6, 1);
        assert!(get_cpu_oods_fb_checkpoint(signer) == 4, 1);
        assert!(get_opi_checkpoint(signer) == 20, 1);
    }
}