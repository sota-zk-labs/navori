module verifier_addr::cpu_oods_7 {

    use std::vector::{borrow, length, slice, for_each_ref};
    use lib_addr::math_mod::{mod_mul, mod_add, mod_exp};
    use verifier_addr::fri_layer::FRI_QUEUE_SLOT_SIZE;
    use verifier_addr::prime_field_element_0::{k_montgomery_r_inv, k_modulus, generator_val};
    use verifier_addr::vector::{assign, set_el};
    use verifier_addr::memory_map_7::{MM_N_UNIQUE_QUERIES, MM_FRI_QUEUE, MM_TRACE_QUERY_RESPONSES,
        MM_COMPOSITION_QUERY_RESPONSES, MM_OODS_ALPHA, MM_TRACE_GENERATOR, MM_OODS_POINT,
        MM_OODS_EVAL_POINTS
    };

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

    fun add(x: u256, y: u256): u256 {
        x + y
    }

    fun sub(x: u256, y: u256): u256 {
        x - y
    }

    /*
      Builds and sums boundary constraints that check that the prover provided the proper evaluations
      out of domain evaluations for the trace and composition columns.

      The inputs to this function are:
          The verifier ctx.

      The boundary constraints for the trace enforce claims of the form f(g^k*z) = c by
      requiring the quotient (f(x) - c)/(x-g^k*z) to be a low degree polynomial.

      The boundary constraints for the composition enforce claims of the form h(z^d) = c by
      requiring the quotient (h(x) - c)/(x-z^d) to be a low degree polynomial.
      Where:
            f is a trace column.
            h is a composition column.
            z is the out of domain sampling point.
            g is the trace generator
            k is the offset in the mask.
            d is the degree of the composition polynomial.
            c is the evaluation sent by the prover.
    */
    public fun fallback(ctx: &mut vector<u256>): vector<u256> {
        let cnt = 0;
        for_each_ref(&DENOMINATORS_PTR_OFFSET, |v| {
            cnt = cnt + length(v);
        });
        let n_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES()) as u64);
        let batch_inverse_array = assign(0u256, 2 * n_queries * BATCH_INVERSE_CHUNK);

        oods_prepare_inverses(ctx, &mut batch_inverse_array);

        let k_montgomery_r_inv = k_montgomery_r_inv();
        let prime = k_modulus();
        let fri_queue = /*fri_queue*/ MM_FRI_QUEUE();
        let fri_queue_end = fri_queue + n_queries * FRI_QUEUE_SLOT_SIZE();
        let trace_query_responses = /*traceQueryQesponses*/ MM_TRACE_QUERY_RESPONSES();

        let composition_query_responses = /*composition_query_responses*/ MM_COMPOSITION_QUERY_RESPONSES();

        // Set denominators_ptr to point to the batchInverseOut array.
        // The content of batchInverseOut is described in oodsPrepareInverses.
        let denominators_ptr = 0u64;
        while (fri_queue < fri_queue_end) {
            // res accumulates numbers modulo prime. Since 31*prime < 2**256, we may add up to
            // 31 numbers without fear of overflow, and use mod_add modulo prime only every
            // 31 iterations, and once more at the very end.
            let res = 0u256;

            // Trace constraints.
            let oods_alpha_pow = 1;
            let oods_alpha = /*oods_alpha*/ *borrow(ctx, MM_OODS_ALPHA());

            let odds_values_offset = 0;
            for (trace_query_responses_offset in 0..12) {
                // Read the next element.
                let column_value = mod_mul(
                    *borrow(ctx, trace_query_responses + trace_query_responses_offset),
                    k_montgomery_r_inv,
                    prime
                );

                for_each_ref(borrow(&DENOMINATORS_PTR_OFFSET, trace_query_responses_offset), |i| {
                    res = mod_add(
                        res,
                        mod_mul(
                            mod_mul(
                                *borrow(&batch_inverse_array, denominators_ptr + *i),
                                oods_alpha_pow,
                                prime
                            ),
                            add(column_value, sub(prime, /*oods_values[0]*/ *borrow(ctx, 359 + odds_values_offset))),
                            prime
                        ),
                        prime
                    );
                    oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
                    odds_values_offset = odds_values_offset + 1;
                });
            };

            // Advance trace_query_responses by amount read (0x20 * nTraceColumns).
            trace_query_responses = trace_query_responses + 12;

            // Composition constraints.

            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, composition_query_responses), k_montgomery_r_inv, prime);
                // res += c_192*(h_0(x) - C_0(z^2)) / (x - z^2).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z^2)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 98),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*composition_oods_values[0]*/ *borrow(ctx, 359 + 192))),
                        prime)
                );
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, composition_query_responses + 1), k_montgomery_r_inv, prime);
                // res += c_193*(h_1(x) - C_1(z^2)) / (x - z^2).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z^2)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 98),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*composition_oods_values[1]*/ *borrow(ctx, 359 + 193))),
                        prime)
                );
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Advance composition_query_responses by amount read (0x20 * constraintDegree).
            composition_query_responses = composition_query_responses + 2;

            // Append the friValue, which is the sum of the out-of-domain-sampling boundary
            // constraints for the trace and composition polynomials, to the fri_queue array.
            set_el(ctx, fri_queue + 1, res % prime);
            
            // print(&(res % prime));

            // Append the friInvPoint of the current query to the fri_queue array.
            set_el(ctx, fri_queue + 2, *borrow(&batch_inverse_array, denominators_ptr + 99));

            // Advance denominators_ptr by chunk size (0x20 * (2+N_ROWS_IN_MASK)).
            denominators_ptr = denominators_ptr + 100;

            fri_queue = fri_queue + 3;
        };

        slice(ctx, 109, 109 + 144)
    }

    /*
          Computes and performs batch inverse on all the denominators required for the out of domain
          sampling boundary constraints.

          Since the frieval_points are calculated during the computation of the denominators
          this function also adds those to the batch inverse in prepartion for the fri that follows.

          After this function returns, the batch_inverse_out array holds #queries
          chunks of size (2 + N_ROWS_IN_MASK) with the following structure:
          0..(N_ROWS_IN_MASK-1):   [(x - g^i * z)^(-1) for i in rowsInMask]
          N_ROWS_IN_MASK:          (x - z^constraintDegree)^-1
          N_ROWS_IN_MASK+1:        frieval_pointInv.
    */
    fun oods_prepare_inverses(ctx: &mut vector<u256>, batch_inverse_array: &mut vector<u256>) {
        let eval_coset_offset_ = generator_val();
        // The array expmods_and_points stores subexpressions that are needed
        // for the denominators computation.
        // The array is segmented as follows:
        //    expmods_and_points[0:13] (.expmods) expmods used during calculations of the points below.
        //    expmods_and_points[13:111] (.points) points used during the denominators calculation.
        let expmods_and_points = &mut assign(0u256, 111);
        {
            let trace_generator = /*trace_generator*/ *borrow(ctx, MM_TRACE_GENERATOR());
            let prime = k_modulus();

            // Prepare expmods for computations of trace generator powers.

            let tg2 = mod_mul(trace_generator, trace_generator, prime);
            let tg3 = mod_mul(tg2, trace_generator, prime);
            let tg4 = mod_mul(tg3, trace_generator, prime);
            let tg5 = mod_mul(tg4, trace_generator, prime);
            let tg7 = mod_mul(tg4, tg3, prime);
            let tg12 = mod_mul(tg7, tg5, prime);
            let tg13 = mod_mul(tg12, trace_generator, prime);
            let tg28 = mod_mul(tg2, mod_mul(tg13, tg13, prime), prime);
            let tg48 = mod_mul(tg28, mod_mul(tg13, tg7, prime), prime);
            let tg216 = mod_exp(tg12, 18, prime);
            let tg245 = mod_mul(trace_generator, mod_mul(tg216, tg28, prime), prime);
            let tg320 = mod_mul(tg216, mod_mul(tg48, mod_mul(tg28, tg28, prime), prime), prime);
            let tg1010 = mod_mul(tg2, mod_mul(tg48, mod_exp(tg320, 3, prime), prime), prime);

            // expmods_and_points.expmods[0] = trace_generator^2.
            set_el(expmods_and_points, 0, tg2);

            // expmods_and_points.expmods[1] = trace_generator^3.
            set_el(expmods_and_points, 1, tg3);

            // expmods_and_points.expmods[2] = trace_generator^4.
            set_el(expmods_and_points, 2, tg4);

            // expmods_and_points.expmods[3] = trace_generator^5.
            set_el(expmods_and_points, 3, tg5);

            // expmods_and_points.expmods[4] = trace_generator^7.
            set_el(expmods_and_points, 4, tg7);

            // expmods_and_points.expmods[5] = trace_generator^12.
            set_el(expmods_and_points, 5, tg12);

            // expmods_and_points.expmods[6] = trace_generator^13.
            set_el(expmods_and_points, 6, tg13);

            // expmods_and_points.expmods[7] = trace_generator^28.
            set_el(expmods_and_points, 7, tg28);

            // expmods_and_points.expmods[8] = trace_generator^48.
            set_el(expmods_and_points, 8, tg48);

            // expmods_and_points.expmods[9] = trace_generator^216.
            set_el(expmods_and_points, 9, tg216);

            // expmods_and_points.expmods[10] = trace_generator^245.
            set_el(expmods_and_points, 10, tg245);

            // expmods_and_points.expmods[11] = trace_generator^320.
            set_el(expmods_and_points, 11, tg320);

            // expmods_and_points.expmods[12] = trace_generator^1010.
            set_el(expmods_and_points, 12, tg1010);

            let oods_point = /*oods_point*/ *borrow(ctx, MM_OODS_POINT());
            {
                // point = -z.
                let point = sub(prime, oods_point);
                // Compute denominators for rows with nonconst mask expression.
                // We compute those first because for the const rows we modify the point variable.

                // Compute denominators for rows with const mask expression.

                // expmods_and_points.points[0] = -z.
                set_el(expmods_and_points, 13, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[1] = -(g * z).
                set_el(expmods_and_points, 14, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[2] = -(g^2 * z).
                set_el(expmods_and_points, 15, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[3] = -(g^3 * z).
                set_el(expmods_and_points, 16, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[4] = -(g^4 * z).
                set_el(expmods_and_points, 17, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[5] = -(g^5 * z).
                set_el(expmods_and_points, 18, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[6] = -(g^6 * z).
                set_el(expmods_and_points, 19, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[7] = -(g^7 * z).
                set_el(expmods_and_points, 20, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[8] = -(g^8 * z).
                set_el(expmods_and_points, 21, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[9] = -(g^9 * z).
                set_el(expmods_and_points, 22, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[10] = -(g^10 * z).
                set_el(expmods_and_points, 23, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[11] = -(g^11 * z).
                set_el(expmods_and_points, 24, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[12] = -(g^12 * z).
                set_el(expmods_and_points, 25, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[13] = -(g^13 * z).
                set_el(expmods_and_points, 26, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[14] = -(g^14 * z).
                set_el(expmods_and_points, 27, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[15] = -(g^15 * z).
                set_el(expmods_and_points, 28, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[16] = -(g^16 * z).
                set_el(expmods_and_points, 29, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[17] = -(g^17 * z).
                set_el(expmods_and_points, 30, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[18] = -(g^18 * z).
                set_el(expmods_and_points, 31, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[19] = -(g^20 * z).
                set_el(expmods_and_points, 32, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[20] = -(g^22 * z).
                set_el(expmods_and_points, 33, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[21] = -(g^23 * z).
                set_el(expmods_and_points, 34, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[22] = -(g^24 * z).
                set_el(expmods_and_points, 35, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[23] = -(g^26 * z).
                set_el(expmods_and_points, 36, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[24] = -(g^27 * z).
                set_el(expmods_and_points, 37, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[25] = -(g^28 * z).
                set_el(expmods_and_points, 38, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[26] = -(g^30 * z).
                set_el(expmods_and_points, 39, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[27] = -(g^32 * z).
                set_el(expmods_and_points, 40, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[28] = -(g^33 * z).
                set_el(expmods_and_points, 41, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[29] = -(g^38 * z).
                set_el(expmods_and_points, 42, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[30] = -(g^39 * z).
                set_el(expmods_and_points, 43, point);

                // point *= g^3.
                point = mod_mul(point, tg3, prime);
                // expmods_and_points.points[31] = -(g^42 * z).
                set_el(expmods_and_points, 44, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[32] = -(g^43 * z).
                set_el(expmods_and_points, 45, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[33] = -(g^44 * z).
                set_el(expmods_and_points, 46, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[34] = -(g^49 * z).
                set_el(expmods_and_points, 47, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[35] = -(g^53 * z).
                set_el(expmods_and_points, 48, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[36] = -(g^54 * z).
                set_el(expmods_and_points, 49, point);

                // point *= g^3.
                point = mod_mul(point, tg3, prime);
                // expmods_and_points.points[37] = -(g^57 * z).
                set_el(expmods_and_points, 50, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[38] = -(g^58 * z).
                set_el(expmods_and_points, 51, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                set_el(expmods_and_points, 52, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[40] = -(g^61 * z).
                set_el(expmods_and_points, 53, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[41] = -(g^62 * z).
                set_el(expmods_and_points, 54, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[42] = -(g^64 * z).
                set_el(expmods_and_points, 55, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[43] = -(g^65 * z).
                set_el(expmods_and_points, 56, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[44] = -(g^70 * z).
                set_el(expmods_and_points, 57, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[45] = -(g^71 * z).
                set_el(expmods_and_points, 58, point);

                // point *= g^3.
                point = mod_mul(point, tg3, prime);
                // expmods_and_points.points[46] = -(g^74 * z).
                set_el(expmods_and_points, 59, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[47] = -(g^75 * z).
                set_el(expmods_and_points, 60, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[48] = -(g^76 * z).
                set_el(expmods_and_points, 61, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[49] = -(g^77 * z).
                set_el(expmods_and_points, 62, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[50] = -(g^78 * z).
                set_el(expmods_and_points, 63, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[51] = -(g^79 * z).
                set_el(expmods_and_points, 64, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[52] = -(g^81 * z).
                set_el(expmods_and_points, 65, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[53] = -(g^83 * z).
                set_el(expmods_and_points, 66, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[54] = -(g^85 * z).
                set_el(expmods_and_points, 67, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[55] = -(g^86 * z).
                set_el(expmods_and_points, 68, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[56] = -(g^87 * z).
                set_el(expmods_and_points, 69, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[57] = -(g^88 * z).
                set_el(expmods_and_points, 70, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[58] = -(g^89 * z).
                set_el(expmods_and_points, 71, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[59] = -(g^90 * z).
                set_el(expmods_and_points, 72, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[60] = -(g^91 * z).
                set_el(expmods_and_points, 73, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[61] = -(g^92 * z).
                set_el(expmods_and_points, 74, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[62] = -(g^94 * z).
                set_el(expmods_and_points, 75, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[63] = -(g^96 * z).
                set_el(expmods_and_points, 76, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[64] = -(g^97 * z).
                set_el(expmods_and_points, 77, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[65] = -(g^102 * z).
                set_el(expmods_and_points, 78, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[66] = -(g^103 * z).
                set_el(expmods_and_points, 79, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[67] = -(g^108 * z).
                set_el(expmods_and_points, 80, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[68] = -(g^113 * z).
                set_el(expmods_and_points, 81, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                    // expmods_and_points.points[69] = -(g^117 * z).
                set_el(expmods_and_points, 82, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[70] = -(g^118 * z).
                set_el(expmods_and_points, 83, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[71] = -(g^120 * z).
                set_el(expmods_and_points, 84, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[72] = -(g^121 * z).
                set_el(expmods_and_points, 85, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[73] = -(g^122 * z).
                set_el(expmods_and_points, 86, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[74] = -(g^123 * z).
                set_el(expmods_and_points, 87, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[75] = -(g^124 * z).
                set_el(expmods_and_points, 88, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[76] = -(g^125 * z).
                set_el(expmods_and_points, 89, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[77] = -(g^126 * z).
                set_el(expmods_and_points, 90, point);

                // point *= g^28.
                point = mod_mul(point, tg28, prime);
                // expmods_and_points.points[78] = -(g^154 * z).
                set_el(expmods_and_points, 91, point);

                // point *= g^48.
                point = mod_mul(point, tg48, prime);
                // expmods_and_points.points[79] = -(g^202 * z).
                set_el(expmods_and_points, 92, point);

                // point *= g^320.
                point = mod_mul(point, tg320, prime);
                // expmods_and_points.points[80] = -(g^522 * z).
                set_el(expmods_and_points, 93, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[81] = -(g^523 * z).
                set_el(expmods_and_points, 94, point);

                // point *= g^245.
                point = mod_mul(point, tg245, prime);
                // expmods_and_points.points[82] = -(g^768 * z).
                set_el(expmods_and_points, 95, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[83] = -(g^772 * z).
                set_el(expmods_and_points, 96, point);

                // point *= g^12.
                point = mod_mul(point, tg12, prime);
                // expmods_and_points.points[84] = -(g^784 * z).
                set_el(expmods_and_points, 97, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[85] = -(g^788 * z).
                set_el(expmods_and_points, 98, point);

                // point *= g^216.
                point = mod_mul(point, tg216, prime);
                // expmods_and_points.points[86] = -(g^1004 * z).
                set_el(expmods_and_points, 99, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[87] = -(g^1008 * z).
                set_el(expmods_and_points, 100, point);

                // point *= g^13.
                point = mod_mul(point, tg13, prime);
                // expmods_and_points.points[88] = -(g^1021 * z).
                set_el(expmods_and_points, 101, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[89] = -(g^1022 * z).
                set_el(expmods_and_points, 102, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[90] = -(g^1023 * z).
                set_el(expmods_and_points, 103, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[91] = -(g^1024 * z).
                set_el(expmods_and_points, 104, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[92] = -(g^1025 * z).
                set_el(expmods_and_points, 105, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[93] = -(g^1027 * z).
                set_el(expmods_and_points, 106, point);

                // point *= g^7.
                point = mod_mul(point, tg7, prime);
                // expmods_and_points.points[94] = -(g^1034 * z).
                set_el(expmods_and_points, 107, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[95] = -(g^1035 * z).
                set_el(expmods_and_points, 108, point);

                // point *= g^1010.
                point = mod_mul(point, tg1010, prime);
                // expmods_and_points.points[96] = -(g^2045 * z).
                set_el(expmods_and_points, 109, point);

                // point *= g^13.
                point = mod_mul(point, tg13, prime);
                // expmods_and_points.points[97] = -(g^2058 * z).
                set_el(expmods_and_points, 110, point);
            };

            let eval_points_ptr = /*oodseval_points*/ MM_OODS_EVAL_POINTS();
            let eval_points_end_ptr = eval_points_ptr + (*borrow(ctx, MM_N_UNIQUE_QUERIES()) as u64);

            // The batchInverseArray is split into two halves.
            // The first half is used for cumulative products and the second half for values to invert.
            // Consequently the products and values are half the array size apart.
            let products_ptr = 0;
            // Compute an offset in bytes to the middle of the array.
            let products_to_values_offset = length(batch_inverse_array) >> 1;
            let values_ptr = products_ptr + products_to_values_offset;
            let partial_product = 1;
            let minus_point_pow = sub(prime, mod_mul(oods_point, oods_point, prime));
            for (eval_points_ptr in eval_points_ptr..eval_points_end_ptr) {
                let eval_point = *borrow(ctx, eval_points_ptr);

                // Shift eval_point to evaluation domain coset.
                let shifted_eval_point = mod_mul(eval_point, eval_coset_offset_, prime);

                for (offset in 13..111) {
                    let denominator = add(shifted_eval_point, *borrow(expmods_and_points, offset));
                    set_el(batch_inverse_array, products_ptr + offset - 13, partial_product);
                    set_el(batch_inverse_array, values_ptr + offset - 13, denominator);
                    partial_product = mod_mul(partial_product, denominator, prime);
                };

                {
                    // Calculate the denominator for the composition polynomial columns: x - z^2.
                    let denominator = add(shifted_eval_point, minus_point_pow);
                    set_el(batch_inverse_array, products_ptr + 98, partial_product);
                    set_el(batch_inverse_array, values_ptr + 98, denominator);
                    partial_product = mod_mul(partial_product, denominator, prime);
                };

                // Add eval_point to batch inverse inputs.
                // inverse(eval_point) is going to be used by FRI.
                set_el(batch_inverse_array, products_ptr + 99, partial_product);
                set_el(batch_inverse_array, values_ptr + 99, eval_point);
                partial_product = mod_mul(partial_product, eval_point, prime);

                // Advance pointers.
                products_ptr = products_ptr + 100;
                values_ptr = values_ptr + 100;
            };

            let first_partial_product_ptr = 0;
            // Compute the inverse of the product.
            let prod_inv = mod_exp(partial_product, prime - 2, prime);

            assert!(prod_inv != 0, BATCH_INVERSE_PRODUCT_IS_ZERO);

            // Compute the inverses.
            // Loop over denominator_invs in reverse order.
            // currentpartial_productPtr is initialized to one past the end.
            let current_partial_product_ptr = products_ptr;
            // Loop in blocks of size 8 as much as possible: we can loop over a full block as long as
            // currentpartial_productPtr >= first_partial_product_ptr + 8*0x20, or equivalently,
            // currentpartial_productPtr > first_partial_product_ptr + 7*0x20.
            // We use the latter comparison since there is no >= evm opcode.
            let mid_partial_product_ptr = first_partial_product_ptr + 7;
            while (current_partial_product_ptr > mid_partial_product_ptr) {
                for (_i in 0..8) {
                    current_partial_product_ptr = current_partial_product_ptr - 1;
                    // Store 1/d_{i} = (d_0 * ... * d_{i-1}) * 1/(d_0 * ... * d_{i}).
                    let tmp = mod_mul(*borrow(batch_inverse_array, current_partial_product_ptr), prod_inv, prime);
                    set_el(batch_inverse_array, current_partial_product_ptr, tmp);

                    // Update prodInv to be 1/(d_0 * ... * d_{i-1}) by multiplying by d_i.
                    prod_inv = mod_mul(
                        prod_inv,
                        *borrow(batch_inverse_array, current_partial_product_ptr + products_to_values_offset),
                        prime
                    );
                };
            };

            // Loop over the remainder.
            while (current_partial_product_ptr > first_partial_product_ptr) {
                current_partial_product_ptr = current_partial_product_ptr - 1;
                // Store 1/d_{i} = (d_0 * ... * d_{i-1}) * 1/(d_0 * ... * d_{i}).
                let tmp = mod_mul(*borrow(batch_inverse_array, current_partial_product_ptr), prod_inv, prime);
                set_el(batch_inverse_array, current_partial_product_ptr, tmp);

                // Update prodInv to be 1/(d_0 * ... * d_{i-1}) by multiplying by d_i.
                prod_inv = mod_mul(
                    prod_inv,
                    *borrow(batch_inverse_array, current_partial_product_ptr + products_to_values_offset),
                    prime
                );
            };
        };
    }

    // assertion codes
    const BATCH_INVERSE_PRODUCT_IS_ZERO: u64 = 1;
}