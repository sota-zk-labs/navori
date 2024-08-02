module verifier_addr::cpu_oods_7 {
    use std::vector::{borrow, for_each_ref, length, push_back};

    use lib_addr::math_mod::{mod_add, mod_exp, mod_mul};
    use verifier_addr::vector::{assign, set_el};

    // This line is used for generating constants DO NOT REMOVE!
	// 3
	const GENERATOR_VAL: u256 = 0x3;
	// 0x800000000000011000000000000000000000000000000000000000000000001
	const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
	// 0x40000000000001100000000000012100000000000000000000000000000000
	const K_MONTGOMERY_R_INV: u256 = 0x40000000000001100000000000012100000000000000000000000000000000;
	// 3
	const FRI_QUEUE_SLOT_SIZE: u64 = 0x3;
	// 0x9
	const MM_N_UNIQUE_QUERIES: u64 = 0x9;
	// 0x6d
	const MM_FRI_QUEUE: u64 = 0x6d;
	// 0x25a
	const MM_TRACE_QUERY_RESPONSES: u64 = 0x25a;
	// 0x49a
	const MM_COMPOSITION_QUERY_RESPONSES: u64 = 0x49a;
	// 0x259
	const MM_OODS_ALPHA: u64 = 0x259;
	// 0x15e
	const MM_TRACE_GENERATOR: u64 = 0x15e;
	// 0x15f
	const MM_OODS_POINT: u64 = 0x15f;
	// 0x229
	const MM_OODS_EVAL_POINTS: u64 = 0x229;
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
    public fun fallback(ctx: &mut vector<u256>) {
        let n_queries = (*borrow(ctx, MM_N_UNIQUE_QUERIES) as u64);
        let batch_inverse_array = assign(0u256, 2 * n_queries * BATCH_INVERSE_CHUNK);

        oods_prepare_inverses(ctx, &mut batch_inverse_array);

        let prime = K_MODULUS;
        let fri_queue = /*fri_queue*/ MM_FRI_QUEUE;
        let fri_queue_end = fri_queue + n_queries * FRI_QUEUE_SLOT_SIZE;
        let trace_query_responses = /*traceQueryQesponses*/ MM_TRACE_QUERY_RESPONSES;

        let composition_query_responses = /*composition_query_responses*/ MM_COMPOSITION_QUERY_RESPONSES;

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
            let oods_alpha = /*oods_alpha*/ *borrow(ctx, MM_OODS_ALPHA);

            let odds_values_offset = 0;
            for (trace_query_responses_offset in 0..12) {
                // Read the next element.
                let column_value = mod_mul(
                    *borrow(ctx, trace_query_responses + trace_query_responses_offset),
                    K_MONTGOMERY_R_INV,
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
                let column_value = mod_mul(*borrow(ctx, composition_query_responses), K_MONTGOMERY_R_INV, prime);
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
                let column_value = mod_mul(*borrow(ctx, composition_query_responses + 1), K_MONTGOMERY_R_INV, prime);
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
            push_back(expmods_and_points, tg2);

            // expmods_and_points.expmods[1] = trace_generator^3.
            push_back(expmods_and_points, tg3);

            // expmods_and_points.expmods[2] = trace_generator^4.
            push_back(expmods_and_points, tg4);

            // expmods_and_points.expmods[3] = trace_generator^5.
            push_back(expmods_and_points, tg5);

            // expmods_and_points.expmods[4] = trace_generator^7.
            push_back(expmods_and_points, tg7);

            // expmods_and_points.expmods[5] = trace_generator^12.
            push_back(expmods_and_points, tg12);

            // expmods_and_points.expmods[6] = trace_generator^13.
            push_back(expmods_and_points, tg13);

            // expmods_and_points.expmods[7] = trace_generator^28.
            push_back(expmods_and_points, tg28);

            // expmods_and_points.expmods[8] = trace_generator^48.
            push_back(expmods_and_points, tg48);

            // expmods_and_points.expmods[9] = trace_generator^216.
            push_back(expmods_and_points, tg216);

            // expmods_and_points.expmods[10] = trace_generator^245.
            push_back(expmods_and_points, tg245);

            // expmods_and_points.expmods[11] = trace_generator^320.
            push_back(expmods_and_points, tg320);

            // expmods_and_points.expmods[12] = trace_generator^1010.
            push_back(expmods_and_points, tg1010);

            let oods_point = /*oods_point*/ *borrow(ctx, MM_OODS_POINT);
            {
                // point = -z.
                let point = sub(prime, oods_point);
                // Compute denominators for rows with nonconst mask expression.
                // We compute those first because for the const rows we modify the point variable.

                // Compute denominators for rows with const mask expression.

                // expmods_and_points.points[0] = -z.
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[1] = -(g * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[2] = -(g^2 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[3] = -(g^3 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[4] = -(g^4 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[5] = -(g^5 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[6] = -(g^6 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[7] = -(g^7 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[8] = -(g^8 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[9] = -(g^9 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[10] = -(g^10 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[11] = -(g^11 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[12] = -(g^12 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[13] = -(g^13 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[14] = -(g^14 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[15] = -(g^15 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[16] = -(g^16 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[17] = -(g^17 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[18] = -(g^18 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[19] = -(g^20 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[20] = -(g^22 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[21] = -(g^23 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[22] = -(g^24 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[23] = -(g^26 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[24] = -(g^27 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[25] = -(g^28 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[26] = -(g^30 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[27] = -(g^32 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[28] = -(g^33 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[29] = -(g^38 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[30] = -(g^39 * z).
                push_back(expmods_and_points, point);

                // point *= g^3.
                point = mod_mul(point, tg3, prime);
                // expmods_and_points.points[31] = -(g^42 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[32] = -(g^43 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[33] = -(g^44 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[34] = -(g^49 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[35] = -(g^53 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[36] = -(g^54 * z).
                push_back(expmods_and_points, point);

                // point *= g^3.
                point = mod_mul(point, tg3, prime);
                // expmods_and_points.points[37] = -(g^57 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[38] = -(g^58 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[40] = -(g^61 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[41] = -(g^62 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[42] = -(g^64 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[43] = -(g^65 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[44] = -(g^70 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[45] = -(g^71 * z).
                push_back(expmods_and_points, point);

                // point *= g^3.
                point = mod_mul(point, tg3, prime);
                // expmods_and_points.points[46] = -(g^74 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[47] = -(g^75 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[48] = -(g^76 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[49] = -(g^77 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[50] = -(g^78 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[51] = -(g^79 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[52] = -(g^81 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[53] = -(g^83 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[54] = -(g^85 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[55] = -(g^86 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[56] = -(g^87 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[57] = -(g^88 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[58] = -(g^89 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[59] = -(g^90 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[60] = -(g^91 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[61] = -(g^92 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[62] = -(g^94 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[63] = -(g^96 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[64] = -(g^97 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[65] = -(g^102 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[66] = -(g^103 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[67] = -(g^108 * z).
                push_back(expmods_and_points, point);

                // point *= g^5.
                point = mod_mul(point, tg5, prime);
                // expmods_and_points.points[68] = -(g^113 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[69] = -(g^117 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[70] = -(g^118 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[71] = -(g^120 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[72] = -(g^121 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[73] = -(g^122 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[74] = -(g^123 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[75] = -(g^124 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[76] = -(g^125 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[77] = -(g^126 * z).
                push_back(expmods_and_points, point);

                // point *= g^28.
                point = mod_mul(point, tg28, prime);
                // expmods_and_points.points[78] = -(g^154 * z).
                push_back(expmods_and_points, point);

                // point *= g^48.
                point = mod_mul(point, tg48, prime);
                // expmods_and_points.points[79] = -(g^202 * z).
                push_back(expmods_and_points, point);

                // point *= g^320.
                point = mod_mul(point, tg320, prime);
                // expmods_and_points.points[80] = -(g^522 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[81] = -(g^523 * z).
                push_back(expmods_and_points, point);

                // point *= g^245.
                point = mod_mul(point, tg245, prime);
                // expmods_and_points.points[82] = -(g^768 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[83] = -(g^772 * z).
                push_back(expmods_and_points, point);

                // point *= g^12.
                point = mod_mul(point, tg12, prime);
                // expmods_and_points.points[84] = -(g^784 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[85] = -(g^788 * z).
                push_back(expmods_and_points, point);

                // point *= g^216.
                point = mod_mul(point, tg216, prime);
                // expmods_and_points.points[86] = -(g^1004 * z).
                push_back(expmods_and_points, point);

                // point *= g^4.
                point = mod_mul(point, tg4, prime);
                // expmods_and_points.points[87] = -(g^1008 * z).
                push_back(expmods_and_points, point);

                // point *= g^13.
                point = mod_mul(point, tg13, prime);
                // expmods_and_points.points[88] = -(g^1021 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[89] = -(g^1022 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[90] = -(g^1023 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[91] = -(g^1024 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[92] = -(g^1025 * z).
                push_back(expmods_and_points, point);

                // point *= g^2.
                point = mod_mul(point, tg2, prime);
                // expmods_and_points.points[93] = -(g^1027 * z).
                push_back(expmods_and_points, point);

                // point *= g^7.
                point = mod_mul(point, tg7, prime);
                // expmods_and_points.points[94] = -(g^1034 * z).
                push_back(expmods_and_points, point);

                // point *= g.
                point = mod_mul(point, trace_generator, prime);
                // expmods_and_points.points[95] = -(g^1035 * z).
                push_back(expmods_and_points, point);

                // point *= g^1010.
                point = mod_mul(point, tg1010, prime);
                // expmods_and_points.points[96] = -(g^2045 * z).
                push_back(expmods_and_points, point);

                // point *= g^13.
                point = mod_mul(point, tg13, prime);
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