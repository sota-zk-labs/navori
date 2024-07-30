module verifier_addr::cpu_oods_7 {

    use std::vector::{borrow, length};
    use lib_addr::math_mod::{mod_mul, mod_add, mod_exp};
    use verifier_addr::fri_layer::FRI_QUEUE_SLOT_SIZE;
    use verifier_addr::prime_field_element_0::{k_montgomery_r_inv, k_modulus, generator_val};
    use verifier_addr::vector::{assign, set_el};
    use verifier_addr::memory_map_7::{MM_N_UNIQUE_QUERIES, MM_FRI_QUEUE, MM_TRACE_QUERY_RESPONSES,
        MM_COMPOSITION_QUERY_RESPONSES, MM_OODS_ALPHA, MM_TRACE_GENERATOR, MM_OODS_POINT,
        MM_OODS_EVAL_POINTS
    };

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
    public(friend) fun fallback(ctx: &mut vector<u256>) {
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

            // Mask items for column #0.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses), k_montgomery_r_inv, prime);

                // res += c_i*(f_0(x) - f_0(g^i * z)) / (x - g^i * z).
                // i = 0..15
                for (i in 0..16) {
                    res = add(
                        res,
                        mod_mul(
                            mod_mul(/*(x - g^i * z)^(-1)*/
                                *borrow(&batch_inverse_array, denominators_ptr + i),
                                oods_alpha_pow,
                                prime
                            ),
                            add(column_value, sub(prime, /*oods_values[0]*/ *borrow(ctx, 359 + i))),
                            prime));
                    oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
                }
            };

            // Mask items for column #1.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 1), k_montgomery_r_inv, prime);

                // res += c_16*(f_1(x) - f_1(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[16]*/ *borrow(ctx, 359 + 16))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_17*(f_1(x) - f_1(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[17]*/ *borrow(ctx, 359 + 17))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_18*(f_1(x) - f_1(g^2 * z)) / (x - g^2 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 2),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[18]*/ *borrow(ctx, 359 + 18))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_19*(f_1(x) - f_1(g^4 * z)) / (x - g^4 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^4 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 4),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[19]*/ *borrow(ctx, 359 + 19))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_20*(f_1(x) - f_1(g^6 * z)) / (x - g^6 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^6 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 6),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[20]*/ *borrow(ctx, 359 + 20))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_21*(f_1(x) - f_1(g^8 * z)) / (x - g^8 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^8 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 8),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[21]*/ *borrow(ctx, 359 + 21))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_22*(f_1(x) - f_1(g^10 * z)) / (x - g^10 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^10 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 10),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[22]*/ *borrow(ctx, 359 + 22))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_23*(f_1(x) - f_1(g^12 * z)) / (x - g^12 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^12 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 12),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[23]*/ *borrow(ctx, 359 + 23))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_24*(f_1(x) - f_1(g^14 * z)) / (x - g^14 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^14 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 14),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[24]*/ *borrow(ctx, 359 + 24))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_25*(f_1(x) - f_1(g^16 * z)) / (x - g^16 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^16 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 16),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[25]*/ *borrow(ctx, 359 + 25))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_26*(f_1(x) - f_1(g^18 * z)) / (x - g^18 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^18 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 18),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[26]*/ *borrow(ctx, 359 + 26))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_27*(f_1(x) - f_1(g^20 * z)) / (x - g^20 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^20 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 19),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[27]*/ *borrow(ctx, 359 + 27))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_28*(f_1(x) - f_1(g^22 * z)) / (x - g^22 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^22 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 20),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[28]*/ *borrow(ctx, 359 + 28))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_29*(f_1(x) - f_1(g^24 * z)) / (x - g^24 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^24 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 22),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[29]*/ *borrow(ctx, 359 + 29))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_30*(f_1(x) - f_1(g^26 * z)) / (x - g^26 * z).
                res = mod_add(
                    res,
                    mod_mul(mod_mul(/*(x - g^26 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 23),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[30]*/ *borrow(ctx, 359 + 30))),
                        prime),
                    prime);
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_31*(f_1(x) - f_1(g^28 * z)) / (x - g^28 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^28 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 25),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[31]*/ *borrow(ctx, 359 + 31))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_32*(f_1(x) - f_1(g^30 * z)) / (x - g^30 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^30 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 26),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[32]*/ *borrow(ctx, 359 + 32))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_33*(f_1(x) - f_1(g^32 * z)) / (x - g^32 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^32 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 27),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[33]*/ *borrow(ctx, 359 + 33))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_34*(f_1(x) - f_1(g^33 * z)) / (x - g^33 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^33 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 28),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[34]*/ *borrow(ctx, 359 + 34))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_35*(f_1(x) - f_1(g^64 * z)) / (x - g^64 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^64 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 42),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[35]*/ *borrow(ctx, 359 + 35))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_36*(f_1(x) - f_1(g^65 * z)) / (x - g^65 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^65 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 43),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[36]*/ *borrow(ctx, 359 + 36))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_37*(f_1(x) - f_1(g^88 * z)) / (x - g^88 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^88 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 57),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[37]*/ *borrow(ctx, 359 + 37))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_38*(f_1(x) - f_1(g^90 * z)) / (x - g^90 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^90 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 59),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[38]*/ *borrow(ctx, 359 + 38))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_39*(f_1(x) - f_1(g^92 * z)) / (x - g^92 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^92 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 61),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[39]*/ *borrow(ctx, 359 + 39))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_40*(f_1(x) - f_1(g^94 * z)) / (x - g^94 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^94 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 62),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[40]*/ *borrow(ctx, 359 + 40))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_41*(f_1(x) - f_1(g^96 * z)) / (x - g^96 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^96 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 63),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[41]*/ *borrow(ctx, 359 + 41))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_42*(f_1(x) - f_1(g^97 * z)) / (x - g^97 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^97 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 64),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[42]*/ *borrow(ctx, 359 + 42))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_43*(f_1(x) - f_1(g^120 * z)) / (x - g^120 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^120 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 71),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[43]*/ *borrow(ctx, 359 + 43))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_44*(f_1(x) - f_1(g^122 * z)) / (x - g^122 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^122 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 73),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[44]*/ *borrow(ctx, 359 + 44))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_45*(f_1(x) - f_1(g^124 * z)) / (x - g^124 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^124 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 75),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[45]*/ *borrow(ctx, 359 + 45))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_46*(f_1(x) - f_1(g^126 * z)) / (x - g^126 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^126 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 77),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[46]*/ *borrow(ctx, 359 + 46))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #2.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 2), k_montgomery_r_inv, prime);

                // res += c_47*(f_2(x) - f_2(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[47]*/ *borrow(ctx, 359 + 47))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_48*(f_2(x) - f_2(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[48]*/ *borrow(ctx, 359 + 48))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #3.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 3), k_montgomery_r_inv, prime);

                // res += c_49*(f_3(x) - f_3(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[49]*/ *borrow(ctx, 359 + 49))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_50*(f_3(x) - f_3(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[50]*/ *borrow(ctx, 359 + 50))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_51*(f_3(x) - f_3(g^2 * z)) / (x - g^2 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 2),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[51]*/ *borrow(ctx, 359 + 51))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_52*(f_3(x) - f_3(g^3 * z)) / (x - g^3 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^3 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 3),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[52]*/ *borrow(ctx, 359 + 52))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_53*(f_3(x) - f_3(g^4 * z)) / (x - g^4 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^4 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 4),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[53]*/ *borrow(ctx, 359 + 53))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_54*(f_3(x) - f_3(g^5 * z)) / (x - g^5 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^5 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 5),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[54]*/ *borrow(ctx, 359 + 54))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_55*(f_3(x) - f_3(g^6 * z)) / (x - g^6 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^6 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 6),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[55]*/ *borrow(ctx, 359 + 55))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_56*(f_3(x) - f_3(g^7 * z)) / (x - g^7 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^7 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 7),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[56]*/ *borrow(ctx, 359 + 56))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_57*(f_3(x) - f_3(g^8 * z)) / (x - g^8 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^8 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 8),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[57]*/ *borrow(ctx, 359 + 57))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_58*(f_3(x) - f_3(g^9 * z)) / (x - g^9 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^9 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 9),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[58]*/ *borrow(ctx, 359 + 58))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_59*(f_3(x) - f_3(g^10 * z)) / (x - g^10 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^10 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 10),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[59]*/ *borrow(ctx, 359 + 59))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_60*(f_3(x) - f_3(g^11 * z)) / (x - g^11 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^11 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 11),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[60]*/ *borrow(ctx, 359 + 60))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_61*(f_3(x) - f_3(g^12 * z)) / (x - g^12 * z).
                res = mod_add(
                    res,
                    mod_mul(mod_mul(/*(x - g^12 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 12),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[61]*/ *borrow(ctx, 359 + 61))),
                        prime),
                    prime);
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_62*(f_3(x) - f_3(g^13 * z)) / (x - g^13 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^13 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 13),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[62]*/ *borrow(ctx, 359 + 62))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_63*(f_3(x) - f_3(g^16 * z)) / (x - g^16 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^16 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 16),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[63]*/ *borrow(ctx, 359 + 63))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_64*(f_3(x) - f_3(g^22 * z)) / (x - g^22 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^22 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 20),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[64]*/ *borrow(ctx, 359 + 64))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_65*(f_3(x) - f_3(g^23 * z)) / (x - g^23 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^23 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 21),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[65]*/ *borrow(ctx, 359 + 65))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_66*(f_3(x) - f_3(g^26 * z)) / (x - g^26 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^26 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 23),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[66]*/ *borrow(ctx, 359 + 66))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_67*(f_3(x) - f_3(g^27 * z)) / (x - g^27 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^27 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 24),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[67]*/ *borrow(ctx, 359 + 67))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_68*(f_3(x) - f_3(g^38 * z)) / (x - g^38 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^38 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 29),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[68]*/ *borrow(ctx, 359 + 68))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_69*(f_3(x) - f_3(g^39 * z)) / (x - g^39 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^39 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 30),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[69]*/ *borrow(ctx, 359 + 69))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_70*(f_3(x) - f_3(g^42 * z)) / (x - g^42 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^42 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 31),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[70]*/ *borrow(ctx, 359 + 70))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_71*(f_3(x) - f_3(g^43 * z)) / (x - g^43 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^43 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 32),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[71]*/ *borrow(ctx, 359 + 71))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_72*(f_3(x) - f_3(g^58 * z)) / (x - g^58 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^58 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 38),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[72]*/ *borrow(ctx, 359 + 72))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_73*(f_3(x) - f_3(g^70 * z)) / (x - g^70 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^70 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 44),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[73]*/ *borrow(ctx, 359 + 73))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_74*(f_3(x) - f_3(g^71 * z)) / (x - g^71 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^71 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 45),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[74]*/ *borrow(ctx, 359 + 74))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_75*(f_3(x) - f_3(g^74 * z)) / (x - g^74 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^74 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 46),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[75]*/ *borrow(ctx, 359 + 75))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_76*(f_3(x) - f_3(g^75 * z)) / (x - g^75 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^75 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 47),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[76]*/ *borrow(ctx, 359 + 76))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_77*(f_3(x) - f_3(g^86 * z)) / (x - g^86 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^86 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 55),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[77]*/ *borrow(ctx, 359 + 77))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_78*(f_3(x) - f_3(g^87 * z)) / (x - g^87 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^87 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 56),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[78]*/ *borrow(ctx, 359 + 78))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_79*(f_3(x) - f_3(g^91 * z)) / (x - g^91 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^91 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 60),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[79]*/ *borrow(ctx, 359 + 79))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_80*(f_3(x) - f_3(g^102 * z)) / (x - g^102 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^102 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 65),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[80]*/ *borrow(ctx, 359 + 80))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_81*(f_3(x) - f_3(g^103 * z)) / (x - g^103 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^103 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 66),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[81]*/ *borrow(ctx, 359 + 81))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_82*(f_3(x) - f_3(g^122 * z)) / (x - g^122 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^122 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 73),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[82]*/ *borrow(ctx, 359 + 82))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_83*(f_3(x) - f_3(g^123 * z)) / (x - g^123 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^123 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 74),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[83]*/ *borrow(ctx, 359 + 83))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_84*(f_3(x) - f_3(g^154 * z)) / (x - g^154 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^154 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 78),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[84]*/ *borrow(ctx, 359 + 84))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_85*(f_3(x) - f_3(g^202 * z)) / (x - g^202 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^202 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 79),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[85]*/ *borrow(ctx, 359 + 85))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_86*(f_3(x) - f_3(g^522 * z)) / (x - g^522 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^522 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 80),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[86]*/ *borrow(ctx, 359 + 86))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_87*(f_3(x) - f_3(g^523 * z)) / (x - g^523 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^523 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 81),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[87]*/ *borrow(ctx, 359 + 87))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_88*(f_3(x) - f_3(g^1034 * z)) / (x - g^1034 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1034 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 94),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[88]*/ *borrow(ctx, 359 + 88))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_89*(f_3(x) - f_3(g^1035 * z)) / (x - g^1035 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1035 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 95),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[89]*/ *borrow(ctx, 359 + 89))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_90*(f_3(x) - f_3(g^2058 * z)) / (x - g^2058 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2058 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 97),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[90]*/ *borrow(ctx, 359 + 90))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #4.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 4), k_montgomery_r_inv, prime);

                // res += c_91*(f_4(x) - f_4(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[91]*/ *borrow(ctx, 359 + 91))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_92*(f_4(x) - f_4(g * z)) / (x - g * z).
                res = mod_add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[92]*/ *borrow(ctx, 359 + 92))),
                        prime),
                    prime);
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_93*(f_4(x) - f_4(g^2 * z)) / (x - g^2 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 2),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[93]*/ *borrow(ctx, 359 + 93))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_94*(f_4(x) - f_4(g^3 * z)) / (x - g^3 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^3 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 3),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[94]*/ *borrow(ctx, 359 + 94))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #5.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 5), k_montgomery_r_inv, prime);

                // res += c_95*(f_5(x) - f_5(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[95]*/ *borrow(ctx, 359 + 95))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_96*(f_5(x) - f_5(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[96]*/ *borrow(ctx, 359 + 96))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_97*(f_5(x) - f_5(g^2 * z)) / (x - g^2 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 2),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[97]*/ *borrow(ctx, 359 + 97))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_98*(f_5(x) - f_5(g^3 * z)) / (x - g^3 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^3 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 3),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[98]*/ *borrow(ctx, 359 + 98))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_99*(f_5(x) - f_5(g^4 * z)) / (x - g^4 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^4 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 4),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[99]*/ *borrow(ctx, 359 + 99))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_100*(f_5(x) - f_5(g^5 * z)) / (x - g^5 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^5 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 5),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[100]*/ *borrow(ctx, 359 + 100))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_101*(f_5(x) - f_5(g^6 * z)) / (x - g^6 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^6 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 6),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[101]*/ *borrow(ctx, 359 + 101))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_102*(f_5(x) - f_5(g^122 * z)) / (x - g^122 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^122 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 73),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[102]*/ *borrow(ctx, 359 + 102))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_103*(f_5(x) - f_5(g^124 * z)) / (x - g^124 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^124 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 75),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[103]*/ *borrow(ctx, 359 + 103))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_104*(f_5(x) - f_5(g^126 * z)) / (x - g^126 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^126 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 77),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[104]*/ *borrow(ctx, 359 + 104))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #6.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 6), k_montgomery_r_inv, prime);

                // res += c_105*(f_6(x) - f_6(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[105]*/ *borrow(ctx, 359 + 105))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_106*(f_6(x) - f_6(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[106]*/ *borrow(ctx, 359 + 106))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_107*(f_6(x) - f_6(g^2 * z)) / (x - g^2 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 2),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[107]*/ *borrow(ctx, 359 + 107))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_108*(f_6(x) - f_6(g^3 * z)) / (x - g^3 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^3 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 3),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[108]*/ *borrow(ctx, 359 + 108))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_109*(f_6(x) - f_6(g^4 * z)) / (x - g^4 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^4 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 4),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[109]*/ *borrow(ctx, 359 + 109))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_110*(f_6(x) - f_6(g^5 * z)) / (x - g^5 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^5 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 5),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[110]*/ *borrow(ctx, 359 + 110))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_111*(f_6(x) - f_6(g^6 * z)) / (x - g^6 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^6 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 6),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[111]*/ *borrow(ctx, 359 + 111))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_112*(f_6(x) - f_6(g^7 * z)) / (x - g^7 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^7 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 7),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[112]*/ *borrow(ctx, 359 + 112))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_113*(f_6(x) - f_6(g^8 * z)) / (x - g^8 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^8 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 8),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[113]*/ *borrow(ctx, 359 + 113))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_114*(f_6(x) - f_6(g^12 * z)) / (x - g^12 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^12 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 12),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[114]*/ *borrow(ctx, 359 + 114))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_115*(f_6(x) - f_6(g^28 * z)) / (x - g^28 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^28 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 25),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[115]*/ *borrow(ctx, 359 + 115))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_116*(f_6(x) - f_6(g^44 * z)) / (x - g^44 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^44 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 33),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[116]*/ *borrow(ctx, 359 + 116))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_117*(f_6(x) - f_6(g^60 * z)) / (x - g^60 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^60 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 39),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[117]*/ *borrow(ctx, 359 + 117))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_118*(f_6(x) - f_6(g^76 * z)) / (x - g^76 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^76 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 48),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[118]*/ *borrow(ctx, 359 + 118))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_119*(f_6(x) - f_6(g^92 * z)) / (x - g^92 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^92 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 61),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[119]*/ *borrow(ctx, 359 + 119))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_120*(f_6(x) - f_6(g^108 * z)) / (x - g^108 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^108 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 67),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[120]*/ *borrow(ctx, 359 + 120))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_121*(f_6(x) - f_6(g^124 * z)) / (x - g^124 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^124 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 75),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[121]*/ *borrow(ctx, 359 + 121))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_122*(f_6(x) - f_6(g^1021 * z)) / (x - g^1021 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1021 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 88),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[122]*/ *borrow(ctx, 359 + 122))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_123*(f_6(x) - f_6(g^1023 * z)) / (x - g^1023 * z).
                res = mod_add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1023 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 90),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[123]*/ *borrow(ctx, 359 + 123))),
                        prime),
                    prime);
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_124*(f_6(x) - f_6(g^1025 * z)) / (x - g^1025 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1025 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 92),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[124]*/ *borrow(ctx, 359 + 124))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_125*(f_6(x) - f_6(g^1027 * z)) / (x - g^1027 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1027 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 93),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[125]*/ *borrow(ctx, 359 + 125))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_126*(f_6(x) - f_6(g^2045 * z)) / (x - g^2045 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2045 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 96),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[126]*/ *borrow(ctx, 359 + 126))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #7.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 7), k_montgomery_r_inv, prime);

                // res += c_127*(f_7(x) - f_7(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[127]*/ *borrow(ctx, 359 + 127))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_128*(f_7(x) - f_7(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[128]*/ *borrow(ctx, 359 + 128))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_129*(f_7(x) - f_7(g^2 * z)) / (x - g^2 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 2),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[129]*/ *borrow(ctx, 359 + 129))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_130*(f_7(x) - f_7(g^3 * z)) / (x - g^3 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^3 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 3),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[130]*/ *borrow(ctx, 359 + 130))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_131*(f_7(x) - f_7(g^4 * z)) / (x - g^4 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^4 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 4),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[131]*/ *borrow(ctx, 359 + 131))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_132*(f_7(x) - f_7(g^5 * z)) / (x - g^5 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^5 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 5),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[132]*/ *borrow(ctx, 359 + 132))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_133*(f_7(x) - f_7(g^7 * z)) / (x - g^7 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^7 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 7),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[133]*/ *borrow(ctx, 359 + 133))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_134*(f_7(x) - f_7(g^9 * z)) / (x - g^9 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^9 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 9),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[134]*/ *borrow(ctx, 359 + 134))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_135*(f_7(x) - f_7(g^11 * z)) / (x - g^11 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^11 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 11),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[135]*/ *borrow(ctx, 359 + 135))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_136*(f_7(x) - f_7(g^13 * z)) / (x - g^13 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^13 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 13),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[136]*/ *borrow(ctx, 359 + 136))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_137*(f_7(x) - f_7(g^77 * z)) / (x - g^77 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^77 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 49),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[137]*/ *borrow(ctx, 359 + 137))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_138*(f_7(x) - f_7(g^79 * z)) / (x - g^79 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^79 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 51),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[138]*/ *borrow(ctx, 359 + 138))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_139*(f_7(x) - f_7(g^81 * z)) / (x - g^81 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^81 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 52),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[139]*/ *borrow(ctx, 359 + 139))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_140*(f_7(x) - f_7(g^83 * z)) / (x - g^83 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^83 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 53),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[140]*/ *borrow(ctx, 359 + 140))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_141*(f_7(x) - f_7(g^85 * z)) / (x - g^85 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^85 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 54),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[141]*/ *borrow(ctx, 359 + 141))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_142*(f_7(x) - f_7(g^87 * z)) / (x - g^87 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^87 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 56),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[142]*/ *borrow(ctx, 359 + 142))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_143*(f_7(x) - f_7(g^89 * z)) / (x - g^89 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^89 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 58),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[143]*/ *borrow(ctx, 359 + 143))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_144*(f_7(x) - f_7(g^768 * z)) / (x - g^768 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^768 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 82),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[144]*/ *borrow(ctx, 359 + 144))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_145*(f_7(x) - f_7(g^772 * z)) / (x - g^772 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^772 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 83),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[145]*/ *borrow(ctx, 359 + 145))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_146*(f_7(x) - f_7(g^784 * z)) / (x - g^784 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^784 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 84),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[146]*/ *borrow(ctx, 359 + 146))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_147*(f_7(x) - f_7(g^788 * z)) / (x - g^788 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^788 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 85),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[147]*/ *borrow(ctx, 359 + 147))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_148*(f_7(x) - f_7(g^1004 * z)) / (x - g^1004 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1004 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 86),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[148]*/ *borrow(ctx, 359 + 148))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_149*(f_7(x) - f_7(g^1008 * z)) / (x - g^1008 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1008 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 87),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[149]*/ *borrow(ctx, 359 + 149))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_150*(f_7(x) - f_7(g^1022 * z)) / (x - g^1022 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1022 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 89),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[150]*/ *borrow(ctx, 359 + 150))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_151*(f_7(x) - f_7(g^1024 * z)) / (x - g^1024 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^1024 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 91),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[151]*/ *borrow(ctx, 359 + 151))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #8.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 8), k_montgomery_r_inv, prime);

                // res += c_152*(f_8(x) - f_8(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[152]*/ *borrow(ctx, 359 + 152))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_153*(f_8(x) - f_8(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[153]*/ *borrow(ctx, 359 + 153))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_154*(f_8(x) - f_8(g^2 * z)) / (x - g^2 * z).
                res = mod_add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 2),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[154]*/ *borrow(ctx, 359 + 154))),
                        prime),
                    prime);
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_155*(f_8(x) - f_8(g^4 * z)) / (x - g^4 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^4 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 4),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[155]*/ *borrow(ctx, 359 + 155))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_156*(f_8(x) - f_8(g^5 * z)) / (x - g^5 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^5 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 5),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[156]*/ *borrow(ctx, 359 + 156))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_157*(f_8(x) - f_8(g^6 * z)) / (x - g^6 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^6 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 6),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[157]*/ *borrow(ctx, 359 + 157))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_158*(f_8(x) - f_8(g^8 * z)) / (x - g^8 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^8 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 8),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[158]*/ *borrow(ctx, 359 + 158))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_159*(f_8(x) - f_8(g^9 * z)) / (x - g^9 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^9 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 9),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[159]*/ *borrow(ctx, 359 + 159))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_160*(f_8(x) - f_8(g^10 * z)) / (x - g^10 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^10 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 10),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[160]*/ *borrow(ctx, 359 + 160))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_161*(f_8(x) - f_8(g^12 * z)) / (x - g^12 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^12 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 12),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[161]*/ *borrow(ctx, 359 + 161))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_162*(f_8(x) - f_8(g^13 * z)) / (x - g^13 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^13 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 13),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[162]*/ *borrow(ctx, 359 + 162))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_163*(f_8(x) - f_8(g^14 * z)) / (x - g^14 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^14 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 14),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[163]*/ *borrow(ctx, 359 + 163))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_164*(f_8(x) - f_8(g^16 * z)) / (x - g^16 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^16 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 16),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[164]*/ *borrow(ctx, 359 + 164))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_165*(f_8(x) - f_8(g^17 * z)) / (x - g^17 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^17 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 17),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[165]*/ *borrow(ctx, 359 + 165))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_166*(f_8(x) - f_8(g^22 * z)) / (x - g^22 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^22 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 20),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[166]*/ *borrow(ctx, 359 + 166))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_167*(f_8(x) - f_8(g^24 * z)) / (x - g^24 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^24 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 22),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[167]*/ *borrow(ctx, 359 + 167))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_168*(f_8(x) - f_8(g^30 * z)) / (x - g^30 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^30 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 26),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[168]*/ *borrow(ctx, 359 + 168))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_169*(f_8(x) - f_8(g^49 * z)) / (x - g^49 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^49 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 34),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[169]*/ *borrow(ctx, 359 + 169))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_170*(f_8(x) - f_8(g^53 * z)) / (x - g^53 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^53 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 35),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[170]*/ *borrow(ctx, 359 + 170))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_171*(f_8(x) - f_8(g^54 * z)) / (x - g^54 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^54 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 36),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[171]*/ *borrow(ctx, 359 + 171))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_172*(f_8(x) - f_8(g^57 * z)) / (x - g^57 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^57 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 37),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[172]*/ *borrow(ctx, 359 + 172))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_173*(f_8(x) - f_8(g^61 * z)) / (x - g^61 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^61 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 40),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[173]*/ *borrow(ctx, 359 + 173))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_174*(f_8(x) - f_8(g^62 * z)) / (x - g^62 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^62 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 41),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[174]*/ *borrow(ctx, 359 + 174))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_175*(f_8(x) - f_8(g^65 * z)) / (x - g^65 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^65 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 43),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[175]*/ *borrow(ctx, 359 + 175))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_176*(f_8(x) - f_8(g^70 * z)) / (x - g^70 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^70 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 44),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[176]*/ *borrow(ctx, 359 + 176))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_177*(f_8(x) - f_8(g^78 * z)) / (x - g^78 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^78 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 50),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[177]*/ *borrow(ctx, 359 + 177))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_178*(f_8(x) - f_8(g^113 * z)) / (x - g^113 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^113 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 68),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[178]*/ *borrow(ctx, 359 + 178))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_179*(f_8(x) - f_8(g^117 * z)) / (x - g^117 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^117 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 69),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[179]*/ *borrow(ctx, 359 + 179))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_180*(f_8(x) - f_8(g^118 * z)) / (x - g^118 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^118 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 70),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[180]*/ *borrow(ctx, 359 + 180))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_181*(f_8(x) - f_8(g^121 * z)) / (x - g^121 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^121 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 72),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[181]*/ *borrow(ctx, 359 + 181))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_182*(f_8(x) - f_8(g^125 * z)) / (x - g^125 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^125 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 76),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[182]*/ *borrow(ctx, 359 + 182))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_183*(f_8(x) - f_8(g^126 * z)) / (x - g^126 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^126 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 77),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[183]*/ *borrow(ctx, 359 + 183))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #9.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 9), k_montgomery_r_inv, prime);

                // res += c_184*(f_9(x) - f_9(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[184]*/ *borrow(ctx, 359 + 184))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_185*(f_9(x) - f_9(g * z)) / (x - g * z).
                res = mod_add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[185]*/ *borrow(ctx, 359 + 185))),
                        prime),
                    prime);
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #10.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 10), k_montgomery_r_inv, prime);

                // res += c_186*(f_10(x) - f_10(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[186]*/ *borrow(ctx, 359 + 186))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_187*(f_10(x) - f_10(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[187]*/ *borrow(ctx, 359 + 187))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
            };

            // Mask items for column #11.
            {
                // Read the next element.
                let column_value = mod_mul(*borrow(ctx, trace_query_responses + 11), k_montgomery_r_inv, prime);

                // res += c_188*(f_11(x) - f_11(z)) / (x - z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[188]*/ *borrow(ctx, 359 + 188))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_189*(f_11(x) - f_11(g * z)) / (x - g * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 1),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[189]*/ *borrow(ctx, 359 + 189))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_190*(f_11(x) - f_11(g^2 * z)) / (x - g^2 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^2 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 2),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[190]*/ *borrow(ctx, 359 + 190))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);

                // res += c_191*(f_11(x) - f_11(g^5 * z)) / (x - g^5 * z).
                res = add(
                    res,
                    mod_mul(mod_mul(/*(x - g^5 * z)^(-1)*/ *borrow(&batch_inverse_array, denominators_ptr + 5),
                        oods_alpha_pow,
                        prime),
                        add(column_value, sub(prime, /*oods_values[191]*/ *borrow(ctx, 359 + 191))),
                        prime));
                oods_alpha_pow = mod_mul(oods_alpha_pow, oods_alpha, prime);
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

            // Append the friInvPoint of the current query to the fri_queue array.
            set_el(ctx, fri_queue + 2, *borrow(&batch_inverse_array, denominators_ptr + 99));

            // Advance denominators_ptr by chunk size (0x20 * (2+N_ROWS_IN_MASK)).
            denominators_ptr = denominators_ptr + 100;

            fri_queue = fri_queue + 3;
        }
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
        let evalCosetOffset_ = generator_val();
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
                set_el(expmods_and_points, 74, point);

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
                set_el(expmods_and_points, 82, point);

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
                let shifted_eval_point = mod_mul(eval_point, evalCosetOffset_, prime);

                for (offset in 13..111) {
                    // Calculate denominator for row 0: x - z.
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
                // inverse(eval_point); is going to be used by FRI.
                set_el(batch_inverse_array, products_ptr + 99, partial_product);
                set_el(batch_inverse_array, products_ptr + 99, eval_point);
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
        }
    }

    // assertion codes
    const BATCH_INVERSE_PRODUCT_IS_ZERO: u64 = 1;
}
