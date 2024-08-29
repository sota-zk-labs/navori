module verifier_addr::horner_evaluator {
    use std::vector::borrow;

    use lib_addr::prime_field_element_0::fmul;

    // This line is used for generating constants DO NOT REMOVE!
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // End of generating constants!

    /*
      Computes the evaluation of a polynomial f(x) = sum(a_i * x^i) on the given point.
      The coefficients of the polynomial are given in
        a_0 = coefsStart[0], ..., a_{n-1} = coefsStart[n - 1]
      where n = n_coef = friLastLayerDegBound. Note that coefsStart is not actually an array but
      a direct pointer.
      The function requires that n is divisible by 8.
    */
    public fun horner_eval(proof: &vector<u256>, coefs_start: u64, point: u256, n_coef: u64): u256 {
        let result = 0;

        assert!(n_coef % 8 == 0, ENUMBER_OF_POLYNOMIAL_COEFFICIENTS_MUST_BE_DIVISIBLE_BY_8);
        // Ensure 'n_coef' is bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(n_coef < 4096, ENO_MORE_THAN_4096_COEFFICIENTS_ARE_SUPPORTED);

        let coefs_ptr = coefs_start + n_coef;
        while (coefs_ptr > coefs_start) {
            // Reduce coefs_ptr by 8 field elements.
            coefs_ptr = coefs_ptr - 8;

            // Apply 4 Horner steps (result = result * point + coef).
            result = *borrow(proof, coefs_ptr + 4) + fmul(
                *borrow(proof, coefs_ptr + 5) + fmul(
                    *borrow(proof, coefs_ptr + 6) + fmul(
                        *borrow(proof, coefs_ptr + 7) + fmul(result, point),
                        point
                    ),
                    point
                ),
                point
            );

            // Apply 4 additional Horner steps.
            result = *borrow(proof, coefs_ptr) + fmul(
                *borrow(proof, coefs_ptr + 1) + fmul(
                    *borrow(proof, coefs_ptr + 2) + fmul(
                        *borrow(proof, coefs_ptr + 3) + fmul(result, point),
                        point
                    ),
                    point
                ),
                point
            );
        };
        // Since the last operation was "add" (instead of "addmod"), we need to take result % prime.
        result % K_MODULUS
    }

    // assertion codes
    const ENUMBER_OF_POLYNOMIAL_COEFFICIENTS_MUST_BE_DIVISIBLE_BY_8: u64 = 1;
    const ENO_MORE_THAN_4096_COEFFICIENTS_ARE_SUPPORTED: u64 = 2;
}