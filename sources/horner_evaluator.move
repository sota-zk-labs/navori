module verifier_addr::horner_evaluator {
    use std::vector::borrow;
    use lib_addr::math_mod::mod_mul;

    // This line is used for generating constants DO NOT REMOVE!
    // 0x800000000000011000000000000000000000000000000000000000000000001
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
        let prime = K_MODULUS;

        assert!(n_coef % 8 == 0, NUMBER_OF_POLYNOMIAL_COEFFICIENTS_MUST_BE_DIVISIBLE_BY_8);
        // Ensure 'n_coef' is bounded as a sanity check (the bound is somewhat arbitrary).
        assert!(n_coef < 4096, NO_MORE_THAN_4096_COEFFICIENTS_ARE_SUPPORTED);

        let coefs_ptr = coefs_start + n_coef;
        while (coefs_ptr > coefs_start) {
            // Reduce coefs_ptr by 8 field elements.
            coefs_ptr = coefs_ptr - 8;

            // Apply 4 Horner steps (result = result * point + coef).
            result = *borrow(proof, coefs_ptr + 4) + mod_mul(
                *borrow(proof, coefs_ptr + 5) + mod_mul(
                    *borrow(proof, coefs_ptr + 6) + mod_mul(
                        *borrow(proof, coefs_ptr + 7) + mod_mul(result, point, prime),
                        point,
                        prime
                    ),
                    point,
                    prime
                ),
                point,
                prime
            );

            // Apply 4 additional Horner steps.
            result = *borrow(proof, coefs_ptr) + mod_mul(
                *borrow(proof, coefs_ptr + 1) + mod_mul(
                    *borrow(proof, coefs_ptr + 2) + mod_mul(
                        *borrow(proof, coefs_ptr + 3) + mod_mul(result, point, prime),
                        point,
                        prime
                    ),
                    point,
                    prime
                ),
                point,
                prime
            );
        };
        // Since the last operation was "add" (instead of "addmod"), we need to take result % prime.
        result % prime
    }

    // assertion codes
    const NUMBER_OF_POLYNOMIAL_COEFFICIENTS_MUST_BE_DIVISIBLE_BY_8: u64 = 1;
    const NO_MORE_THAN_4096_COEFFICIENTS_ARE_SUPPORTED: u64 = 2;
}