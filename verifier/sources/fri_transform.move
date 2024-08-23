module verifier_addr::fri_transform {
    use std::vector;

    use lib_addr::prime_field_element_0::fmul;

    // This line is used for generating constants DO NOT REMOVE!
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // 57896044618658099419157164529521121689969715445305547199569472898173952327696
    const K_MODULUS_TIMES_16: u256 = 0x8000000000000110000000000000000000000000000000000000000000000010;
    // End of generating constants!

    public fun transform_coset(
        fri: &mut vector<u256>,
        fri_half_inv_group_prt: u64,
        evaluations_on_coset_ptr: u64,
        coset_off_set: u256,
        fri_eval_point: u256,
        fri_coset_size: u64
    ): (u256, u256) {
        if (fri_coset_size == 8) {
            transform_coset_of_size_8(
                fri,
                fri_half_inv_group_prt,
                evaluations_on_coset_ptr,
                coset_off_set,
                fri_eval_point
            )
        } else if (fri_coset_size == 4) {
            transform_coset_of_size_4(
                fri,
                fri_half_inv_group_prt,
                evaluations_on_coset_ptr,
                coset_off_set,
                fri_eval_point
            )
        } else {
            transform_coset_of_size_16(
                fri,
                fri_half_inv_group_prt,
                evaluations_on_coset_ptr,
                coset_off_set,
                fri_eval_point
            )
        }
    }

    /*
      Applies 2 + 1 FRI transformations to a coset of size 2^2.

      evaluations on coset:                    f0 f1  f2 f3
      ----------------------------------------  \ / -- \ / -----------
                                                 f0    f2
      ------------------------------------------- \ -- / -------------
      nextLayerValue:                               f0

    */
    fun transform_coset_of_size_4(
        fri: &mut vector<u256>,
        fri_half_inv_group_ptr: u64,
        evaluations_on_coset_ptr: u64,
        coset_off_set: u256,
        fri_eval_point: u256
    ): (u256, u256) {
        let fri_eval_point_div_by_x = fmul(
            fri_eval_point,
            coset_off_set
        );

        let f0 = *vector::borrow(fri, evaluations_on_coset_ptr);

        let f1 = *vector::borrow(fri, evaluations_on_coset_ptr + 1);
        // f0 < 3P ( = 1 + 1 + 1).
        f0 = (f0 + f1 + fmul(
            fri_eval_point_div_by_x,
            f0 + (K_MODULUS - f1)
        ));

        let f2 = *vector::borrow(fri, evaluations_on_coset_ptr + 2);
        let f3 = *vector::borrow(fri, evaluations_on_coset_ptr + 3);

        f2 = (f2 + f3 + fmul(
            f2 + (K_MODULUS - f3),
            fmul(*vector::borrow(fri, fri_half_inv_group_ptr + 1), fri_eval_point_div_by_x)
        )) % K_MODULUS;

        let new_x_inv = fmul(coset_off_set, coset_off_set);
        let next_x_inx = fmul(new_x_inv, new_x_inv);
        let next_layer_value = (f0 + f2 + fmul(
            fmul(fri_eval_point_div_by_x, fri_eval_point_div_by_x),
            f0 + (K_MODULUS - f2)
        )) % K_MODULUS;

        (next_layer_value, next_x_inx)
    }


    /*
      Applies 4 + 2 + 1 FRI transformations to a coset of size 2^3.

      For more detail, see description of the FRI transformations at the top of this file.
    */
    fun transform_coset_of_size_8(
        fri: &mut vector<u256>,
        fri_half_inv_group_prt: u64,
        evaluations_on_coset_ptr: u64,
        coset_off_set: u256,
        fri_eval_point: u256
    ): (u256, u256) {
        let f0 = *vector::borrow(fri, evaluations_on_coset_ptr);

        let fri_eval_point_div_by_x = fmul(
            fri_eval_point,
            coset_off_set
        );

        let fri_eval_point_div_by_x_squared = fmul(
            fri_eval_point_div_by_x,
            fri_eval_point_div_by_x
        );

        let imaginary_unit = *vector::borrow(fri, fri_half_inv_group_prt + 1) ;


        let f1 = *vector::borrow(fri, evaluations_on_coset_ptr + 1);
        f0 = (f0 + f1 + fmul(
            fri_eval_point_div_by_x,
            f0 + (K_MODULUS - f1)));


        let f2 = *vector::borrow(fri, evaluations_on_coset_ptr + 2);
        let f3 = *vector::borrow(fri, evaluations_on_coset_ptr + 3);
        f2 = (f2 + f3 + fmul(
            f2 + (K_MODULUS - f3),
            fmul(fri_eval_point_div_by_x, imaginary_unit)
        ));


        f0 = (f0 + f2 + fmul(
            fri_eval_point_div_by_x_squared,
            f0 + (K_MODULUS_TIMES_16 - f2)));


        let f4 = *vector::borrow(fri, evaluations_on_coset_ptr + 4);
        let fri_eval_point_div_by_x2 = fmul(
            fri_eval_point_div_by_x,
            *vector::borrow(fri, fri_half_inv_group_prt + 2));

        let f5 = *vector::borrow(fri, evaluations_on_coset_ptr + 5) ;

        f4 = (f4 + f5 + fmul(
            f4 + (K_MODULUS - f5),
            fri_eval_point_div_by_x2));

        let f6 = *vector::borrow(fri, evaluations_on_coset_ptr + 6);
        let f7 = *vector::borrow(fri, evaluations_on_coset_ptr + 7);

        f6 = (f6 + f7 + fmul(
            f6 + (K_MODULUS - f7),
            fmul(fri_eval_point_div_by_x2, imaginary_unit)
        ));

        f4 = (f4 + f6 + fmul(
            fmul(fri_eval_point_div_by_x2, fri_eval_point_div_by_x2),
            f4 + (K_MODULUS_TIMES_16 - f6)
        ));

        let next_layer_value = (
            f0 + f4
                + fmul(
                fmul(fri_eval_point_div_by_x_squared, fri_eval_point_div_by_x_squared),
                f0 + (K_MODULUS_TIMES_16 - f4)
            )
        ) % K_MODULUS;

        let x_Inv2 = fmul(coset_off_set, coset_off_set);
        let x_Inv4 = fmul(x_Inv2, x_Inv2);
        let next_x_Inv = fmul(x_Inv4, x_Inv4);
        (next_layer_value, next_x_Inv)
    }

    fun transform_coset_of_size_16(
        fri: &mut vector<u256>,
        fri_half_inv_group_ptr: u64,
        evaluations_on_coset_ptr: u64,
        coset_off_set: u256,
        fri_eval_point: u256
    ): (u256, u256) {
        let f0 = *vector::borrow(fri, evaluations_on_coset_ptr);

        let fri_eval_point_div_by_x = fmul(
            fri_eval_point,
            coset_off_set
        );
        let imaginary_unit = *vector::borrow(fri, fri_half_inv_group_ptr + 1);

        let f1 = *vector::borrow(fri, evaluations_on_coset_ptr + 1);
        f0 = (f0 + f1 + fmul(
            fri_eval_point_div_by_x,
            f0 + (K_MODULUS - f1)
        ));

        let f2 = *vector::borrow(fri, evaluations_on_coset_ptr + 2);
        let f3 = *vector::borrow(fri, evaluations_on_coset_ptr + 3);

        f2 = (f2 + f3 + fmul(
            f2 + (K_MODULUS - f3),
            fmul(fri_eval_point_div_by_x, imaginary_unit)
        ));

        let fri_eval_point_div_by_x_squared = fmul(
            fri_eval_point_div_by_x,
            fri_eval_point_div_by_x
        );
        let fri_eval_point_div_by_x_tessed = fmul(
            fri_eval_point_div_by_x_squared,
            fri_eval_point_div_by_x_squared
        );

        f0 = (f0 + f2 + fmul(
            fri_eval_point_div_by_x_squared,
            f0 + (K_MODULUS_TIMES_16 - f2)
        ));

        let f4 = *vector::borrow(fri, evaluations_on_coset_ptr + 4);
        let fri_eval_point_div_by_x2 = fmul(
            fri_eval_point_div_by_x,
            *vector::borrow(fri, fri_half_inv_group_ptr + 2)
        );

        let f5 = *vector::borrow(fri, evaluations_on_coset_ptr + 5);
        // f4 < 3P ( = 1 + 1 + 1).
        f4 = (f4 + f5 + fmul(
            f4 + (K_MODULUS - f5),
            fri_eval_point_div_by_x2
        ));

        let f6 = *vector::borrow(fri, evaluations_on_coset_ptr + 6);
        let f7 = *vector::borrow(fri, evaluations_on_coset_ptr + 7) ;
        // f6 < 3P ( = 1 + 1 + 1).
        f6 = (f6 + f7 + fmul(
            f6 + (K_MODULUS - f7),
            fmul(fri_eval_point_div_by_x2, imaginary_unit)
        ));
        // f4 < 7P ( = 3 + 3 + 1).
        f4 = (f4 + f6 + fmul(
            fmul(fri_eval_point_div_by_x2, fri_eval_point_div_by_x2),
            f4 + (K_MODULUS_TIMES_16 - f6)
        ));

        // f0 < 15P ( = 7 + 7 + 1).
        f0 = (f0 + f4 + fmul(
            fri_eval_point_div_by_x_tessed,
            f0 + (K_MODULUS_TIMES_16 - f4)
        ));

        let f8 = *vector::borrow(fri, evaluations_on_coset_ptr + 8);
        let fri_eval_point_div_by_x4 = fmul(
            fri_eval_point_div_by_x,
            *vector::borrow(fri, fri_half_inv_group_ptr + 4)
        );
        let f9 = *vector::borrow(fri, evaluations_on_coset_ptr + 9) ;
        // f8 < 3P ( = 1 + 1 + 1).
        f8 = (f8 + f9 + fmul(
            f8 + (K_MODULUS - f9),
            fri_eval_point_div_by_x4
        ));
        let f10 = *vector::borrow(fri, evaluations_on_coset_ptr + 10);
        let f11 = *vector::borrow(fri, evaluations_on_coset_ptr + 11);
        // f10 < 3P ( = 1 + 1 + 1).
        f10 = (f10 + f11 + fmul(
            f10 + (K_MODULUS - f11),
            fmul(fri_eval_point_div_by_x4, imaginary_unit)
        ));

        // f8 < 7P ( = 3 + 3 + 1).
        f8 = (f8 + f10 + fmul(
            fmul(fri_eval_point_div_by_x4, fri_eval_point_div_by_x4),
            f8 + (K_MODULUS_TIMES_16 - f10)
        ));

        let f12 = *vector::borrow(fri, evaluations_on_coset_ptr + 12);
        let fri_eval_point_div_by_x6 = fmul(
            fri_eval_point_div_by_x,
            *vector::borrow(fri, fri_half_inv_group_ptr + 6)
        );
        let f13 = *vector::borrow(fri, evaluations_on_coset_ptr + 13);
        // f12 < 3P ( = 1 + 1 + 1).
        f12 = (f12 + f13 + fmul(
            f12 + (K_MODULUS - f13),
            fri_eval_point_div_by_x6
        ));
        let f14 = *vector::borrow(fri, evaluations_on_coset_ptr + 14);
        let f15 = *vector::borrow(fri, evaluations_on_coset_ptr + 15);
        // f14 < 3P ( = 1 + 1 + 1).
        f14 = (f14 + f15 + fmul(
            f14 + (K_MODULUS - f15),
            fmul(fri_eval_point_div_by_x6, imaginary_unit)
        ));
        // f12 < 7P ( = 3 + 3 + 1).
        f12 = (f12 + f14 + fmul(
            fmul(fri_eval_point_div_by_x6, fri_eval_point_div_by_x6),
            f12 + (K_MODULUS_TIMES_16 - f14)
        ));

        // f8 < 15P ( = 7 + 7 + 1).
        f8 = (f8 + f12 + fmul(
            fmul(fri_eval_point_div_by_x_tessed, fri_eval_point_div_by_x_tessed),
            f8 + (K_MODULUS_TIMES_16 - f12)
        ));

        let next_layer_value = (f0 + f8 + fmul(
            fmul(fri_eval_point_div_by_x_tessed, fri_eval_point_div_by_x_tessed),
            f0 + (K_MODULUS_TIMES_16 - f8)
        )) % K_MODULUS;

        let x_Inv2 = fmul(coset_off_set, coset_off_set);
        let x_Inv4 = fmul(x_Inv2, x_Inv2);
        let x_Inv8 = fmul(x_Inv4, x_Inv4);
        let next_x_Inv = fmul(x_Inv8, x_Inv8);
        (next_layer_value, next_x_Inv)
    }
}
