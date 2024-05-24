module verifier_addr::fri_transform {
    use aptos_std::table::{Self, Table, new, borrow};
    use verifier_addr::prime_field_element_0::{k_modulus, fmul, fadd};
    use verifier_addr::prime_field_element_0;
    use lib_addr::memory::{Memory, mload};

    #[test_only]
    use aptos_std::debug;
    use std::bcs::to_bytes;
    use std::bcs;
    use aptos_std::debug::print;
    use aptos_std::table::{upsert, borrow_mut};


    const FRI_MIN_STEP_SIZE: u256 = 2;
    const FRI_MAX_STEP_SIZE: u256 = 4;

    const K_MODULUS_TIMES_16: u256 = 0x8000000000000110000000000000000000000000000000000000000000000010;

    public fun fri_max_step_size(): u256 {
        FRI_MAX_STEP_SIZE
    }



    public fun transform_coset(
        memory: &mut Memory,
        fri_half_inv_group_prt: u256,
        evaluations_on_coset_ptr: u256,
        coset_off_set: u256,
        fri_eval_point: u256,
        fri_coset_size: u256
    ): (u256, u256) {
        if (fri_coset_size == 8) {
            transform_coset_of_size_8(
                memory,
                fri_half_inv_group_prt,
                evaluations_on_coset_ptr,
                coset_off_set,
                fri_eval_point
            )
        } else if (fri_coset_size == 4) {
            transform_coset_of_size_4(
                memory,
                fri_half_inv_group_prt,
                evaluations_on_coset_ptr,
                coset_off_set,
                fri_eval_point
            )
        } else {
            transform_coset_of_size_16(
                memory,
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
        memory: &mut Memory,
        fri_half_inv_group_prt: u256,
        evaluations_on_coset_ptr: u256,
        coset_off_set: u256,
        fri_eval_point: u256
    ): (u256, u256) {
        let fri_eval_point_div_by_x = fmul(
            fri_eval_point,
            coset_off_set
        );

        let f0 = mload(memory, evaluations_on_coset_ptr);

        let f1 = mload(memory, evaluations_on_coset_ptr + 0x20);
        // f0 < 3P ( = 1 + 1 + 1).
        f0 = (f0 + f1 + fmul(
            fri_eval_point_div_by_x,
            f0 + (k_modulus() - f1)
        ));

        let f2 = mload(memory, evaluations_on_coset_ptr + 0x40);
        let f3 = mload(memory, evaluations_on_coset_ptr + 0x60);

        f2 = (f2 + f3 + fmul(
            f2 + (k_modulus() - f3),
            fmul(mload(memory, fri_half_inv_group_prt + 0x20), fri_eval_point_div_by_x)
        )) % k_modulus();

        let new_x_inv = fmul(coset_off_set, coset_off_set);
        let next_x_inx = fmul(new_x_inv, new_x_inv);
        let next_layer_value = (f0 + f2 + fmul(
            fmul(fri_eval_point_div_by_x, fri_eval_point_div_by_x),
            f0 + (k_modulus() - f2)
        )) % k_modulus();

        (next_layer_value, next_x_inx)
    }


    /*
      Applies 4 + 2 + 1 FRI transformations to a coset of size 2^3.

      For more detail, see description of the FRI transformations at the top of this file.
    */
    fun transform_coset_of_size_8(
        memory: &mut Memory,
        fri_half_inv_group_prt: u256,
        evaluations_on_coset_ptr: u256,
        coset_off_set: u256,
        fri_eval_point: u256
    ): (u256, u256) {
        let f0 = mload(memory, evaluations_on_coset_ptr);
        // print(&f0);

        let fri_eval_point_div_by_x = fmul(
            fri_eval_point,
            coset_off_set
        );

        let fri_eval_point_div_by_x_squared = fmul(
            fri_eval_point_div_by_x,
            fri_eval_point_div_by_x
        );

        let imaginary_unit = mload(memory, fri_half_inv_group_prt + 0x20);


        let f1 = mload(memory, evaluations_on_coset_ptr + 0x20);
        f0 = (f0 + f1 + fmul(
            fri_eval_point_div_by_x,
            f0 + (k_modulus() - f1)));


        let f2 = mload(memory, evaluations_on_coset_ptr + 0x40);
        let f3 = mload(memory, evaluations_on_coset_ptr + 0x60);
        f2 = (f2 + f3 + fmul(
            f2 + (k_modulus() - f3),
            fmul(fri_eval_point_div_by_x, imaginary_unit)
        ));


        f0 = (f0 + f2 + fmul(
            fri_eval_point_div_by_x_squared,
            f0 + (K_MODULUS_TIMES_16 - f2)));


        let f4 = mload(memory, evaluations_on_coset_ptr + 0x80);
        let fri_eval_point_div_by_x2 = fmul(
            fri_eval_point_div_by_x,
            mload(memory, fri_half_inv_group_prt + 0x40));

        let f5 = mload(memory, evaluations_on_coset_ptr + 0xa0);

        f4 = (f4 + f5 + fmul(
            f4 + (k_modulus() - f5),
            fri_eval_point_div_by_x2));

        let f6 = mload(memory, evaluations_on_coset_ptr + 0xc0);
        let f7 = mload(memory, evaluations_on_coset_ptr + 0xe0);

        f6 = (f6 + f7 + fmul(
            f6 + (k_modulus() - f7),
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
        ) % k_modulus();

        let x_Inv2 = fmul(coset_off_set, coset_off_set);
        let x_Inv4 = fmul(x_Inv2, x_Inv2);
        let next_x_Inv = fmul(x_Inv4, x_Inv4);
        (next_layer_value, next_x_Inv)
    }

    fun transform_coset_of_size_16(
        memory: &mut Memory,
        fri_half_inv_group_prt: u256,
        evaluations_on_coset_ptr: u256,
        coset_off_set: u256,
        fri_eval_point: u256
    ): (u256, u256) {
        let f0 = mload(memory, evaluations_on_coset_ptr);

        let fri_eval_point_div_by_x = fmul(
            fri_eval_point,
            coset_off_set
        );
        let imaginary_unit = mload(memory, fri_half_inv_group_prt + 0x20);

        let f1 = mload(memory, evaluations_on_coset_ptr + 0x20);
        f0 = (f0 + f1 + fmul(
            fri_eval_point_div_by_x,
            f0 + (k_modulus() - f1)
        ));

        let f2 = mload(memory, evaluations_on_coset_ptr + 0x40);
        let f3 = mload(memory, evaluations_on_coset_ptr + 0x60);

        f2 = (f2 + f3 + fmul(
            f2 + (k_modulus() - f3),
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

        let f4 = mload(memory, evaluations_on_coset_ptr + 0x80);
        let fri_eval_point_div_by_x2 = fmul(
            fri_eval_point_div_by_x,
            mload(memory, fri_half_inv_group_prt + 0x40)
        );

        let f5 = mload(memory, evaluations_on_coset_ptr + 0xa0);
        // f4 < 3P ( = 1 + 1 + 1).
        f4 = (f4 + f5 + fmul(
            f4 + (k_modulus() - f5),
            fri_eval_point_div_by_x2
        ));

        let f6 = mload(memory, evaluations_on_coset_ptr + 0xc0);
        let f7 = mload(memory, evaluations_on_coset_ptr + 0xe0);
        // f6 < 3P ( = 1 + 1 + 1).
        f6 = (f6 + f7 + fmul(
            f6 + (k_modulus() - f7),
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

        let f8 = mload(memory, evaluations_on_coset_ptr + 0x100);
        let fri_eval_point_div_by_x4 = fmul(
            fri_eval_point_div_by_x,
            mload(memory, fri_half_inv_group_prt + 0x80)
        );
        let f9 = mload(memory, evaluations_on_coset_ptr + 0x120);
        // f8 < 3P ( = 1 + 1 + 1).
        f8 = (f8 + f9 + fmul(
            f8 + (k_modulus() - f9),
            fri_eval_point_div_by_x4
        ));
        let f10 = mload(memory, evaluations_on_coset_ptr + 0x140);
        let f11 = mload(memory, evaluations_on_coset_ptr + 0x160);
        // f10 < 3P ( = 1 + 1 + 1).
        f10 = (f10 + f11 + fmul(
            f10 + (k_modulus() - f11),
            fmul(fri_eval_point_div_by_x4, imaginary_unit)
        ));

        // f8 < 7P ( = 3 + 3 + 1).
        f8 = (f8 + f10 + fmul(
            fmul(fri_eval_point_div_by_x4, fri_eval_point_div_by_x4),
            f8 + (K_MODULUS_TIMES_16 - f10)
        ));

        let f12 = mload(memory, evaluations_on_coset_ptr + 0x180);
        let fri_eval_point_div_by_x6 = fmul(
            fri_eval_point_div_by_x,
            mload(memory, fri_half_inv_group_prt + 0xc0)
        );
        let f13 = mload(memory, evaluations_on_coset_ptr + 0x1a0);
        // f12 < 3P ( = 1 + 1 + 1).
        f12 = (f12 + f13 + fmul(
            f12 + (k_modulus() - f13),
            fri_eval_point_div_by_x6
        ));
        let f14 = mload(memory, evaluations_on_coset_ptr + 0x1c0);
        let f15 = mload(memory, evaluations_on_coset_ptr + 0x1e0);
        // f14 < 3P ( = 1 + 1 + 1).
        f14 = (f14 + f15 + fmul(
            f14 + (k_modulus() - f15),
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
        )) % k_modulus();

        let x_Inv2 = fmul(coset_off_set, coset_off_set);
        let x_Inv4 = fmul(x_Inv2, x_Inv2);
        let x_Inv8 = fmul(x_Inv4, x_Inv4);
        let next_x_Inv = fmul(x_Inv8, x_Inv8);
        (next_layer_value, next_x_Inv)
    }
}
