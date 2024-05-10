module verifier_addr::fri_transform {
    use aptos_std::table::{Self, Table, new};
    use verifier_addr::prime_field_element_0;


    const FRI_MIN_STEP_SIZE: u256 = 3;
    const FRI_MAX_STEP_SIZE: u256 = 4;

    const K_MODULUS_TIMES_16: u256 = 0x8000000000000110000000000000000000000000000000000000000000000010;
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;

    struct FriTransform has key {
        fri_transform : Table<u256,u256>
    }

    public fun init(signer : &signer) {
        let fri_transform =  new<u256,u256>();
        move_to(signer, FriTransform{fri_transform});
    }

    public fun transform_coset(
        fri_half_inv_group_prt: u256,
        evaluations_on_coset_ptr: u256,
        coset_off_set: u256,
        fri_eval_point: u256,
        fri_coset_size: u256
    ): (u256, u256) acquires FriTransform {
        transform_coset_of_size_8(
            fri_half_inv_group_prt,
            evaluations_on_coset_ptr,
            coset_off_set,
            fri_eval_point
        )
    }

    /*
      Applies 2 + 1 FRI transformations to a coset of size 2^2.

      evaluations on coset:                    f0 f1  f2 f3
      ----------------------------------------  \ / -- \ / -----------
                                                 f0    f2
      ------------------------------------------- \ -- / -------------
      nextLayerValue:                               f0

    */
    /*
      Applies 4 + 2 + 1 FRI transformations to a coset of size 2^3.

      For more detail, see description of the FRI transformations at the top of this file.
    */
    fun transform_coset_of_size_8(
        fri_half_inv_group_prt: u256,
        evaluations_on_coset_ptr: u256,
        coset_off_set: u256,
        fri_eval_point: u256
    ): (u256, u256) acquires FriTransform {
        let fri_transform = &mut borrow_global_mut<FriTransform>(@verifier_addr).fri_transform;
        let f0 = *table::borrow_mut(fri_transform, evaluations_on_coset_ptr);
        let fri_eval_point_div_by_x = prime_field_element_0::fmul(
            fri_eval_point,
            coset_off_set
        );
        let fri_eval_point_div_by_x_squared = prime_field_element_0::fmul(
            fri_eval_point_div_by_x,
            fri_eval_point_div_by_x
        );
        let imaginary_unit = *table::borrow_mut(fri_transform, fri_half_inv_group_prt + 1); // note this

        let f1 =  *table::borrow_mut(fri_transform, evaluations_on_coset_ptr + 1);
        f0 = (f0 + f1 + prime_field_element_0::fmul(fri_eval_point_div_by_x, f0 + (K_MODULUS - f1)));
        let f2 = *table::borrow_mut(fri_transform, evaluations_on_coset_ptr + 2);
        let f3 = *table::borrow_mut(fri_transform, evaluations_on_coset_ptr + 3);
        f2 = (f2 + f3 + prime_field_element_0::fmul(
            f2 + (K_MODULUS - f3),
            prime_field_element_0::fmul(fri_eval_point_div_by_x, imaginary_unit)
        ));
        f0 = (f0 + f2 + prime_field_element_0::fmul(fri_eval_point_div_by_x_squared, f0 + (K_MODULUS_TIMES_16 - f2)));

        let f4 = *table::borrow_mut(fri_transform, evaluations_on_coset_ptr + 4);
        let fri_eval_point_div_by_x2 = prime_field_element_0::fmul(fri_eval_point_div_by_x,  *table::borrow(fri_transform ,fri_half_inv_group_prt+2));
        let f5 = *table::borrow_mut(fri_transform, evaluations_on_coset_ptr + 5);
        f4 = (f4 + f5 + prime_field_element_0::fmul(f4 + (K_MODULUS - f5), fri_eval_point_div_by_x2));

        let f6 = *table::borrow_mut(fri_transform, evaluations_on_coset_ptr + 6);
        let f7 =  *table::borrow_mut(fri_transform, evaluations_on_coset_ptr + 7);
        f6 = (f6 + f7 + prime_field_element_0::fmul(
            f6 + (K_MODULUS - f7),
            prime_field_element_0::fmul(fri_eval_point_div_by_x2, imaginary_unit)
        ));

        f4 = (f4 + f6 + prime_field_element_0::fmul(
            prime_field_element_0::fmul(fri_eval_point_div_by_x2, fri_eval_point_div_by_x2),
            f4 + (K_MODULUS_TIMES_16 - f6)
        ));

        let next_layer_value = (f0 + f4 + prime_field_element_0::fmul(
            prime_field_element_0::fmul(fri_eval_point_div_by_x_squared, fri_eval_point_div_by_x_squared),
            f0 + (K_MODULUS_TIMES_16 - f4)
        ));

        let x_Inv2 = prime_field_element_0::fmul(coset_off_set, coset_off_set);
        let x_Inv4 = prime_field_element_0::fmul(x_Inv2, x_Inv2);
        let next_x_Inv = prime_field_element_0::fmul(x_Inv2, x_Inv4);
        (next_layer_value, next_x_Inv)
    }

    #[test(s = @verifier_addr)]
    fun test_transform_coset() {
        let fri_half_inv_group_prt = 0x800000000000011;
    }
}
