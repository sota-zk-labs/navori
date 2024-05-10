module verifier_addr::fri_layer {
    use std::vector;
    use aptos_std::math128::pow;
    use aptos_std::table::{Self, Table, new};
    use verifier_addr::prime_field_element_0::fpow;
    use verifier_addr::prime_field_element_0;
    use verifier_addr::fri_transform;
    #[test_only]
    use aptos_std::debug::print;

    const K_MODULUS : u256= 0x800000000000011000000000000000000000000000000000000000000000001;
    const MAX_COSET_SIZE:u256 = 16;
    const FRI_GROUP_GEN:u256 = 0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539;
    const FRI_GROUP_SIZE :u256 = 16;
    const FRI_CTX_TO_COSET_EVALUATIONS_OFFSET :u256 = 0;
    const FRI_CTX_TO_FRI_GROUP_OFFSET :u256 = 16;
    const FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET : u256 = 16  + 16;
    const FRI_CTX_SIZE : u256 = 32 + (16/2);
    const FRI_QUEUE_SLOT_SIZE : u256 = 3;
    const FRI_QUEUE_SLOT_SIZE_IN_BYTES : u256 = 3 * 32;

    struct FriLayer has key {
        fri_layer : Table<u256,u256>
    }

    public fun init(signer : &signer) {
        let fri_layer =  new<u256,u256>();
        move_to(signer, FriLayer{fri_layer});
    }

    public fun gather_coset_inputs(
        channel_ptr : u256,
        fri_group_ptr : u256,
        evaluations_on_coset_ptr : u256,
        fri_queue_head : u256,
        coset_size : u256
    ) : (u256,u256,u256) acquires FriLayer {
        let fri_layer = &mut borrow_global_mut<FriLayer>(@verifier_addr).fri_layer;
        let queue_item_idx = *table::borrow(fri_layer, fri_queue_head);
        let max_bit_index = coset_size - 1;
        let coset_idx = queue_item_idx & max_bit_index; //todo: need to add not operator : cosetIdx := and(queueItemIdx, not(sub(cosetSize, 1)))
        let next_coset_idx = coset_idx + coset_size;


        let coset_off_set = *table::borrow(fri_layer,fri_queue_head + 2) * *table::borrow(fri_layer,queue_item_idx - coset_idx) % K_MODULUS ;


        let proof_ptr = *table::borrow_mut(fri_layer, channel_ptr);
        let index = coset_idx;
        while ( index < next_coset_idx ) {
            let field_element_ptr = proof_ptr;
            proof_ptr = proof_ptr + 1;
            if (index == queue_item_idx ) {
                field_element_ptr = fri_queue_head +1;
                proof_ptr = proof_ptr - 1;
                fri_queue_head = fri_queue_head + FRI_QUEUE_SLOT_SIZE;
                queue_item_idx = *table::borrow(fri_layer, fri_queue_head);
            };
            let field_element = *table::borrow(fri_layer, field_element_ptr );
            table::upsert(fri_layer, (field_element % K_MODULUS), field_element_ptr);
            let evaluation_on_coset_ptr = evaluations_on_coset_ptr + 1;
            index = index + 1;
        };
        table::upsert(fri_layer, channel_ptr, proof_ptr);
        let new_fri_queue_head = fri_queue_head;
        (new_fri_queue_head, coset_idx, coset_off_set)
    }
    public fun bit_reverse(
        num : u256,
        number_of_bits : u256
    ) : u256 {
        // assert!((number_of_bits == 256 || num < 2**&number_of_bits),1); // Have some error with this func
        let n = num;
        let r = 0 ;
        let k = 0;
        while (k < number_of_bits) {
            r = (r * 2) | (n %2);
            n = n/2;
            k = k +1;
        };
        r
    }

    /*
          Initializes the FRI group and half inv group in the FRI context.
    */
    public fun init_fri_group(
        fri_ctx : u256
    ) acquires FriLayer {
        let fri_group_ptr = fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET;
        let fri_half_inv_group_ptr = fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET;
        let gen_fri_group = FRI_GROUP_GEN;
        let gen_fri_group_inv = fpow(gen_fri_group,(MAX_COSET_SIZE-1));
        let last_val = 1;
        let last_val_inv = 1;
        let fri_layer = &mut borrow_global_mut<FriLayer>(@verifier_addr).fri_layer;

        table::upsert(fri_layer, fri_half_inv_group_ptr, last_val_inv);
        table::upsert(fri_layer, fri_group_ptr, last_val);
        table::upsert(fri_layer, fri_group_ptr + 1, K_MODULUS - last_val);

        let half_coset_size = MAX_COSET_SIZE/2;
        let idx = 1;
        while (idx < half_coset_size) {
            last_val = (last_val * gen_fri_group) % K_MODULUS;
            last_val_inv = (last_val_inv * gen_fri_group_inv) % K_MODULUS;
            table::upsert(fri_layer, fri_group_ptr + idx, last_val_inv);
            table::upsert(fri_layer, fri_group_ptr + idx*2 , last_val);
            table::upsert(fri_layer, fri_group_ptr + (idx*2 + 1), K_MODULUS - last_val);
            idx = idx + 1;
        };
    }
    /*
      Computes the FRI step with eta = log2(friCosetSize) for all the live queries.

      The inputs for the current layer are read from the FRI queue and the inputs
      for the next layer are written to the same queue (overwriting the input).
      See friVerifyLayers for the description for the FRI queue.

      The function returns the number of live queries remaining after computing the FRI step.

      The number of live queries decreases whenever multiple query points in the same
      coset are reduced to a single query in the next FRI layer.

      As the function computes the next layer it also collects that data from
      the previous layer for Merkle verification.
    */
    fun compute_next_layer (
        channel_ptr : u256,
        fri_queue_ptr : u256,
        merkle_queue_ptr : u256,
        n_queries : u256,
        fri_ctx : u256,
        fri_eval_point : u256,
        fri_coset_size : u256,
    ) : u256 acquires FriLayer {
        let fri_layer = &mut borrow_global_mut<FriLayer>(@verifier_addr).fri_layer;
        let evaluation_on_coset_ptr = fri_ctx + FRI_CTX_TO_COSET_EVALUATIONS_OFFSET;
        let input_ptr = fri_queue_ptr;
        let input_end = input_ptr + (FRI_QUEUE_SLOT_SIZE * n_queries);
        let output_ptr = fri_queue_ptr;
        while ( input_ptr < input_end) {
            let coset_offset;
            let index;
            (input_ptr,index, coset_offset) = gather_coset_inputs(
                channel_ptr, fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET, evaluation_on_coset_ptr, input_ptr, fri_coset_size
            );


        };
        input_ptr
    }


    #[test()]
    fun test_bit_reverse() {
        let num = 13;
        let number_of_bits = 6;
        let result = bit_reverse(num, number_of_bits);
        assert!(result ==44, 1);
    }
    #[test(s = @verifier_addr)]
    fun test_init_fri_group() acquires FriLayer {
        let fri_ctx = 0;
        init_fri_group(fri_ctx);
        let fri_layer = &borrow_global<FriLayer>(@verifier_addr).fri_layer;
        let fri_group_ptr = fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET;
        let fri_half_inv_group_ptr = fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET;
        let gen_fri_group = FRI_GROUP_GEN;
        let gen_fri_group_inv = fpow(gen_fri_group,(MAX_COSET_SIZE-1));
        let last_val = 1;
        let last_val_inv = 1;
        assert!(*table::borrow(fri_layer, fri_half_inv_group_ptr) == last_val_inv, 1);
        assert!(*table::borrow(fri_layer, fri_group_ptr) == last_val, 1);
        assert!(*table::borrow(fri_layer, fri_group_ptr + 1) == K_MODULUS - last_val, 1);
        let half_coset_size = MAX_COSET_SIZE/2;
        let idx = 1;
        while (idx < half_coset_size) {
            last_val = (last_val * gen_fri_group) % K_MODULUS;
            last_val_inv = (last_val_inv * gen_fri_group_inv) % K_MODULUS;
            assert!(*table::borrow(fri_layer, fri_group_ptr + idx) == last_val_inv, 1);
            assert!(*table::borrow(fri_layer, fri_group_ptr + idx*2) == last_val, 1);
            assert!(*table::borrow(fri_layer, fri_group_ptr + (idx*2 + 1)) == K_MODULUS - last_val, 1);
            idx = idx + 1;
        }
    }
}
