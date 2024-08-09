module verifier_addr::fri_layer {
    use std::signer::address_of;
    use std::vector;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::debug::print;
    use aptos_std::math128::pow;
    use aptos_std::math64::ceil_div;
    use aptos_std::smart_table;
    use aptos_std::smart_table::SmartTable;
    use aptos_std::smart_table::{borrow, upsert};
    use aptos_framework::event::emit;

    use verifier_addr::fri::{get_fri, update_fri};
    use verifier_addr::fri_transform::{fri_max_step_size, transform_coset};
    use verifier_addr::prime_field_element_0::{fmul, fpow, k_modulus};
    use verifier_addr::u256_to_byte32::{bytes32_to_u256, u256_to_bytes32};

    const MAX_COSET_SIZE: u256 = 16;
    const FRI_GROUP_GEN: u256 = 0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539;
    const FRI_GROUP_SIZE: u256 = 16;
    const FRI_CTX_TO_COSET_EVALUATIONS_OFFSET: u256 = 0;
    const FRI_CTX_TO_FRI_GROUP_OFFSET: u256 = 16;
    const FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET: u256 = 32;
    const FRI_CTX_SIZE: u256 = 40;
    const FRI_QUEUE_SLOT_SIZE: u256 = 3;
    const FRI_QUEUE_SLOT_SIZE_IN_BYTES: u256 = 96;
    const NOT_NUM: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    const MAX_CYCLES: u64 = 6;

    const ECOMPUTE_NEXT_LAYER_NOT_INITIATED: u64 = 10;

    public fun fri_ctx_size(): u256 {
        FRI_CTX_SIZE
    }

    struct Ptr has key, store, copy, drop {
        input_ptr: u256,
        input_end: u256,
        output_ptr: u256,
        merkle_queue_ptr: u256
    }

    #[event]
    struct NQueries has store, drop {
        n_queries: u256
    }


    public fun gather_coset_inputs(
        fri: &mut SmartTable<u256, u256>,
        channel_ptr: u256,
        fri_group_ptr: u256,
        evaluations_on_coset_ptr: u256,
        fri_queue_head: u256,
        coset_size: u256
    ): (u256, u256, u256) {
        let queue_item_idx = *borrow(fri, fri_queue_head);
        let max_bit_index = (coset_size - 1) ^ NOT_NUM;
        // The coset index is represented by the most significant bits of the queue item index.
        let coset_idx = queue_item_idx & max_bit_index;
        let next_coset_idx = coset_idx + coset_size;
        // Get the algebraic coset offset:
        // I.e. given c*g^(-k) compute c, where
        //      g is the generator of the coset group.
        //      k is bitReverse(offsetWithinCoset, log2(cosetSize)).
        //
        // To do this we multiply the algebraic coset offset at the top of the queue (c*g^(-k))
        // by the group element that corresponds to the index inside the coset (g^k).

        // (c*g^(-k))=
        let fri_queue = *borrow(fri, (fri_queue_head + 2));
        // (g^k)=

        let queue_item = *borrow(fri, (fri_group_ptr + queue_item_idx - coset_idx));
        let coset_off_set = fmul(fri_queue, queue_item);


        let proof_ptr = *borrow(fri, channel_ptr);
        let index = coset_idx;


        while (index < next_coset_idx) {
            let field_element_ptr = proof_ptr;
            proof_ptr = proof_ptr + 1;

            if (index == queue_item_idx) {
                field_element_ptr = fri_queue_head + 1;
                proof_ptr = proof_ptr - 1;
                fri_queue_head = fri_queue_head + FRI_QUEUE_SLOT_SIZE;
                queue_item_idx = *borrow(fri, fri_queue_head);
            };

            let field_element = *borrow(fri, field_element_ptr);
            upsert(fri, evaluations_on_coset_ptr, field_element % k_modulus());
            evaluations_on_coset_ptr = evaluations_on_coset_ptr + 1;
            index = index + 1;
        };
        upsert(fri, channel_ptr, proof_ptr);
        let new_fri_queue_head = fri_queue_head;

        (new_fri_queue_head, coset_idx, coset_off_set)
    }

    public fun bit_reverse(
        num: u256,
        number_of_bits: u256
    ): u256 {
        assert!((number_of_bits == 256 || num < (pow(2, (number_of_bits as u128)) as u256)), 1);
        let n = num;
        let r = 0 ;
        let k = 0;
        while (k < number_of_bits) {
            r = (r * 2) | (n % 2);
            n = n / 2;
            k = k + 1;
        };
        r
    }

    /*
          Initializes the FRI group and half inv group in the FRI context.
    */
    public entry fun init_fri_group(
        signer: &signer,
        fri_ctx: u256
    ) {
        let fri = get_fri(address_of(signer));
        let ffri = &mut fri;
        let fri_group_ptr = fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET;
        let fri_half_inv_group_ptr = fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET;
        let gen_fri_group = FRI_GROUP_GEN;
        let gen_fri_group_inv = fpow(gen_fri_group, (MAX_COSET_SIZE - 1));
        let last_val = 1;
        let last_val_inv = 1;

        upsert(ffri, fri_half_inv_group_ptr, last_val_inv);
        upsert(ffri, fri_group_ptr, last_val);
        upsert(ffri, fri_group_ptr + 1, k_modulus() - last_val);

        let half_coset_size = MAX_COSET_SIZE / 2;
        let i = 1;
        while (i < half_coset_size) {
            last_val = fmul(last_val, gen_fri_group);
            last_val_inv = fmul(last_val_inv, gen_fri_group_inv);
            let idx = bit_reverse(i, fri_max_step_size() - 1);
            upsert(ffri, fri_half_inv_group_ptr + idx, last_val_inv);
            upsert(ffri, fri_group_ptr + idx * 2, last_val);
            upsert(ffri, fri_group_ptr + idx * 2 + 1, k_modulus() - last_val);
            i = i + 1;
        };
        update_fri(signer, fri);
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

    public entry fun init_compute_next_layer(
        s: &signer,
        fri_queue_ptr: u256,
        merkle_queue_ptr: u256,
        n_queries: u256
    ) acquires Ptr {
        if (exists<Ptr>(address_of(s))) {
            move_from<Ptr>(address_of(s));
        };
        move_to<Ptr>(
            s,
            Ptr {
                input_ptr: fri_queue_ptr,
                input_end: fri_queue_ptr + (FRI_QUEUE_SLOT_SIZE * n_queries),
                output_ptr: fri_queue_ptr,
                merkle_queue_ptr,
            }
        );
    }

    public entry fun compute_next_layer(
        s: &signer,
        channel_ptr: u256,
        fri_queue_ptr: u256,
        fri_ctx: u256,
        fri_eval_point: u256,
        fri_coset_size: u256,
    ) acquires Ptr {
        let ffri = get_fri(address_of(s));
        let fri = &mut ffri;
        assert!(exists<Ptr>(address_of(s)), ECOMPUTE_NEXT_LAYER_NOT_INITIATED);
        let ptr = borrow_global_mut<Ptr>(address_of(s));
        let evaluation_on_coset_ptr = fri_ctx + FRI_CTX_TO_COSET_EVALUATIONS_OFFSET;

        let input_ptr = ptr.input_ptr;
        let input_end = ptr.input_end;
        let output_ptr = ptr.output_ptr;
        let merkle_queue_ptr = ptr.merkle_queue_ptr;
        let i = 0;
        while (i < MAX_CYCLES) {
            i = i + 1;
            if (input_ptr >= input_end) {
                move_from<Ptr>(address_of(s));
                break
            };
            let coset_offset;
            let index;
            (input_ptr, index, coset_offset) = gather_coset_inputs(
                fri,
                channel_ptr,
                fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET,
                evaluation_on_coset_ptr,
                input_ptr,
                fri_coset_size
            );

            ptr.input_ptr = input_ptr;
            // Compute the index of the coset evaluations in the Merkle queue.
            index = index / fri_coset_size;
            // Add (index, keccak256(evaluationsOnCoset)) to the Merkle queue.
            upsert(fri, merkle_queue_ptr, index);

            let hash = vector::empty();
            let idx_hash = 0;
            while (idx_hash < fri_coset_size) {
                vector::append(&mut hash, u256_to_bytes32(*borrow(fri, evaluation_on_coset_ptr + idx_hash)));
                idx_hash = idx_hash + 1;
            };

            upsert(fri, merkle_queue_ptr + 1, COMMITMENT_MASK & bytes32_to_u256(keccak256(hash)));


            merkle_queue_ptr = merkle_queue_ptr + 2;

            let (fri_value, fri_inversed_point) = transform_coset(
                fri,
                fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET,
                evaluation_on_coset_ptr,
                coset_offset,
                fri_eval_point,
                fri_coset_size
            );

            upsert(fri, output_ptr, index);
            upsert(fri, output_ptr + 1, fri_value);
            upsert(fri, output_ptr + 2, fri_inversed_point);
            output_ptr = output_ptr + FRI_QUEUE_SLOT_SIZE;
            ptr.output_ptr = output_ptr;
            ptr.merkle_queue_ptr = merkle_queue_ptr;

        };
        let n_queries = ((input_end -  fri_queue_ptr) / FRI_QUEUE_SLOT_SIZE);
        emit<NQueries>(NQueries { n_queries });
        update_fri(s, ffri);
    }

    #[view]
    public fun count_next_layer_cycles(
        s: address,
        channel_ptr: u256,
        fri_queue_ptr: u256,
        n_queries: u256,
        fri_ctx: u256,
        fri_coset_size: u256,
    ): u64 {
        let ffri = get_fri(s);
        let fri = &mut ffri;
        let evaluation_on_coset_ptr = fri_ctx + FRI_CTX_TO_COSET_EVALUATIONS_OFFSET;
        let input_ptr = fri_queue_ptr;
        let input_end = input_ptr + (FRI_QUEUE_SLOT_SIZE * n_queries);
        let count: u64 = 0;
        while (input_ptr < input_end) {
            count = count + 1;
            (input_ptr, _, _) = gather_coset_inputs(
                fri,
                channel_ptr,
                fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET,
                evaluation_on_coset_ptr,
                input_ptr,
                fri_coset_size
            );
        };
        smart_table::destroy(ffri);
        ceil_div(count, MAX_CYCLES)
    }
}
