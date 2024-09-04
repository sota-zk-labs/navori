module verifier_addr::fri_layer {
    use std::signer::address_of;
    use std::vector;
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{bytes32_to_u256, num_to_bytes_le};
    use lib_addr::prime_field_element_0::{fmul, fpow};
    use verifier_addr::fri::{get_fri, update_fri};
    use verifier_addr::fri_transform::transform_coset;

    // This line is used for generating constants DO NOT REMOVE!
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    // 0
    const FRI_CTX_TO_COSET_EVALUATIONS_OFFSET: u64 = 0x0;
    // FRI_GROUP_SIZE
    const FRI_CTX_TO_FRI_GROUP_OFFSET: u64 = 0x10;
    // FRI_CTX_TO_FRI_GROUP_OFFSET + FRI_GROUP_SIZE
    const FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET: u64 = 0x20;
    // 2679026602897868112349604024891625875968950767352485125058791696935099163961
    const FRI_GROUP_GEN: u256 = 0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539;
    // 4
    const FRI_MAX_STEP_SIZE: u256 = 0x4;
    // 3
    const FRI_QUEUE_SLOT_SIZE: u64 = 0x3;
    // 3618502788666131213697322783095070105623107215331596699973092056135872020481
    const K_MODULUS: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;
    // 2^FRI_MAX_STEP_SIZE
    const MAX_COSET_SIZE: u256 = 0x10;
    // 0xffffffffffffffff
    const MAX_U64: u64 = 0xffffffffffffffff;
    // End of generating constants!

    public fun gather_coset_inputs(
        fri: &mut vector<u256>,
        channel_ptr: u64,
        fri_group_ptr: u64,
        evaluations_on_coset_ptr: u64,
        fri_queue_head: u64,
        coset_size: u64
    ): (u64, u64, u256) {
        let queue_item_idx = (*vector::borrow(fri, fri_queue_head) as u64);
        // The coset index is represented by the most significant bits of the queue item index.
        let coset_idx = queue_item_idx & (MAX_U64 - coset_size + 1);
        let next_coset_idx = coset_idx + coset_size;
        // Get the algebraic coset offset:
        // I.e. given c*g^(-k) compute c, where
        //      g is the generator of the coset group.
        //      k is bitReverse(offsetWithinCoset, log2(cosetSize)).
        //
        // To do this we multiply the algebraic coset offset at the top of the queue (c*g^(-k))
        // by the group element that corresponds to the index inside the coset (g^k).

        // (c*g^(-k))=
        let fri_queue = *vector::borrow(fri, fri_queue_head + 2);
        // (g^k)=

        let queue_item = *vector::borrow(fri, fri_group_ptr + queue_item_idx - coset_idx);
        let coset_off_set = fmul(fri_queue, queue_item);


        let proof_ptr = (*vector::borrow(fri, channel_ptr) as u64) ;
        let index = coset_idx;


        while (index < next_coset_idx) {
            let field_element_ptr = proof_ptr;
            proof_ptr = proof_ptr + 1;

            if (index == queue_item_idx) {
                field_element_ptr = fri_queue_head + 1;
                proof_ptr = proof_ptr - 1;
                fri_queue_head = fri_queue_head + FRI_QUEUE_SLOT_SIZE;
                queue_item_idx = (*vector::borrow(fri, fri_queue_head) as u64);
            };

            let field_element = *vector::borrow(fri, field_element_ptr);
            *vector::borrow_mut(fri, evaluations_on_coset_ptr) = field_element % K_MODULUS;
            evaluations_on_coset_ptr = evaluations_on_coset_ptr + 1;
            index = index + 1;
        };
        *vector::borrow_mut(fri, channel_ptr) = (proof_ptr as u256);
        let new_fri_queue_head = fri_queue_head;

        (new_fri_queue_head, coset_idx, coset_off_set)
    }

    public fun bit_reverse(
        num: u256,
        number_of_bits: u8
    ): u256 {
        assert!(num < (1 << number_of_bits), 1);
        let r = 0 ;
        for (i in 0..number_of_bits) {
            r = (r * 2) | (num % 2);
            num = num / 2;
        };
        r
    }

    // Initializes the FRI group and half inv group in the FRI context.
    public entry fun init_fri_group(
        signer: &signer,
        fri_ctx: u64
    ) {
        let fri = &mut get_fri(address_of(signer));

        let fri_group_ptr = fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET;
        let fri_half_inv_group_ptr = fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET;
        let gen_fri_group = FRI_GROUP_GEN;
        let gen_fri_group_inv = fpow(gen_fri_group, (MAX_COSET_SIZE - 1));
        let last_val = 1;
        let last_val_inv = 1;

        *vector::borrow_mut(fri, fri_half_inv_group_ptr) = last_val_inv;
        *vector::borrow_mut(fri, fri_group_ptr) = last_val;
        *vector::borrow_mut(fri, fri_group_ptr + 1) = K_MODULUS - last_val;

        let half_coset_size = MAX_COSET_SIZE / 2;
        let i = 1;
        while (i < half_coset_size) {
            last_val = fmul(last_val, gen_fri_group);
            last_val_inv = fmul(last_val_inv, gen_fri_group_inv);
            let idx = (bit_reverse(i, (FRI_MAX_STEP_SIZE - 1 as u8)) as u64);
            *vector::borrow_mut(fri, fri_half_inv_group_ptr + idx) = last_val_inv;
            *vector::borrow_mut(fri, fri_group_ptr + idx * 2) = last_val;
            *vector::borrow_mut(fri, fri_group_ptr + idx * 2 + 1) = K_MODULUS - last_val;
            i = i + 1;
        };
        update_fri(signer, *fri);
    }

    // Computes the FRI step with eta = log2(friCosetSize) for all the live queries.
    //
    // The inputs for the current layer are read from the FRI queue and the inputs
    // for the next layer are written to the same queue (overwriting the input).
    // See friVerifyLayers for the description for the FRI queue.
    //
    // The function returns the number of live queries remaining after computing the FRI step.
    //
    // The number of live queries decreases whenever multiple query points in the same
    // coset are reduced to a single query in the next FRI layer.
    //
    // As the function computes the next layer it also collects that data from
    // the previous layer for Merkle verification.
    public entry fun compute_next_layer(
        s: &signer,
        channel_ptr: u64,
        fri_queue_ptr: u64,
        merkle_queue_ptr: u64,
        n_queries: u64,
        fri_ctx: u64,
        fri_eval_point: u256,
        fri_coset_size: u64,
    ) {
        let fri = &mut get_fri(address_of(s));

        let evaluation_on_coset_ptr = fri_ctx + FRI_CTX_TO_COSET_EVALUATIONS_OFFSET;
        let input_ptr = fri_queue_ptr;
        let input_end = input_ptr + (FRI_QUEUE_SLOT_SIZE * n_queries);
        let output_ptr = fri_queue_ptr;

        while (input_ptr < input_end) {
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

            // Compute the index of the coset evaluations in the Merkle queue.
            index = index / fri_coset_size;
            // Add (index, keccak256(evaluationsOnCoset)) to the Merkle queue.
            *vector::borrow_mut(fri, merkle_queue_ptr) = (index as u256);

            let hash = vector::empty();
            for (i in 0..fri_coset_size) {
                vector::append(&mut hash, num_to_bytes_le(vector::borrow(fri, evaluation_on_coset_ptr + i)));
            };

            *vector::borrow_mut(fri, merkle_queue_ptr + 1) = COMMITMENT_MASK & bytes32_to_u256(keccak256(hash));

            merkle_queue_ptr = merkle_queue_ptr + 2;

            let (fri_value, fri_inversed_point) = transform_coset(
                fri,
                fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET,
                evaluation_on_coset_ptr,
                coset_offset,
                fri_eval_point,
                fri_coset_size
            );

            *vector::borrow_mut(fri, output_ptr) = (index as u256);
            *vector::borrow_mut(fri, output_ptr + 1) = fri_value;
            *vector::borrow_mut(fri, output_ptr + 2) = fri_inversed_point;
            output_ptr = output_ptr + FRI_QUEUE_SLOT_SIZE;
        };
        update_fri(s, *fri);
    }
}
