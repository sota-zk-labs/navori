module verifier_addr::fri_layer {
    use std::vector;
    use std::vector::slice;
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_le};
    use lib_addr::prime_field_element_0::{fmul, fpow};
    use lib_addr::vector::set_el;
    use verifier_addr::fri_transform::transform_coset;

    // This line is used for generating constants DO NOT REMOVE!
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    // 1
    const EBIT_REVERSE: u64 = 0x1;
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
    // 2
    const MERKLE_SLOT_SIZE: u64 = 0x2;
    // End of generating constants!

    public fun gather_coset_inputs(
        channel_ptr: &mut u64,
        proof: &vector<u256>,
        fri_ctx: &mut vector<u256>,
        fri_group_ptr: u64,
        evaluations_on_coset_ptr: u64,
        fri_queue: &vector<u256>,
        fri_queue_head: u64,
        coset_size: u64
    ): (u64, u64, u256) {
        let queue_item_idx = (*vector::borrow(fri_queue, fri_queue_head) as u64);
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

        let coset_offset = fmul(
            // (c*g^(-k))=
            *vector::borrow(fri_queue, fri_queue_head + 2),
            // (g^k)=
            *vector::borrow(fri_ctx, fri_group_ptr + queue_item_idx - coset_idx)
        );

        let proof_ptr = *channel_ptr;
        let index = coset_idx;
        while (index < next_coset_idx) {
            // Inline channel operation:
            // Assume we are going to read the next element from the proof.
            // If this is not the case add(proofPtr, 0x20) will be reverted.
            let load_element_from_proof = true;
            let field_element_ptr = proof_ptr;
            proof_ptr = proof_ptr + 1;

            // Load the next index from the queue and check if it is our sibling.
            if (index == queue_item_idx) {
                // Take element from the queue rather than from the proof
                // and convert it back to Montgomery form for Merkle verification.
                field_element_ptr = fri_queue_head + 1;
                load_element_from_proof = false;
                // Revert the read from proof.
                proof_ptr = proof_ptr - 1;

                // Reading the next index here is safe due to the
                // delimiter after the queries.
                fri_queue_head = fri_queue_head + FRI_QUEUE_SLOT_SIZE;
                queue_item_idx = (*vector::borrow(fri_queue, fri_queue_head) as u64);
            };

            // Note that we apply the modulo operation to convert the field elements we read
            // from the proof to canonical representation (in the range [0, K_MODULUS - 1]).
            let field_element = *vector::borrow(
                if (load_element_from_proof) { proof } else { fri_queue },
                field_element_ptr
            );
            set_el(fri_ctx, evaluations_on_coset_ptr, field_element % K_MODULUS);
            evaluations_on_coset_ptr = evaluations_on_coset_ptr + 1;
            index = index + 1;
        };
        *channel_ptr = proof_ptr;
        let new_fri_queue_head = fri_queue_head;

        (new_fri_queue_head, coset_idx, coset_offset)
    }

    public fun bit_reverse(
        num: u256,
        number_of_bits: u8
    ): u256 {
        assert!(num < (1 << number_of_bits), EBIT_REVERSE);
        let r = 0 ;
        for (i in 0..number_of_bits) {
            r = (r << 1) | (num & 1);
            num = num >> 1;
        };
        r
    }

    // Initializes the FRI group and half inv group in the FRI context.
    public fun init_fri_group(fri_ctx: &mut vector<u256>) {
        let fri_group_ptr = FRI_CTX_TO_FRI_GROUP_OFFSET;
        let fri_half_inv_group_ptr = FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET;
        let gen_fri_group = FRI_GROUP_GEN;
        let gen_fri_group_inv = fpow(gen_fri_group, (MAX_COSET_SIZE - 1));
        let last_val = 1;
        let last_val_inv = 1;

        // ctx[mmHalfFriInvGroup + 0] = ONE_VAL;
        set_el(fri_ctx, fri_half_inv_group_ptr, last_val_inv);
        // ctx[mmFriGroup + 0] = ONE_VAL;
        set_el(fri_ctx, fri_group_ptr, last_val);
        // ctx[mmFriGroup + 1] = fsub(0, ONE_VAL);
        set_el(fri_ctx, fri_group_ptr + 1, K_MODULUS - last_val);

        let half_coset_size = MAX_COSET_SIZE / 2;
        let i = 1;
        while (i < half_coset_size) {
            last_val = fmul(last_val, gen_fri_group);
            last_val_inv = fmul(last_val_inv, gen_fri_group_inv);
            let idx = (bit_reverse(i, (FRI_MAX_STEP_SIZE - 1 as u8)) as u64);
            set_el(fri_ctx, fri_half_inv_group_ptr + idx, last_val_inv);
            set_el(fri_ctx, fri_group_ptr + (idx << 1), last_val);
            set_el(fri_ctx, fri_group_ptr + (idx << 1 | 1), K_MODULUS - last_val);
            i = i + 1;
        };
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
    public fun compute_next_layer(
        channel_ptr: &mut u64,
        proof: &vector<u256>,
        fri_queue: &mut vector<u256>,
        merkle_queue: &mut vector<u256>,
        n_queries: u64,
        fri_ctx: &mut vector<u256>,
        fri_eval_point: u256,
        fri_coset_size: u64,
    ): u64 {
        let merkle_queue_ptr = 0;
        let evaluation_on_coset_ptr = FRI_CTX_TO_COSET_EVALUATIONS_OFFSET;
        let input_ptr = 0;
        let input_end = FRI_QUEUE_SLOT_SIZE * n_queries;
        let output_ptr = 0;

        loop {
            let coset_offset;
            let index;
            (input_ptr, index, coset_offset) = gather_coset_inputs(
                channel_ptr,
                proof,
                fri_ctx,
                FRI_CTX_TO_FRI_GROUP_OFFSET,
                evaluation_on_coset_ptr,
                fri_queue,
                input_ptr,
                fri_coset_size
            );

            // Compute the index of the coset evaluations in the Merkle queue.
            index = index / fri_coset_size;
            // Add (index, keccak256(evaluationsOnCoset)) to the Merkle queue.
            set_el(merkle_queue, merkle_queue_ptr, index as u256);
            set_el(
                merkle_queue,
                merkle_queue_ptr + 1,
                COMMITMENT_MASK & bytes32_to_u256(
                    keccak256(
                        vec_to_bytes_le(
                            &slice(fri_ctx, evaluation_on_coset_ptr, evaluation_on_coset_ptr + fri_coset_size)
                        )
                    )
                )
            );

            merkle_queue_ptr = merkle_queue_ptr + MERKLE_SLOT_SIZE;

            let (fri_value, fri_inversed_point) = transform_coset(
                fri_ctx,
                FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET,
                evaluation_on_coset_ptr,
                coset_offset,
                fri_eval_point,
                fri_coset_size
            );

            // Add (index, friValue, FriInversedPoint) to the FRI queue.
            // Note that the index in the Merkle queue is also the index in the next FRI layer.
            set_el(fri_queue, output_ptr, index as u256);
            set_el(fri_queue, output_ptr + 1, fri_value);
            set_el(fri_queue, output_ptr + 2, fri_inversed_point);
            output_ptr = output_ptr + FRI_QUEUE_SLOT_SIZE;
            if (input_ptr >= input_end) {
                break;
            }
        };
        output_ptr / FRI_QUEUE_SLOT_SIZE
    }
}
