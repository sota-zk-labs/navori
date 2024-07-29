module verifier_addr::fri_layer {
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::math128::pow;

    use lib_addr::bitwise::not;
    use lib_addr::endia_encode::to_big_endian;
    use lib_addr::memory::{Memory, mload, mloadrange, mstore};
    use verifier_addr::fri_transform::{FRI_MAX_STEP_SIZE, transform_coset};
    use verifier_addr::merkle_verifier::{COMMITMENT_MASK, MERKLE_SLOT_SIZE_IN_BYTES};
    use verifier_addr::prime_field_element_0::{fmul, fpow, k_modulus, one_val};

    public fun MAX_COSET_SIZE(): u256 {
        (pow(2, (FRI_MAX_STEP_SIZE() as u128)) as u256)
    }

    public fun FRI_GROUP_GEN(): u256 {
        0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539
    }

    public fun FRI_GROUP_SIZE(): u256 {
        0x20 * MAX_COSET_SIZE()
    }

    public fun FRI_CTX_TO_COSET_EVALUATIONS_OFFSET(): u256 {
        0
    }

    public fun FRI_CTX_TO_FRI_GROUP_OFFSET(): u256 {
        FRI_GROUP_SIZE()
    }

    public fun FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET(): u256 {
        FRI_CTX_TO_FRI_GROUP_OFFSET() + FRI_GROUP_SIZE()
    }

    public fun FRI_CTX_SIZE(): u256 {
        FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET() + (FRI_GROUP_SIZE() / 2)
    }

    public fun FRI_QUEUE_SLOT_SIZE(): u64 {
        3
    }

    public fun FRI_QUEUE_SLOT_SIZE_IN_BYTES(): u256 {
        3 * 0x20
    }
    /*
          Gathers the "cosetSize" elements that belong the coset of the first element in the FRI queue.
          The elements are written to 'evaluationsOnCosetPtr'.

          The coset elements are read either from the FriQueue or from the verifier channel
          depending on whether the required element are in queue or not.

          Returns
            newFriQueueHead - The update FRI queue head i.e.
              friQueueHead + FRI_QUEUE_SLOT_SIZE_IN_BYTES * (# elements that were taken from the queue).
            cosetIdx - the start index of the coset that was gathered.
            cosetOffset - the xInv field element that corresponds to cosetIdx.
        */
    public fun gather_coset_inputs(
        memory: &mut Memory,
        channel_ptr: u256,
        fri_group_ptr: u256,
        evaluations_on_coset_ptr: u256,
        fri_queue_head: u256,
        coset_size: u256
    ): (u256, u256, u256) {
        let new_fri_queue_head: u256;
        let coset_idx: u256;
        let coset_off_set: u256;

        let queue_item_idx = mload(memory, fri_queue_head);
        // The coset index is represented by the most significant bits of the queue item index.;
        // The coset index is represented by the most significant bits of the queue item index.
        coset_idx = queue_item_idx & not(coset_size - 1);
        let next_coset_idx = coset_idx + coset_size;

        // Get the algebraic coset offset:
        // I.e. given c*g^(-k) compute c, where
        //      g is the generator of the coset group.
        //      k is bitReverse(offsetWithinCoset, log2(cosetSize)).
        //
        // To do this we multiply the algebraic coset offset at the top of the queue (c*g^(-k))
        // by the group element that corresponds to the index inside the coset (g^k).

        // (c*g^(-k))=
        let fri_queue = mload(memory, fri_queue_head + 0x40);
        // (g^k)=

        let queue_item = mload(memory, fri_group_ptr + (queue_item_idx - coset_idx) * 0x20);
        coset_off_set = fmul(fri_queue, queue_item);


        let proof_ptr = mload(memory, channel_ptr);

        let index = coset_idx;
        while (index < next_coset_idx) {
            // Inline channel operation:
            // Assume we are going to read the next element from the proof.
            // If this is not the case add(proofPtr, 0x20) will be reverted.
            let field_element_ptr = proof_ptr;
            proof_ptr = proof_ptr + 0x20;

            // Load the next index from the queue and check if it is our sibling.
            if (index == queue_item_idx) {
                // Take element from the queue rather than from the proof
                // and convert it back to Montgomery form for Merkle verification.
                field_element_ptr = fri_queue_head + 0x20;

                // Revert the read from proof.
                proof_ptr = proof_ptr - 0x20;

                // Reading the next index here is safe due to the
                // delimiter after the queries.
                fri_queue_head = fri_queue_head + FRI_QUEUE_SLOT_SIZE_IN_BYTES();
                queue_item_idx = mload(memory, fri_queue_head);
            };

            let field_element = mload(memory, field_element_ptr);
            mstore(memory, evaluations_on_coset_ptr, field_element % k_modulus());
            evaluations_on_coset_ptr = evaluations_on_coset_ptr + 0x20;

            index = index + 1;
        };
        mstore(memory, channel_ptr, proof_ptr);
        new_fri_queue_head = fri_queue_head;

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
    public fun init_fri_group(
        memory: &mut Memory,
        fri_ctx: u256
    ) {
        let fri_group_ptr = fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET();
        let fri_half_inv_group_ptr = fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET();

        // FRI_GROUP_GEN is the coset generator.
        // Raising it to the (MAX_COSET_SIZE - 1) power gives us the inverse.
        let gen_fri_group = FRI_GROUP_GEN();
        let gen_fri_group_inv = fpow(gen_fri_group, (MAX_COSET_SIZE() - 1));

        let last_val = one_val();
        let last_val_inv = one_val();

        // ctx[mmHalfFriInvGroup + 0] = ONE_VAL;
        mstore(memory, fri_half_inv_group_ptr, last_val_inv);
        // ctx[mmFriGroup + 0] = ONE_VAL;
        mstore(memory, fri_group_ptr, last_val);
        // ctx[mmFriGroup + 1] = fsub(0, ONE_VAL);
        mstore(memory, fri_group_ptr + 0x20, k_modulus() - last_val);

        // To compute [1, -1 (== g^n/2), g^n/4, -g^n/4, ...]
        // we compute half the elements and derive the rest using negation.
        let half_coset_size = MAX_COSET_SIZE() / 2;

        let i = 1;
        while (i < half_coset_size) {
            // TODO: check next 3 lines
            last_val = fmul(last_val, gen_fri_group);
            last_val_inv = fmul(last_val_inv, gen_fri_group_inv);
            let idx = bit_reverse(i, FRI_MAX_STEP_SIZE() - 1);

            mstore(memory, fri_half_inv_group_ptr + idx * 0x20, last_val_inv);
            mstore(memory, fri_group_ptr + idx * 0x40, last_val);
            mstore(memory, fri_group_ptr + idx * 0x40 + 0x20, k_modulus() - last_val);

            i = i + 1;
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
    public fun compute_next_layer(
        memory: &mut Memory,
        channel_ptr: u256,
        fri_queue_ptr: u256,
        merkle_queue_ptr: u256,
        n_queries: u256,
        fri_ctx: u256,
        fri_eval_point: u256,
        fri_coset_size: u256,
    ): u256 {
        let evaluation_on_coset_ptr = fri_ctx + FRI_CTX_TO_COSET_EVALUATIONS_OFFSET();

        // The inputs are read from the Fri queue and the result is written same queue.
        // The inputs are never overwritten since gatherCosetInputs reads at least one element and
        // transformCoset writes exactly one element.
        let input_ptr = fri_queue_ptr;
        let input_end = input_ptr + (FRI_QUEUE_SLOT_SIZE_IN_BYTES() * n_queries);
        let output_ptr = fri_queue_ptr;


        while (input_ptr < input_end) {
            let coset_offset;
            let index;
            (input_ptr, index, coset_offset) = gather_coset_inputs(
                memory,
                channel_ptr,
                fri_ctx + FRI_CTX_TO_FRI_GROUP_OFFSET(),
                evaluation_on_coset_ptr,
                input_ptr,
                fri_coset_size
            );


            // Compute the index of the coset evaluations in the Merkle queue.
            index = index / fri_coset_size;

            // Add (index, keccak256(evaluationsOnCoset)) to the Merkle queue.
            mstore(memory, merkle_queue_ptr, index);
            let keccak_input = mloadrange(memory, evaluation_on_coset_ptr, fri_coset_size * 0x20);

            mstore(memory, merkle_queue_ptr + 0x20, COMMITMENT_MASK() & to_u256(to_big_endian(
                keccak256(keccak_input))));
            merkle_queue_ptr = merkle_queue_ptr + (MERKLE_SLOT_SIZE_IN_BYTES() as u256);

            let (fri_value, fri_inversed_point) = transform_coset(
                memory,
                fri_ctx + FRI_CTX_TO_FRI_HALF_INV_GROUP_OFFSET(),
                evaluation_on_coset_ptr,
                coset_offset,
                fri_eval_point,
                fri_coset_size
            );

            mstore(memory, output_ptr, index);
            mstore(memory, output_ptr + 0x20, fri_value);
            mstore(memory, output_ptr + 0x40, fri_inversed_point);

            output_ptr = output_ptr + FRI_QUEUE_SLOT_SIZE_IN_BYTES();
        };

        return (output_ptr - fri_queue_ptr) / FRI_QUEUE_SLOT_SIZE_IN_BYTES()
    }
}
