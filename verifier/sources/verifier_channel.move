module verifier_addr::verifier_channel {
    use std::vector::{append, borrow, borrow_mut, enumerate_ref, slice};
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{bytes32_to_u256, num_to_bytes_le, vec_to_bytes_le, merge_num_offset_8};
    use lib_addr::prime_field_element_0::{fmul, from_montgomery};
    use lib_addr::vector::set_el;
    use verifier_addr::prng::{get_random_bytes, init_prng};

    // This line is used for generating constants DO NOT REMOVE!
    // 3
    const EMASK_MUST_BE_LESS_THAN_2_TO_THE_POWER_OF_64: u64 = 0x3;
    // 100
    const EOVERFLOW_PROTECTION_FAILED: u64 = 0x64;
    // 2
    const EPROOF_OF_WORK_CHECK_FAILED: u64 = 0x2;
    // 113078212145816603762751633895895194930089271709401121343797004406777446400
    const K_MONTGOMERY_R_INV: u256 = 0x40000000000001100000000000012100000000000000000000000000000000;
    // End of generating constants!

    friend verifier_addr::stark_verifier_7;
    friend verifier_addr::fri_statement_verifier_7;

    public(friend) fun init_channel(ctx: &mut vector<u256>, channel_ptr: u64, public_input_hash: u256) {
        // set `ctx[channel_ptr]` as index 0 in `proof`
        set_el(ctx, channel_ptr, 0);
        init_prng(ctx, channel_ptr + 1, public_input_hash);
    }

    // Sends a field element through the verifier channel.
    //
    // Note that the logic of this function is inlined in many places throughout the code to reduce
    // gas costs.
    public(friend) fun send_field_elements(
        ctx: &mut vector<u256>,
        channel_ptr: u64,
        n_elements: u64,
        target_ptr: u64
    ) {
        assert!(n_elements < 0x1000000, EOVERFLOW_PROTECTION_FAILED);
        let bound = 0xf80000000000020f00000000000000000000000000000000000000000000001fu256;
        let digest = *borrow(ctx, channel_ptr + 1);

        let counter = *borrow(ctx, channel_ptr + 2);
        for (i in target_ptr..(target_ptr + n_elements)) {
            let field_element = bound;
            while (field_element >= bound) {
                // keccak256(abi.encodePacked(digest, counter));
                field_element = bytes32_to_u256(keccak256(vec_to_bytes_le(&vector[digest, counter])));
                // *counterPtr += 1;
                counter = counter + 1;
            };
            // *targetPtr = fromMontgomery(fieldElement);
            set_el(ctx, i, fmul(field_element, K_MONTGOMERY_R_INV));
        };
        set_el(ctx, channel_ptr + 2, counter);
    }

    // Sends random queries and returns an array of queries sorted in ascending order.
    // Generates count queries in the range [0, mask] and returns the number of unique queries.
    // Note that mask is of the form 2^k-1 (for some k <= 64).
    //
    // Note that queries_out_ptr may be (and is) interleaved with other arrays. The stride parameter
    // is passed to indicate the distance between every two entries in the queries array, i.e.
    // stride = 0x20*(number of interleaved arrays).
    public(friend) fun send_random_queries(
        ctx: &mut vector<u256>,
        channel_ptr: u64,
        count: u256,
        mask: u256,
        queries_out_ptr: u64,
        stride: u64
    ): u256 {
        assert!(mask < (1 << 64), EMASK_MUST_BE_LESS_THAN_2_TO_THE_POWER_OF_64);
        let val = 0u256;
        let shift = 0u256;
        let end_ptr = queries_out_ptr;

        for (i in 0..count) {
            if (shift == 0) {
                val = get_random_bytes(ctx, channel_ptr + 1);
                shift = 0x100;
            };
            shift = shift - 0x40;
            let query_idx = (val >> (shift as u8)) & mask;
            let ptr = end_ptr;

            // Initialize 'curr' to -1 to make sure the condition 'queryIdx != curr' is satisfied
            // on the first iteration.
            let curr = (1u256 << 255);

            // Insert new queryIdx in the correct place like insertion sort.
            while (ptr > queries_out_ptr) {
                curr = *borrow(ctx, ptr - stride);

                if (query_idx >= curr) {
                    break
                };

                set_el(ctx, ptr, curr);

                ptr = ptr - stride;
            };

            if (query_idx != curr) {
                set_el(ctx, ptr, query_idx);
                end_ptr = end_ptr + stride;
            } else {
                // Revert right shuffling.
                while (ptr < end_ptr) {
                    let tmp = *borrow(ctx, ptr + stride);
                    set_el(ctx, ptr, tmp);
                    ptr = ptr + stride;
                }
            }
        };

        ((end_ptr - queries_out_ptr) / stride as u256)
    }

    public(friend) inline fun read_hash(ctx: &mut vector<u256>, proof: &vector<u256>, channel_ptr: u64, mix: bool): u256 {
        read_bytes(ctx, proof, channel_ptr, mix, false)
    }

    // Reads a field element from the verifier channel (that is, the proof in the non-interactive
    // case).
    // The field elements on the channel are in Montgomery form and this function converts
    // them to the standard representation.
    //
    // Note that the logic of this function is inlined in many places throughout the code to reduce
    // gas costs.
    public(friend) fun read_field_element(
        ctx: &mut vector<u256>,
        proof: &vector<u256>,
        channel_ptr: u64,
        mix: bool
    ): u256 {
        from_montgomery(read_bytes(ctx, proof, channel_ptr, mix, false))
    }

    public(friend) fun verify_proof_of_work(
        ctx: &mut vector<u256>,
        proof: &vector<u256>,
        channel_ptr: u64,
        proof_of_work_bits: u8
    ) {
        if (proof_of_work_bits == 0) {
            return
        };

        // [0:0x29) := 0123456789abcded || digest     || workBits.
        //             8 bytes          || 0x20 bytes || 1 byte.
        let digest = *borrow(ctx, channel_ptr + 1);

        let proof_ptr = *borrow(ctx, channel_ptr);
        // proofOfWorkDigest:= keccak256(keccak256(0123456789abcded || digest || workBits) || nonce).
        let hash_input = num_to_bytes_le<u64>(&0x0123456789abcdedu64);
        append(&mut hash_input, num_to_bytes_le<u256>(&digest));
        append(&mut hash_input, num_to_bytes_le<u8>(&proof_of_work_bits));
        hash_input = keccak256(hash_input);
        append(&mut hash_input, slice(&num_to_bytes_le<u256>(borrow(proof, (proof_ptr as u64))), 0, 8));
        let proof_of_work_digest = bytes32_to_u256(keccak256(hash_input));

        // prng.digest := keccak256(digest + 1||nonce), nonce was written earlier.
        enumerate_ref(&num_to_bytes_le(&(digest + 1)), |i, byte| {
            set_el(&mut hash_input, i, *byte);
        });
        set_el(ctx, channel_ptr + 1, bytes32_to_u256(keccak256(hash_input)));
        // prng.counter := 0.
        set_el(ctx, channel_ptr + 2, 0);

        let proof_of_work_threshold = 1u256 << ((256 - (proof_of_work_bits as u16)) as u8);
        assert!(proof_of_work_digest < proof_of_work_threshold, EPROOF_OF_WORK_CHECK_FAILED);
    }

    public(friend) fun read_bytes(
        ctx: &mut vector<u256>,
        proof: &vector<u256>,
        channel_ptr: u64,
        mix: bool,
        should_add_8_bytes: bool
    ): u256 {
        let proof_ptr = (*borrow(ctx, channel_ptr) as u64);

        let val = if (should_add_8_bytes) {
            merge_num_offset_8(*borrow(proof, proof_ptr), *borrow(proof, proof_ptr + 1))
        } else {
            *borrow(proof, proof_ptr)
        };

        set_el(ctx, channel_ptr, (proof_ptr + 1 as u256));
        if (mix) {
            let digest = borrow_mut(ctx, channel_ptr + 1);

            // prng.digest := keccak256(digest + 1||val), nonce was written earlier.
            *digest = bytes32_to_u256(keccak256(vec_to_bytes_le(&vector[*digest + 1, val])));
            // prng.counter := 0.
            set_el(ctx, channel_ptr + 2, 0);
        };
        val
    }
}

#[test_only]
module verifier_addr::test_verifier_channel {
    use std::vector::{append, length, slice};
    use aptos_std::aptos_hash::keccak256;

    use lib_addr::bytes::{bytes32_to_u256, num_to_bytes_le};

    #[test]
    fun test_verify_proof_of_work() {
        let proof_of_work_bits = 30u8;
        let digest = 10939379740148575780327786662593165573331175161919867611518579145850604124779u256;

        // let proof_ptr = *borrow(ctx, channel_ptr);
        // proofOfWorkDigest:= keccak256(keccak256(0123456789abcded || digest || workBits) || nonce).
        let hash_input = num_to_bytes_le<u64>(&0x0123456789abcdedu64);
        append(&mut hash_input, num_to_bytes_le<u256>(&digest));
        append(&mut hash_input, num_to_bytes_le<u8>(&proof_of_work_bits));
        hash_input = keccak256(hash_input);
        assert!(
            bytes32_to_u256(
                hash_input
            ) == 6838760435758358717748204741702738474564120725378941118720130852105265839032,
            1
        );
        append(&mut hash_input, slice(&num_to_bytes_le<u256>(
            &(5122894908359966063365751743241561245605455810076508980447074811081u256)
        ), 0, 8));
        assert!(length(&hash_input) == 0x28, 1);
        let proof_of_work_digest = bytes32_to_u256(keccak256(hash_input));
        assert!(
            proof_of_work_digest == 80016376160009073511093101787680069639582489071041857172706540200793300723443,
            1
        );
    }
}