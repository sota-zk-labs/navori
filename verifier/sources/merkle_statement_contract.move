module verifier_addr::merkle_statement_contract {
    use std::signer::address_of;
    use std::vector;
    use std::vector::length;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::math64::pow;
    use aptos_framework::event;

    use lib_addr::bytes::{bytes32_to_u256, u256_to_bytes32};
    use lib_addr::convert_memory::copy_vec_to_memory;
    use verifier_addr::fact_registry::register_fact;
    use verifier_addr::fri::{get_fri, new_fri, update_fri};

    // This line is used for generating constants DO NOT REMOVE!
    // 1
    const EHEIGHT_MUST_BE_LESS_THAN_200: u64 = 0x1;
    // 2
    const EINVALID_MERKLE_INDICES: u64 = 0x2;
    // 6
    const EODD_MERKLE_QUEUE_SIZE: u64 = 0x6;
    // 1
    const ETOO_MANY_MERKLE_QUERIES: u64 = 0x1;
    // 128
    const MAX_N_MERKLE_VERIFIER_QUERIES: u64 = 0x80;
    // 2
    const MERKLE_SLOT_SIZE: u64 = 0x2;
    // End of generating constants!

    #[event]
    struct VerifyMerkle has store, drop {
        channel_ptr: u64,
        merkle_queue_ptr: u64,
        expected_root: u256,
        n_queries: u64
    }

    #[event]
    struct RegisterFactVerifyMerkle has store, drop {
        channel_ptr: u64,
        data_to_hash_ptr: u64,
        n_queries: u64,
        res_root: u256
    }


    public entry fun verify_merkle(
        s: &signer,
        merkle_view: vector<u256>,
        initial_merkle_queue: vector<u256>,
        height: u64,
        expected_root: u256
    ) {
        assert!(height < 200, EHEIGHT_MUST_BE_LESS_THAN_200);
        assert!(length(&initial_merkle_queue) <= MAX_N_MERKLE_VERIFIER_QUERIES * 2, ETOO_MANY_MERKLE_QUERIES);
        assert!(length(&initial_merkle_queue) % 2 == 0, EODD_MERKLE_QUEUE_SIZE);

        //init
        let fri = &mut new_fri();

        // Let merkleViewPtr point to a free space in fri.
        let merkle_view_ptr = 4;
        // let initialMerkleQueuePtr point to a free space in fri.
        let initial_merkle_queue_ptr = length(&merkle_view) + 5;

        // Copy the merkleView and initialMerkleQueue to fri.
        *vector::borrow_mut(fri, merkle_view_ptr) = (length(&merkle_view) as u256);
        copy_vec_to_memory(merkle_view, fri, 5);

        *vector::borrow_mut(fri, initial_merkle_queue_ptr) = (vector::length(&initial_merkle_queue) as u256);
        copy_vec_to_memory(initial_merkle_queue, fri, initial_merkle_queue_ptr + 1);

        // Skip 0x20 bytes length at the beginning of the merkleView.
        merkle_view_ptr = merkle_view_ptr + 1;
        // Let channelPtr point to a free space.
        let channel_ptr: u64 = initial_merkle_queue_ptr + length(&initial_merkle_queue) + 1;
        // channelPtr will point to the merkleViewPtr since the 'verify' function expects
        // a pointer to the proofPtr.
        *vector::borrow_mut(fri, channel_ptr) = (merkle_view_ptr as u256);
        // Skip 0x20 bytes length at the beginning of the initialMerkleQueue.
        let merkle_queue_ptr = initial_merkle_queue_ptr + 1 ;
        // Get number of queries.
        let n_queries = (*vector::borrow(fri, initial_merkle_queue_ptr) / 2 as u64);
        // Get a pointer to the end of initialMerkleQueue.
        let initial_merkle_queue_end_ptr = merkle_queue_ptr + (n_queries * MERKLE_SLOT_SIZE);
        // Let dataToHashPtr point to a free memory.
        let data_to_hash_ptr = channel_ptr + 1;

        // Copy initialMerkleQueue to dataToHashPtr and validaite the indices.
        // The indices need to be in the range [2**height..2*(height+1)-1] and
        // strictly incrementing.

        // First index needs to be >= 2**height.
        let idx_lower_limit = ((pow(2, height) / 32) as u256);

        // Basically just copying all initial_merkle_queue into other memory slot
        // Then the sanity check that the indices are sorted and the overflow check
        while (merkle_queue_ptr < initial_merkle_queue_end_ptr) {
            let cur_idx = *vector::borrow(fri, merkle_queue_ptr);

            // Sanity check that the indices are sorted.
            assert!(cur_idx >= idx_lower_limit, EINVALID_MERKLE_INDICES);

            // The next idx must be at least curIdx + 1. Ensure it doesn't overflow.
            idx_lower_limit = cur_idx + 1;
            assert!(idx_lower_limit != 0, EINVALID_MERKLE_INDICES);

            // Copy the pair (idx, hash) to the dataToHash array.
            *vector::borrow_mut(fri, data_to_hash_ptr) = cur_idx;

            let value_store = *vector::borrow(fri, merkle_queue_ptr + 1);
            *vector::borrow_mut(fri, data_to_hash_ptr + 1) = value_store;
            data_to_hash_ptr = data_to_hash_ptr + 2;
            merkle_queue_ptr = merkle_queue_ptr + MERKLE_SLOT_SIZE;
        };

        // We need to enforce that lastIdx < 2**(height+1)
        // => fail if lastIdx >= 2**(height+1)
        // => fail if (lastIdx + 1) > 2**(height+1)
        // => fail if idxLowerLimit > 2**(height+1).

        // Check the last idx_lower_limit must inside the index range.
        assert!(idx_lower_limit <= (pow(2, height + 1) as u256), EINVALID_MERKLE_INDICES);

        // Reset merkleQueuePtr.
        merkle_queue_ptr = initial_merkle_queue_ptr + 1;
        // Let freePtr point to a free memory (one word after the copied queries - reserved
        // for the root).
        *vector::borrow_mut(fri, 2) = (data_to_hash_ptr + 1 as u256);

        update_fri(s, *fri);
        // Verify the merkle tree.
        event::emit<VerifyMerkle>(VerifyMerkle {
            channel_ptr,
            merkle_queue_ptr,
            expected_root,
            n_queries
        });

        event::emit<RegisterFactVerifyMerkle>(RegisterFactVerifyMerkle {
            channel_ptr,
            data_to_hash_ptr,
            n_queries,
            res_root: expected_root
        });
    }

    public entry fun register_fact_verify_merkle(
        s: &signer,
        channel_ptr: u64,
        data_to_hash_ptr: u64,
        n_queries: u64,
        res_root: u256
    ) {
        let fri = &mut get_fri(address_of(s));

        *vector::borrow_mut(fri, data_to_hash_ptr) = res_root;
        data_to_hash_ptr = channel_ptr + 1;

        //input_hash has range from data_to_hash_ptr to data_to_hash_ptr + n_queries * 2.
        let input_hash = vector::empty();
        for (i in 0..(n_queries * 2 + 1)) {
            vector::append(
                &mut input_hash,
                u256_to_bytes32(vector::borrow(fri, data_to_hash_ptr + i))
            );
        };
        // register fact
        register_fact(s, bytes32_to_u256(keccak256(input_hash)));
    }
}
