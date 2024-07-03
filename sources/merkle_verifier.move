module verifier_addr::merkle_verifier {
    use std::signer::address_of;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::simple_map::{borrow, upsert};
    use aptos_framework::event;

    use verifier_addr::u256_to_byte32::{bytes32_to_u256, u256_to_bytes32};
    use verifier_addr::vector_helper::append_vector;
    use verifier_addr::fri::{get_fri, reset_memory_fri, update_fri};

    const MAX_N_MERKLE_VERIFIER_QUERIES: u256 = 128;
    const MERKLE_SLOT_SIZE: u256 = 2;
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    const COMMITMENT_SIZE: u256 = 1;
    const TWO_COMMITMENTS_SIZE: u256 = 2;
    const INDEX_SIZE: u256 = 1;

    //error
    const TOO_MANY_MERKLE_QUERIES: u64 = 1;
    const INVALID_MERKLE_PROOF: u64 = 3;

    #[event]
    struct Hash has drop, store {
        hash: u256
    }

    struct Ptr has key, store {
        index: u256,
        proof_ptr: u256,
        rd_idx: u256,
        wr_idx: u256,
        is_loop: bool,
        looped: u256
    }


    public entry fun verify_merkle(
        s: &signer,
        channel_ptr: u256,
        queue_ptr: u256,
        root: u256,
        n: u256
    ) acquires Ptr {
        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, TOO_MANY_MERKLE_QUERIES);

        let fri = &mut get_fri(address_of(s));
        if (!exists<Ptr>(address_of(s))) {
            move_to<Ptr>(s, Ptr {
                index: *borrow(fri, &queue_ptr),
                proof_ptr: 0, rd_idx: 0, wr_idx: 0, is_loop: false, looped: 5
            });
        };
        let index;
        let proof_ptr;
        let rd_idx;
        let wr_idx;
        let looped;

        if (borrow_global<Ptr>(address_of(s)).is_loop) {
            index = borrow_global<Ptr>(address_of(s)).index;
            proof_ptr = borrow_global<Ptr>(address_of(s)).proof_ptr;
            rd_idx = borrow_global<Ptr>(address_of(s)).rd_idx;
            wr_idx = borrow_global<Ptr>(address_of(s)).wr_idx;
            looped = borrow_global<Ptr>(address_of(s)).looped;
        } else {
            index = *borrow(fri, &queue_ptr);
            proof_ptr = *borrow(fri, &channel_ptr);
            rd_idx = 0;
            wr_idx = 0;
            borrow_global_mut<Ptr>(address_of(s)).is_loop = true;
            looped = borrow_global<Ptr>(address_of(s)).looped;
        };


        // queuePtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th index in the queue.
        // hashesPtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th hash in the queue.
        let hashes_ptr = queue_ptr + INDEX_SIZE;
        let queue_size = n * MERKLE_SLOT_SIZE;

        while (index > 1 && check_in_mloop(address_of(s)) && looped > 0) {
            let sibling_index = index ^ 1;
            // sibblingOffset := COMMITMENT_SIZE_IN_BYTES * lsb(siblingIndex).
            let sibling_offset = (sibling_index * COMMITMENT_SIZE) % TWO_COMMITMENTS_SIZE;
            // Store the hash corresponding to index in the correct slot.
            // 0 if index is even and 0x20 if index is odd.
            // The hash of the sibling will be written to the other slot.
            let hash = *borrow(fri, &(hashes_ptr + rd_idx));
            upsert(fri, (sibling_offset ^ 1), hash);

            rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

            // Inline channel operation:
            // Assume we are going to read a new hash from the proof.
            // If this is not the case add(proofPtr, COMMITMENT_SIZE_IN_BYTES) will be reverted.

            let new_hash_ptr = proof_ptr;
            proof_ptr = proof_ptr + COMMITMENT_SIZE;

            // Push index/2 into the queue, before reading the next index.
            // The order is important, as otherwise we may try to read from an empty queue (in
            // the case where we are working on one item).
            // wrIdx will be updated after writing the relevant hash to the queue.

            upsert(fri, (wr_idx + queue_ptr), index / 2);

            // Load the next index from the queue and check if it is our sibling.
            index = *borrow(fri, &(queue_ptr + rd_idx));
            if (index == sibling_index) {
                // Take sibling from queue rather than from proof.
                new_hash_ptr = rd_idx + hashes_ptr;
                // Revert reading from proof.
                proof_ptr = proof_ptr - COMMITMENT_SIZE;
                rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

                // Index was consumed, read the next one.
                // Note that the queue can't be empty at this point.
                // The index of the parent of the current node was already pushed into the
                // queue, and the parent is never the sibling.

                index = *borrow(fri, &(queue_ptr + rd_idx));
            };

            let new_hash = *borrow(fri, &new_hash_ptr);

            upsert(fri, sibling_offset, new_hash);
            let pre_hash = keccak256(
                append_vector(u256_to_bytes32(*borrow(fri, &0)), u256_to_bytes32(*borrow(fri, &1)))
            );
            upsert(fri, (wr_idx + hashes_ptr), COMMITMENT_MASK & bytes32_to_u256(pre_hash));
            wr_idx = (wr_idx + MERKLE_SLOT_SIZE) % queue_size;
            looped = looped - 1;

            borrow_global_mut<Ptr>(address_of(s)).index = index;
            borrow_global_mut<Ptr>(address_of(s)).rd_idx = rd_idx;
            borrow_global_mut<Ptr>(address_of(s)).wr_idx = wr_idx;
            borrow_global_mut<Ptr>(address_of(s)).proof_ptr = proof_ptr;
        };
        update_fri(s, *freeze(fri));
        if (index == 1 || index == 0) {
            borrow_global_mut<Ptr>(address_of(s)).is_loop = false;
            let hash = *borrow(fri, &(hashes_ptr + rd_idx));
            upsert(fri, channel_ptr, proof_ptr);
            event::emit<Hash>(Hash { hash });
            assert!(hash == root, INVALID_MERKLE_PROOF);

            reset_memory_fri(s);
        };
    }

    #[view]
    public fun check_in_mloop(s: address): bool acquires Ptr {
        borrow_global<Ptr>(s).is_loop
    }

    public entry fun set_loop(s: address, looped: u256) acquires Ptr {
        borrow_global_mut<Ptr>(s).looped = looped;
    }
}


