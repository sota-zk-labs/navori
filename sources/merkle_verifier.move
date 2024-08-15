module verifier_addr::merkle_verifier {
    use std::signer::address_of;
    use std::vector;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::math64::ceil_div;
    use aptos_framework::event;

    use verifier_addr::fri::{get_fri, update_fri};
    use verifier_addr::u256_to_byte32::{bytes32_to_u256, u256_to_bytes32};
    use verifier_addr::vector_helper::append_vector;

    // This line is used for generating constants DO NOT REMOVE!
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
    const COMMITMENT_MASK: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000;
    // 1
    const COMMITMENT_SIZE: u64 = 0x1;
    // 32
    const COMMITMENT_SIZE_IN_BYTES: u64 = 0x20;
    // 2
    const EINVALID_MERKLE_PROOF: u64 = 0x2;
    // 1
    const ETOO_MANY_MERKLE_QUERIES: u64 = 0x1;
    // 4
    const EVERIFY_MERKLE_NOT_INITIATED: u64 = 0x4;
    // 1
    const INDEX_SIZE: u64 = 0x1;
    // 110
    const MAX_CYCLES_MERKLE: u64 = 0x6e;
    // 128
    const MAX_N_MERKLE_VERIFIER_QUERIES: u64 = 0x80;
    // 2
    const MERKLE_SLOT_SIZE: u64 = 0x2;
    // 64
    const MERKLE_SLOT_SIZE_IN_BYTES: u64 = 0x40;
    // 2
    const TWO_COMMITMENTS_SIZE: u64 = 0x2;
    // End of generating constants!


    #[event]
    struct Hash has store, drop {
        hash: vector<u8>
    }

    struct Ptr has key, store, drop {
        index: u64,
        proof_ptr: u64,
        rd_idx: u64,
        wr_idx: u64,
    }

    public entry fun init_verify_merkle(
        s: &signer,
        channel_ptr: u256,
        queue_ptr: u256,
    ) acquires Ptr {
        if (exists<Ptr>(address_of(s))) {
            move_from<Ptr>(address_of(s));
        };
        let queue_ptr = (queue_ptr as u64);
        let channel_ptr = (channel_ptr as u64);

        let ffri = get_fri(address_of(s));
        let fri = &mut ffri;
        move_to<Ptr>(
            s,
            Ptr {
                index: (*vector::borrow(fri, queue_ptr) as u64),
                proof_ptr: (*vector::borrow(fri, channel_ptr) as u64),
                rd_idx: 0,
                wr_idx: 0,
            }
        );
        update_fri(s, ffri);
    }

    public entry fun verify_merkle(
        s: &signer,
        channel_ptr: u256,
        queue_ptr: u256,
        root: u256,
        n: u256
    ) acquires Ptr {
        let queue_ptr = (queue_ptr as u64);
        let channel_ptr = (channel_ptr as u64);
        let n = (n as u64);

        assert!(exists<Ptr>(address_of(s)), EVERIFY_MERKLE_NOT_INITIATED);
        let ffri = get_fri(address_of(s));
        let fri = &mut ffri;

        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, ETOO_MANY_MERKLE_QUERIES);

        let ptr = borrow_global_mut<Ptr>(address_of(s));

        let index = ptr.index;
        let proof_ptr = ptr.proof_ptr;
        let rd_idx = ptr.rd_idx;
        let wr_idx = ptr.wr_idx;

        // queuePtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th index in the queue.
        // hashesPtr + i * MERKLE_SLOT_SIZE_IN_BYTES gives the i'th hash in the queue.
        let hashes_ptr = queue_ptr + INDEX_SIZE;
        let queue_size = n * MERKLE_SLOT_SIZE;
        let count = 0;
        while (index > 1 && count < MAX_CYCLES_MERKLE) {
            count = count + 1;
            let sibling_index = index ^ 1;
            // sibblingOffset := COMMITMENT_SIZE_IN_BYTES * lsb(siblingIndex).
            let sibling_offset = (sibling_index * COMMITMENT_SIZE) % TWO_COMMITMENTS_SIZE;
            // Store the hash corresponding to index in the correct slot.
            // 0 if index is even and 0x20 if index is odd.
            // The hash of the sibling will be written to the other slot.
            let hash = *vector::borrow(fri, hashes_ptr + rd_idx);
            *vector::borrow_mut(fri, sibling_offset ^ 1) = hash;
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

            *vector::borrow_mut(fri, wr_idx + queue_ptr) = (index / 2 as u256);

            // Load the next index from the queue and check if it is our sibling.
            index = (*vector::borrow(fri, queue_ptr + rd_idx) as u64);
            if (index == sibling_index) {
                // Take sibling from queue rather than from proof.
                new_hash_ptr = rd_idx + hashes_ptr;
                // Revert reading from proof.
                proof_ptr = proof_ptr - COMMITMENT_SIZE;
                rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

                // Index was consumed, read the next one.
                // Note that the queue can't.txt be empty at this point.
                // The index of the parent of the current node was already pushed into the
                // queue, and the parent is never the sibling.

                index = (*vector::borrow(fri, queue_ptr + rd_idx) as u64);
            };

            let new_hash = *vector::borrow(fri, new_hash_ptr);
            *vector::borrow_mut(fri, sibling_offset) = new_hash;

            let pre_hash = keccak256(
                append_vector(u256_to_bytes32(*vector::borrow(fri, 0)), u256_to_bytes32(*vector::borrow(fri, 1)))
            );

            *vector::borrow_mut(fri, wr_idx + hashes_ptr) = COMMITMENT_MASK & bytes32_to_u256(pre_hash);
            wr_idx = (wr_idx + MERKLE_SLOT_SIZE) % queue_size;
        };

        ptr.index = index;
        ptr.rd_idx = rd_idx;
        ptr.wr_idx = wr_idx;
        ptr.proof_ptr = proof_ptr;

        if (index == 1 || index == 0) {
            let hash = *vector::borrow(fri, hashes_ptr + rd_idx);
            assert!(hash == root, EINVALID_MERKLE_PROOF);
            event::emit<Hash>(Hash { hash: u256_to_bytes32(hash) });

            *vector::borrow_mut(fri, channel_ptr) = (proof_ptr as u256);
            move_from<Ptr>(address_of(s));
        };
        update_fri(s, ffri);
    }

    #[view]
    public fun count_verify_merkle_cycles(
        s: address,
        queue_ptr: u256,
        n: u256
    ): u64 {
        let queue_ptr = (queue_ptr as u64);
        let n = (n as u64);

        let ffri = get_fri(s);
        let fri = &mut ffri;
        
        assert!(n <= MAX_N_MERKLE_VERIFIER_QUERIES, ETOO_MANY_MERKLE_QUERIES);
        let index = *vector::borrow(fri, queue_ptr);
        let rd_idx = 0;
        let wr_idx = 0;

        let queue_size = n * MERKLE_SLOT_SIZE;
        let count = 0;

        while (index > 1) {
            let sibling_index = index ^ 1;
            rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;
            *vector::borrow_mut(fri, wr_idx + queue_ptr) = index / 2;
            index = *vector::borrow(fri, queue_ptr + rd_idx);
            if (index == sibling_index) {
                rd_idx = (rd_idx + MERKLE_SLOT_SIZE) % queue_size;

                index = *vector::borrow(fri, queue_ptr + rd_idx);
            };

            wr_idx = (wr_idx + MERKLE_SLOT_SIZE) % queue_size;
            count = count + 1;
        };
        ceil_div(count, MAX_CYCLES_MERKLE)
    }
}



