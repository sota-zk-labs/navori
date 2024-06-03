module verifier_addr::gps_output_parser {
    use std::vector;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::bcs;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::math128::pow;
    use verifier_addr::fact_registry::register_fact;
    use verifier_addr::memory_page_fact_registry::append_vector;
    use verifier_addr::page_info::{get_page_info_size_in_bytes, get_page_info_size};
    use verifier_addr::fact_registry;
    use verifier_addr::cpu_public_input_offset_base;
    use verifier_addr::page_info;

    const METADATA_TASKS_OFFSET: u256 = 1;
    const METADATA_OFFSET_TASK_OUTPUT_SIZE: u256 = 0;
    const METADATA_OFFSET_TASK_PROGRAM_HASH: u256 = 1;
    const METADATA_OFFSET_TASK_N_TREE_PAIRS: u256 = 2;
    const METADATA_TASK_HEADER_SIZE: u256 = 3;

    const METADATA_OFFSET_TREE_PAIR_N_PAGES: u256 = 0;
    const METADATA_OFFSET_TREE_PAIR_N_NODES: u256 = 1;

    const NODE_STACK_OFFSET_HASH: u256 = 0;
    const NODE_STACK_OFFSET_END: u256 = 1;
    // The size of each node in the node stack.
    const NODE_STACK_ITEM_SIZE: u256 = 2;

    const FIRST_CONTINUOUS_PAGE_INDEX: u256 = 1;

    #[event]
    struct LogMemoryPagesHashes has drop, copy {
        program_output_fact: vector<u8>,
        referal_duration: vector<u8>,
    }

    fun initialize(s: &signer, ref_fact_registry: address, referal_duration: u64) {
        fact_registry::init_fact_registry(s, ref_fact_registry, referal_duration);
    }

    fun register_gps_fact(
        task_metadata: vector<u256>,
        public_memory_pages: vector<u256>,
        output_start_address: u256
    ) {
        let total_num_pages = vector::borrow(&public_memory_pages, 0);

        let task: u256;
        let n_tree_pairs: u256;
        let n_task = *vector::borrow(&task_metadata, 0);

        let page_hashed_log_data = vector::empty<u256>();
        vector::insert(&mut page_hashed_log_data, 1, 0x40);

        let task_metadata_offset = METADATA_TASKS_OFFSET;

        let cur_addr = output_start_address + 5;

        let cur_page = FIRST_CONTINUOUS_PAGE_INDEX;

        let node_stack = vector::empty<u256>();

        let task_meta_data_copy = task_metadata;

        let page_info_ptr = vector::empty<u256>();
        page_info_ptr = vector::slice(&public_memory_pages, 1, vector::length(&public_memory_pages));
        let task = 0;
        loop {
            let cur_offset = 0;
            let first_page_of_task = cur_page;
            let n_tree_pairs = *vector::borrow(&task_meta_data_copy, (METADATA_OFFSET_TASK_N_TREE_PAIRS as u64));
            let node_stack_len = 0;

            for (tree_pairs in 0..n_tree_pairs) {
                let n_pages = *vector::borrow(&task_meta_data_copy,
                    ((task_metadata_offset + METADATA_TASK_HEADER_SIZE + 2 * tree_pairs + METADATA_OFFSET_TREE_PAIR_N_PAGES) as u64)
                );
                for (i in 0..n_pages) {
                    let (page_size, page_hash) = push_page_to_stack(
                        page_info_ptr,
                        cur_addr,
                        cur_offset,
                        node_stack,
                        node_stack_len
                    );
                    vector::insert(&mut page_hashed_log_data, (cur_page - first_page_of_task + 3 as u64), page_hash);
                    cur_page = cur_page + 1;
                    node_stack_len = node_stack_len + 1;
                    cur_addr = cur_addr + page_size;
                    cur_offset = cur_offset + page_size;
                    page_info_ptr = vector::slice(&page_info_ptr, 3, vector::length(&page_info_ptr));
                };
                let n_nodes = *vector::borrow(&task_meta_data_copy,
                    ((task_metadata_offset + METADATA_TASK_HEADER_SIZE + 2 * tree_pairs + METADATA_OFFSET_TREE_PAIR_N_NODES) as u64)
                );
                if (n_nodes != 0) {
                    node_stack_len = construct_node(node_stack, node_stack_len, n_nodes);
                };
            };
            assert!(node_stack_len == 1, 10);
            let program_hash = *vector::borrow(
                &task_meta_data_copy,
                (task_metadata_offset + METADATA_OFFSET_TASK_PROGRAM_HASH as u64)
            );
            let program_output_fact = *vector::borrow(&node_stack, (NODE_STACK_OFFSET_HASH as u64));
            let fact = keccak256(bcs::to_bytes(&(program_hash + program_output_fact)));
            task_metadata_offset = task_metadata_offset + METADATA_TASK_HEADER_SIZE + 2 * n_tree_pairs;
            register_fact(fact);
            cur_addr = cur_addr + 2;
            task = task + 1;
            if (task < n_task) {
                break;
            };
        };
    }

    fun push_page_to_stack(
        page_info_prt: vector<u256>,
        cur_addr: u256,
        cur_offset: u256,
        node_stack: vector<u256>,
        node_stack_len: u256): (u256, u256) {
        let page_addr = *vector::borrow(&page_info_prt, page_info::get_page_info_address_offset());
        let page_size = *vector::borrow(&page_info_prt, page_info::get_page_info_size_offset());
        let page_hash = *vector::borrow(&page_info_prt, page_info::get_page_info_hash_offset());

        assert!(page_addr == cur_addr, 8);

        vector::insert(&mut node_stack,
            (NODE_STACK_ITEM_SIZE * node_stack_len + NODE_STACK_OFFSET_END as u64), cur_offset + page_size);
        vector::insert(&mut node_stack,
            (NODE_STACK_ITEM_SIZE * node_stack_len + NODE_STACK_OFFSET_HASH as u64), page_hash);
        (page_size, page_hash)
    }

    fun construct_node(
        node_stack: vector<u256>,
        node_stack_len: u256,
        n_nodes: u256,
    ): u256 {
        assert!(n_nodes <= node_stack_len, 9);
        let new_node_end = *vector::borrow(&node_stack,
            (NODE_STACK_ITEM_SIZE * (node_stack_len - 1) + NODE_STACK_OFFSET_END as u64)
        );
        let new_stack_len = node_stack_len - n_nodes;
        let node_start = 1 + new_stack_len * NODE_STACK_ITEM_SIZE;
        let new_node_hash = to_u256(keccak256(bcs::to_bytes(&vector::slice(&node_stack,
            (node_start as u64), (node_start + n_nodes * NODE_STACK_ITEM_SIZE as u64)))));
        vector::insert(&mut node_stack,
            (NODE_STACK_ITEM_SIZE * new_stack_len + NODE_STACK_OFFSET_END as u64), new_node_end);
        vector::insert(&mut node_stack,
            (NODE_STACK_ITEM_SIZE * new_stack_len + NODE_STACK_OFFSET_HASH as u64), new_node_hash + 1);
        new_stack_len + 1
    }
}
