module verifier_addr::gps_output_parser {
    use std::vector::borrow;
    use std::vector::slice;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::vector;
    use aptos_framework::event::emit;

    use lib_addr::bytes::{bytes32_to_u256, vec_to_bytes_le};
    use lib_addr::vector::{assign, set_el};
    use verifier_addr::fact_registry::register_fact;

    friend verifier_addr::gps_statement_verifier;

    // This line is used for generating constants DO NOT REMOVE!
    // 3
    const EINVALID_PAGE_ADDRESS: u64 = 0x3;
    // 2
    const EINVALID_PAGE_SIZE: u64 = 0x2;
    // 8
    const EINVALID_VALUE_OF_N_NODES_IN_TREE_STRUCTURE: u64 = 0x8;
    // 1
    const EINVALID_VALUE_OF_N_PAGES_IN_TREE_STRUCTURE: u64 = 0x1;
    // 6
    const ENODE_STACK_MUST_CONTAIN_EXACTLY_ONE_ITEM: u64 = 0x6;
    // 7
    const ENOT_ALL_MEMORY_PAGES_WERE_PROCESSED: u64 = 0x7;
    // 5
    const ESUM_OF_THE_PAGE_SIZES_DOES_NOT_MATCH_OUTPUT_SIZE: u64 = 0x5;
    // 1
    const FIRST_CONTINUOUS_PAGE_INDEX: u64 = 0x1;
    // 2
    const METADATA_OFFSET_TASK_N_TREE_PAIRS: u64 = 0x2;
    // 0
    const METADATA_OFFSET_TASK_OUTPUT_SIZE: u64 = 0x0;
    // 1
    const METADATA_OFFSET_TASK_PROGRAM_HASH: u64 = 0x1;
    // 1
    const METADATA_OFFSET_TREE_PAIR_N_NODES: u64 = 0x1;
    // 0
    const METADATA_OFFSET_TREE_PAIR_N_PAGES: u64 = 0x0;
    // 1
    const METADATA_TASKS_OFFSET: u64 = 0x1;
    // 3
    const METADATA_TASK_HEADER_SIZE: u64 = 0x3;
    // 2
    const NODE_STACK_ITEM_SIZE: u64 = 0x2;
    // 1
    const NODE_STACK_OFFSET_END: u64 = 0x1;
    // 0
    const NODE_STACK_OFFSET_HASH: u64 = 0x0;
    // 0
    const PAGE_INFO_ADDRESS_OFFSET: u64 = 0x0;
    // 2
    const PAGE_INFO_HASH_OFFSET: u64 = 0x2;
    // 3
    const PAGE_INFO_SIZE: u64 = 0x3;
    // 1
    const PAGE_INFO_SIZE_OFFSET: u64 = 0x1;
    // End of generating constants!

    // Logs the program output fact together with the relevant continuous memory pages' hashes.
    // The event is emitted for each registered fact.
    #[event]
    struct LogMemoryPagesHashes has drop, store {
        program_output_fact: u256,
        pages_hashes: vector<u256>,
    }


    // Parses the GPS program output (using taskMetadata, which should be verified by the caller),
    // and registers the facts of the tasks which were executed.
    //
    // The first entry in taskMetadata is the number of tasks.
    //
    // For each task, the structure is as follows:
    //   1. Size (including the size and hash fields).
    //   2. Program hash.
    //   3. The number of pairs in the Merkle tree structure (see below).
    //   4. The Merkle tree structure (see below).
    //
    // The fact of each task is stored as a (non-binary) Merkle tree.
    // Leaf nodes are labeled with the hash of their data.
    // Each non-leaf node is labeled as 1 + the hash of (node0, end0, node1, end1, ...)
    // where node* is a label of a child children and end* is the total number of data words up to
    // and including that node and its children (including the previous sibling nodes).
    // We add 1 to the result of the hash to prevent an attacker from using a preimage of a leaf node
    // as a preimage of a non-leaf hash and vice versa.
    //
    // The structure of the tree is passed as a list of pairs (n_pages, n_nodes), and the tree is
    // constructed using a stack of nodes (initialized to an empty stack) by repeating for each pair:
    // 1. Add n_pages to the stack of nodes.
    // 2. Pop the top n_nodes, construct a parent node for them, and push it back to the stack.
    // After applying the steps above, the stack much contain exactly one node, which will
    // constitute the root of the Merkle tree.
    // For example, [(2, 2)] will create a Merkle tree with a root and two direct children, while
    // [(3, 2), (0, 2)] will create a Merkle tree with a root whose left child is a leaf and
    // right child has two leaf children.
    //
    // Assumptions: taskMetadata and cairoAuxInput are verified externally.
    public(friend) fun register_gps_facts(
        signer: &signer,
        task_metadata: &vector<u256>,
        public_memory_pages: &vector<u256>,
        output_start_address: u256
    ) {
        let total_num_pages = (*borrow(public_memory_pages, 0) as u64);
        let n_task = (*borrow(task_metadata, 0) as u64);

        // Contains fact hash with the relevant memory pages' hashes.
        // Size is bounded from above with the total number of pages. Three extra places are
        // dedicated for the fact hash and the array address and length.
        let page_hashed_log_data = assign(0u256, total_num_pages + 3);
        // Relative address to the beginning of the memory pages' hashes in the array.
        set_el(&mut page_hashed_log_data, 1, 0x40);

        let task_metadata_offset = METADATA_TASKS_OFFSET;

        // Skip the 5 first output cells which contain the bootloader config, the number of tasks
        // and the size and program hash of the first task. curAddr points to the output of the
        // first task.
        let cur_addr = output_start_address + 5;

        // Skip the main page.
        let cur_page = FIRST_CONTINUOUS_PAGE_INDEX;

        // Bound the size of the stack by the total number of pages.
        // TODO(lior, 15/04/2022): Get a better bound on the size of the stack.
        let node_stack = assign(0u256, NODE_STACK_ITEM_SIZE * total_num_pages);

        // Skip the array length and the first page.
        let page_info_ptr_start = PAGE_INFO_SIZE;
        // Register the fact for each task.
        for (task in 0..n_task) {
            let cur_offset = 0;
            let first_page_of_task = cur_page;
            let n_tree_pairs = (*borrow(
                task_metadata,
                task_metadata_offset + METADATA_OFFSET_TASK_N_TREE_PAIRS
            ) as u64);

            // Build the Merkle tree using a stack (see the function documentation) to compute the fact.
            let node_stack_len = 0;
            for (tree_pairs in 0..n_tree_pairs) {
                let n_pages = *borrow(task_metadata,
                    (task_metadata_offset + METADATA_TASK_HEADER_SIZE
                        + 2 * tree_pairs + METADATA_OFFSET_TREE_PAIR_N_PAGES)
                );

                // Ensure 'nPages' is bounded from above as a sanity check
                // (the bound is somewhat arbitrary).
                assert!(n_pages <= (1 << 20), EINVALID_VALUE_OF_N_PAGES_IN_TREE_STRUCTURE);
                for (i in 0..n_pages) {
                    let page_info_ptr = slice(public_memory_pages, page_info_ptr_start,
                        page_info_ptr_start + PAGE_INFO_SIZE
                    );
                    let (page_size, page_hash) = push_page_to_stack(
                        &page_info_ptr,
                        cur_addr,
                        cur_offset,
                        &mut node_stack,
                        node_stack_len
                    );
                    set_el(&mut page_hashed_log_data, cur_page - first_page_of_task + 3, page_hash);
                    cur_page = cur_page + 1;
                    node_stack_len = node_stack_len + 1;
                    cur_addr = cur_addr + page_size;
                    cur_offset = cur_offset + page_size;

                    page_info_ptr_start = page_info_ptr_start + PAGE_INFO_SIZE;
                };
                let n_nodes = (*vector::borrow(task_metadata,
                    (task_metadata_offset + METADATA_TASK_HEADER_SIZE
                        + 2 * tree_pairs + METADATA_OFFSET_TREE_PAIR_N_NODES)
                ) as u64);
                if (n_nodes != 0) {
                    node_stack_len = construct_node(&mut node_stack, node_stack_len, n_nodes);
                }
            };
            assert!(node_stack_len == 1, ENODE_STACK_MUST_CONTAIN_EXACTLY_ONE_ITEM);
            let program_hash = *vector::borrow(
                task_metadata,
                task_metadata_offset + METADATA_OFFSET_TASK_PROGRAM_HASH
            );

            // Verify that the sizes of the pages correspond to the task output, to make
            // sure that the computed hash is indeed the hash of the entire output of the task.
            {
                let output_size = *borrow(
                    task_metadata,
                    task_metadata_offset + METADATA_OFFSET_TASK_OUTPUT_SIZE
                );

                assert!(
                    *borrow(&node_stack, NODE_STACK_OFFSET_END) + 2 == output_size,
                    ESUM_OF_THE_PAGE_SIZES_DOES_NOT_MATCH_OUTPUT_SIZE
                );
            };

            let program_output_fact = *vector::borrow(&node_stack, NODE_STACK_OFFSET_HASH);
            let fact = bytes32_to_u256(
                keccak256(vec_to_bytes_le(&vector[program_hash, program_output_fact]))
            );
            task_metadata_offset = task_metadata_offset + METADATA_TASK_HEADER_SIZE + 2 * n_tree_pairs;

            {
                // Emit the output Merkle root with the hashes of the relevant memory pages.
                // set_el(&mut page_hashed_log_data, 0, program_output_fact);
                let length = cur_page - first_page_of_task;
                set_el(&mut page_hashed_log_data, 2, (length as u256));
                emit(LogMemoryPagesHashes {
                    program_output_fact,
                    pages_hashes: slice(&mut page_hashed_log_data, 1, length + 3),
                });
            };

            register_fact(signer, fact);
            cur_addr = cur_addr + 2;
        };

        assert!(total_num_pages == cur_page, ENOT_ALL_MEMORY_PAGES_WERE_PROCESSED);
    }

    fun push_page_to_stack(
        page_info_ptr: &vector<u256>,
        cur_addr: u256,
        cur_offset: u256,
        node_stack: &mut vector<u256>,
        node_stack_len: u64
    ): (u256, u256) {
        let page_addr = *borrow(page_info_ptr, PAGE_INFO_ADDRESS_OFFSET);
        let page_size = *borrow(page_info_ptr, PAGE_INFO_SIZE_OFFSET);
        let page_hash = *borrow(page_info_ptr, PAGE_INFO_HASH_OFFSET);
        assert!(page_size < (1 << 30), EINVALID_PAGE_SIZE);
        assert!(page_addr == cur_addr, EINVALID_PAGE_ADDRESS);

        set_el(
            node_stack,
            NODE_STACK_ITEM_SIZE * node_stack_len + NODE_STACK_OFFSET_END,
            cur_offset + page_size
        );
        set_el(
            node_stack,
            NODE_STACK_ITEM_SIZE * node_stack_len + NODE_STACK_OFFSET_HASH,
            page_hash
        );

        (page_size, page_hash)
    }

    fun construct_node(
        node_stack: &mut vector<u256>,
        node_stack_len: u64,
        n_nodes: u64,
    ): u64 {
        assert!(n_nodes <= node_stack_len, EINVALID_VALUE_OF_N_NODES_IN_TREE_STRUCTURE);
        let new_node_end = *borrow(node_stack,
            NODE_STACK_ITEM_SIZE * (node_stack_len - 1) + NODE_STACK_OFFSET_END
        );
        let new_stack_len = node_stack_len - n_nodes;
        let node_start = 1 + new_stack_len * NODE_STACK_ITEM_SIZE;
        let new_node_hash = bytes32_to_u256(
            keccak256(vec_to_bytes_le(&slice(node_stack, node_start, node_start + n_nodes * 2)))
        );

        set_el(node_stack, NODE_STACK_ITEM_SIZE * new_stack_len + NODE_STACK_OFFSET_END, new_node_end);
        set_el(node_stack, NODE_STACK_ITEM_SIZE * new_stack_len + NODE_STACK_OFFSET_HASH, new_node_hash + 1);

        new_stack_len + 1
    }
}