module verifier_addr::gps_output_parser {

    //libs
    use std::bcs;
    use std::vector::for_each;
    use std::vector::length;
    use std::vector::{borrow, insert};
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::from_bcs::to_u256;
    use aptos_std::math64::pow;
    use aptos_std::vector;

    use lib_addr::endia_encode::to_big_endian;
    use lib_addr::memory;
    use lib_addr::memory::{allocate, Memory, mloadrange};
    use verifier_addr::fact_registry::register_fact;
    use verifier_addr::page_info::{PAGE_INFO_ADDRESS_OFFSET, PAGE_INFO_HASH_OFFSET, PAGE_INFO_SIZE_IN_BYTES,
        PAGE_INFO_SIZE_OFFSET
    };

    //modules
    //error codes
    const INVALID_VALUE_OF_N_PAGES_IN_TREE_STRUCTURE: u64 = 1;
    const INVALID_PAGE_SIZE: u64 = 2;
    const INVALID_PAGE_ADDRESS: u64 = 3;


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
    /*
      Logs the program output fact together with the relevant continuous memory pages' hashes.
      The event is emitted for each registered fact.
    */
    #[event]
    struct LogMemoryPagesHashes has drop, copy {
        program_output_fact: vector<u8>,
        pages_hashes: vector<u8>,
    }


    /*
      Parses the GPS program output (using taskMetadata, which should be verified by the caller),
      and registers the facts of the tasks which were executed.

      The first entry in taskMetadata is the number of tasks.

      For each task, the structure is as follows:
        1. Size (including the size and hash fields).
        2. Program hash.
        3. The number of pairs in the Merkle tree structure (see below).
        4. The Merkle tree structure (see below).

      The fact of each task is stored as a (non-binary) Merkle tree.
      Leaf nodes are labeled with the hash of their data.
      Each non-leaf node is labeled as 1 + the hash of (node0, end0, node1, end1, ...)
      where node* is a label of a child children and end* is the total number of data words up to
      and including that node and its children (including the previous sibling nodes).
      We add 1 to the result of the hash to prevent an attacker from using a preimage of a leaf node
      as a preimage of a non-leaf hash and vice versa.

      The structure of the tree is passed as a list of pairs (n_pages, n_nodes), and the tree is
      constructed using a stack of nodes (initialized to an empty stack) by repeating for each pair:
      1. Add n_pages to the stack of nodes.
      2. Pop the top n_nodes, construct a parent node for them, and push it back to the stack.
      After applying the steps above, the stack much contain exactly one node, which will
      constitute the root of the Merkle tree.
      For example, [(2, 2)] will create a Merkle tree with a root and two direct children, while
      [(3, 2), (0, 2)] will create a Merkle tree with a root whose left child is a leaf and
      right child has two leaf children.

      Assumptions: taskMetadata and cairoAuxInput are verified externally.
    */


    fun register_gps_fact(
        signer: &signer,
        task_metadata: vector<u256>,
        public_memory_pages: vector<u256>,
        output_start_address: u256
    ) {
        // Allocate memory.
        let memory = memory::new();
        let public_memory_pages_ptr = allocate(&mut memory, (length(&public_memory_pages) as u256));
        for_each(public_memory_pages, |p|{
            allocate(&mut memory, p);
        });

        let total_num_pages = *borrow(&public_memory_pages, 0);

        let task: u256;
        let n_tree_pairs: u256;
        let n_task = *borrow(&task_metadata, 0);

        // Contains fact hash with the relevant memory pages' hashes.
        // Size is bounded from above with the total number of pages. Three extra places are
        // dedicated for the fact hash and the array address and length.
        let page_hashed_log_data = vector::empty<u256>();
        insert(&mut page_hashed_log_data, 1, 0x40);

        let task_metadata_offset = METADATA_TASKS_OFFSET;

        let cur_addr = output_start_address + 5;

        let cur_page = FIRST_CONTINUOUS_PAGE_INDEX;

        let node_stack = vector::empty<u256>();

        let task_meta_data_copy = task_metadata;

        let page_info_ptr = vector::empty<u256>();

        // page_info_ptr will take 3 elements from the public_memory_pages vector start from index 3.
        // Skip the array length and the first page.
        page_info_ptr = vector::slice(&public_memory_pages, (public_memory_pages_ptr + 0x20 as u64),
            (PAGE_INFO_SIZE_IN_BYTES() as u64)
        );


        for (task in 0..n_task) {
            let cur_offset = 0;
            let first_page_of_task = cur_page;
            let n_tree_pairs = *borrow(
                &task_meta_data_copy,
                (task_metadata_offset + METADATA_OFFSET_TASK_N_TREE_PAIRS as u64)
            );

            // Build the Merkle tree using a stack (see the function documentation) to compute the fact.
            let node_stack_len = 0;
            for (tree_pairs in 0..n_tree_pairs) {
                let n_pages = *borrow(&task_meta_data_copy,
                    ((task_metadata_offset + METADATA_TASK_HEADER_SIZE + 2 * tree_pairs + METADATA_OFFSET_TREE_PAIR_N_PAGES) as u64)
                );

                assert!(n_pages <= (pow(2, 20) as u256), INVALID_VALUE_OF_N_PAGES_IN_TREE_STRUCTURE);
                for (i in 0..n_pages) {
                    let (page_size, page_hash) = push_page_to_stack(
                        page_info_ptr,
                        cur_addr,
                        cur_offset,
                        node_stack,
                        node_stack_len
                    );
                    insert(&mut page_hashed_log_data, (cur_page - first_page_of_task + 3 as u64), page_hash);
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
                    node_stack_len = construct_node(&mut memory, node_stack, node_stack_len, n_nodes);
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
            register_fact(signer, fact);
            cur_addr = cur_addr + 2;
        };
    }

    //
    fun push_page_to_stack(
        page_info_prt: vector<u256>,
        cur_addr: u256,
        cur_offset: u256,
        node_stack: vector<u256>,
        node_stack_len: u256): (u256, u256) {
        let page_addr = *borrow(&page_info_prt, (PAGE_INFO_ADDRESS_OFFSET() as u64));
        let page_size = *borrow(&page_info_prt, (PAGE_INFO_SIZE_OFFSET() as u64));
        let page_hash = *borrow(&page_info_prt, (PAGE_INFO_HASH_OFFSET() as u64));

        assert!(page_size <= (pow(2, 30) as u256), INVALID_PAGE_SIZE);
        assert!(page_addr == cur_addr, INVALID_PAGE_ADDRESS);

        vector::insert(&mut node_stack,
            (NODE_STACK_ITEM_SIZE * node_stack_len + NODE_STACK_OFFSET_END as u64), cur_offset + page_size);
        vector::insert(&mut node_stack,
            (NODE_STACK_ITEM_SIZE * node_stack_len + NODE_STACK_OFFSET_HASH as u64), page_hash);
        (page_size, page_hash)
    }

    fun construct_node(
        memory: &mut Memory,
        node_stack: vector<u256>,
        node_stack_len: u256,
        n_nodes: u256,
    ): u256 {
        for_each(node_stack, |p|{
            allocate(memory, p);
        });

        assert!(n_nodes <= node_stack_len, 9);
        let new_node_end = *borrow(&node_stack,
            (NODE_STACK_ITEM_SIZE * (node_stack_len - 1) + NODE_STACK_OFFSET_END as u64)
        );
        let new_stack_len = node_stack_len - n_nodes;
        let node_start = 0x20 + new_stack_len * NODE_STACK_ITEM_SIZE * 0x20;
        //TODO: node_stack
        let input_hash = mloadrange(memory, (vector::length(&node_stack) as u256) + node_start, n_nodes * 0x40);
        let new_node_hash = to_u256(to_big_endian(input_hash));

        vector::insert(&mut node_stack,
            (NODE_STACK_ITEM_SIZE * new_stack_len + NODE_STACK_OFFSET_END as u64), new_node_end);
        vector::insert(&mut node_stack,
            (NODE_STACK_ITEM_SIZE * new_stack_len + NODE_STACK_OFFSET_HASH as u64), new_node_hash + 1);
        new_stack_len + 1
    }
}
