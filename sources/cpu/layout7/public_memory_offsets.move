module verifier_addr::public_memory_offsets_7 {

    // This line is used for generating constants DO NOT REMOVE!
	// 21
	const OFFSET_PUBLIC_MEMORY: u64 = 0x15;
	// 3
	const PAGE_INFO_SIZE: u256 = 0x3;
	// 1
	const PAGE_INFO_SIZE_OFFSET: u256 = 0x1;
	// 0
	const PAGE_INFO_ADDRESS_OFFSET: u256 = 0x0;
	// 2
	const PAGE_INFO_HASH_OFFSET: u256 = 0x2;
    // End of generating constants!

    public fun get_public_memory_offset(): u256 {
        (OFFSET_PUBLIC_MEMORY as u256)
    }

    public fun get_offset_page_size(page_id: u256): u256 {
        return get_public_memory_offset() + PAGE_INFO_SIZE * page_id - 1 + PAGE_INFO_SIZE_OFFSET
    }

    public fun get_offset_page_hash(page_id: u256): u256 {
        get_public_memory_offset() + PAGE_INFO_SIZE * page_id - 1 + PAGE_INFO_HASH_OFFSET
    }

    public fun get_offset_page_addr(page_id: u256): u256 {
        assert!(page_id >= 1, 1);
        get_public_memory_offset() + PAGE_INFO_SIZE * page_id - 1 + PAGE_INFO_ADDRESS_OFFSET
    }

    public fun get_offset_page_prod(page_id: u256, n_pages: u256): u256 {
        get_public_memory_offset() + PAGE_INFO_SIZE * n_pages - 1 + page_id
    }

    public fun get_public_input_length(n_pages: u256): u256 {
        get_public_memory_offset() + (PAGE_INFO_SIZE + 1) * n_pages - 1
    }
}