module cpu_addr::public_memory_offsets_7 {
    // This line is used for generating constants DO NOT REMOVE!
    // 1
    const EADDRESS_OF_PAGE_0_IS_NOT_PART_OF_THE_PUBLIC_INPUT: u64 = 0x1;
    // 21
    const OFFSET_PUBLIC_MEMORY: u64 = 0x15;
    // 0
    const PAGE_INFO_ADDRESS_OFFSET: u64 = 0x0;
    // 2
    const PAGE_INFO_HASH_OFFSET: u64 = 0x2;
    // 3
    const PAGE_INFO_SIZE: u64 = 0x3;
    // 1
    const PAGE_INFO_SIZE_OFFSET: u64 = 0x1;
    // End of generating constants!

    #[view]
    public fun get_offset_page_size(page_id: u64): u64 {
        return OFFSET_PUBLIC_MEMORY + PAGE_INFO_SIZE * page_id - 1 + PAGE_INFO_SIZE_OFFSET
    }

    #[view]
    public fun get_offset_page_hash(page_id: u64): u64 {
        OFFSET_PUBLIC_MEMORY + PAGE_INFO_SIZE * page_id - 1 + PAGE_INFO_HASH_OFFSET
    }

    #[view]
    public fun get_offset_page_addr(page_id: u64): u64 {
        assert!(page_id != 0, EADDRESS_OF_PAGE_0_IS_NOT_PART_OF_THE_PUBLIC_INPUT);
        OFFSET_PUBLIC_MEMORY + PAGE_INFO_SIZE * page_id - 1 + PAGE_INFO_ADDRESS_OFFSET
    }

    #[view]
    public fun get_offset_page_prod(page_id: u64, n_pages: u64): u64 {
        OFFSET_PUBLIC_MEMORY + PAGE_INFO_SIZE * n_pages - 1 + page_id
    }

    #[view]
    public fun get_public_input_length(n_pages: u64): u64 {
        OFFSET_PUBLIC_MEMORY + (PAGE_INFO_SIZE + 1) * n_pages - 1
    }
}