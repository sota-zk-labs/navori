module verifier_addr::page_info {
    const PAGE_INFO_SIZE : u64 = 3;
    const PAGE_INFO_SIZE_IN_BYTES : u64 = 3 * 32;
    const PAGE_INFO_ADDRESS_OFFSET : u64= 0;
    const PAGE_INFO_SIZE_OFFSET : u64 = 1;
    const PAGE_INFO_HASH_OFFSET : u64 = 2;
    const MEMORY_PAGE_SIZE :u64 = 2;

    public fun get_page_info_size() : u64 {
        return PAGE_INFO_SIZE
    }

    public fun get_page_info_size_in_bytes() : u64 {
        return PAGE_INFO_SIZE_IN_BYTES
    }

    public fun get_page_info_address_offset() : u64 {
        return PAGE_INFO_ADDRESS_OFFSET
    }

    public fun get_page_info_size_offset() : u64 {
        return PAGE_INFO_SIZE_OFFSET
    }

    public fun get_page_info_hash_offset() : u64 {
        return PAGE_INFO_HASH_OFFSET
    }

    public fun get_memory_page_size() : u64 {
        return MEMORY_PAGE_SIZE
    }
}
