module verifier_addr::public_memory_offsets_7 {
    use verifier_addr::cpu_public_input_offsets_7::OFFSET_PUBLIC_MEMORY;
    use verifier_addr::page_info::{PAGE_INFO_SIZE, PAGE_INFO_SIZE_OFFSET};

    public fun get_offset_page_size(page_id: u256): u256 {
        return get_public_memory_offset() + PAGE_INFO_SIZE() * page_id - 1 + PAGE_INFO_SIZE_OFFSET()
    }
    
    public fun get_public_memory_offset(): u256 {
        (OFFSET_PUBLIC_MEMORY() as u256)
    }

    public fun get_public_input_length(n_pages: u256): u256 {
        get_public_memory_offset() + (PAGE_INFO_SIZE() + 1) * n_pages - 1
    }
}
