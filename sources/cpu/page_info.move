module verifier_addr::page_info {

    public fun PAGE_INFO_SIZE(): u256 {
        return 3
    }

    public fun PAGE_INFO_SIZE_IN_BYTES(): u256 {
        return 3 * 32
    }

    public fun PAGE_INFO_ADDRESS_OFFSET(): u256 {
        return 0
    }

    public fun PAGE_INFO_SIZE_OFFSET(): u256 {
        return 1
    }

    public fun PAGE_INFO_HASH_OFFSET(): u256 {
        return 2
    }

    public fun MEMORY_PAGE_SIZE(): u256 {
        return 2
    }
}
