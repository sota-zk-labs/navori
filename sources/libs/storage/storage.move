module lib_addr::storage {
    use std::signer::address_of;
    use aptos_std::table;
    use aptos_std::table::Table;

    use lib_addr::umax::u64_max;

    struct Storage has store, key {
        slots: Table<u256, u256>
    }

    public fun init_storage(signer: &signer) {
        move_to(signer, Storage {
            slots: table::new()
        });
    }

    fun convert_part(offset: u256): (u256, u64) {
        let index: u256 = offset / 32;
        let part_index: u256 = index / (u64_max() as u256);
        let part_offset: u64 = (index % (u64_max() as u256) as u64);

        return (part_index, part_offset)
    }

    public fun sload(signer: &signer, index: u256): u256 acquires Storage {
        *table::borrow(&borrow_global_mut<Storage>(address_of(signer)).slots, index)
    }

    public fun sstore(signer: &signer, index: u256, value: u256) acquires Storage {
        table::upsert(&mut borrow_global_mut<Storage>(address_of(signer)).slots, index, value);
    }
}