module verifier_addr::convert_memory {

    use std::vector;
    use aptos_std::table;
    use aptos_std::table::{Table, new};

    public fun from_vector(vec: vector<u256>, table: &mut Table<u256, u256>, start_prt: u256) {
        let length_vector = (vector::length(&vec) as u256);
        let index = start_prt;
        while (index < length_vector + start_prt) {
            table::upsert(table, index, *vector::borrow(&vec, ((index - start_prt) as u64)));
            index = index + 1;
        }
    }
}
