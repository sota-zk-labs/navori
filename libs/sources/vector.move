module lib_addr::vector {
    use std::vector;
    use std::vector::{borrow_mut, length, pop_back, push_back};

    const EINVALID_NEW_LENGTH: u64 = 0;

    public inline fun append_vector(
        vec1: vector<u8>,
        vec2: vector<u8>
    ): vector<u8> {
        vector::append(&mut vec1, vec2);
        vec1
    }

    public fun assign<Element: copy + drop>(el: Element, size: u64): vector<Element> {
        let v = vector[];
        while (size > 0) {
            push_back(&mut v, copy el);
            size = size - 1;
        };
        return v
    }

    public inline fun set_el<Element: drop>(v: &mut vector<Element>, i: u64, value: Element) {
        *borrow_mut(v, i) = value;
    }

    public fun trim_only<Element: copy + drop>(v: &mut vector<Element>, new_length: u64) {
        let length = length(v);
        assert!(new_length <= length, EINVALID_NEW_LENGTH);
        while (length != new_length) {
            length = length - 1;
            pop_back(v);
        }
    }
}
