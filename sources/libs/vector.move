module verifier_addr::vector {
    use std::vector;
    use std::vector::{push_back, borrow_mut};

    public fun append_vector(
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
    
    public fun set_el<Element: drop>(v: &mut vector<Element>, i: u64, new_el: Element) {
        *borrow_mut(v, i) = new_el;
    }
}
