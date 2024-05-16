module verifier_addr::append_vector {
    use std::vector;

    public fun append_vector(
        vec1 : vector<u8>,
        vec2 : vector<u8>
    ) : vector<u8> {
        vector::append(&mut vec1,vec2);
        vec1
    }
}
