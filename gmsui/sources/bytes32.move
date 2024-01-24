module gmsui::bytes32 {
    use sui::address;
    use std::vector::{Self};

    struct Bytes32 has copy, drop, store {
        data: vector<u8>,
    }

    public fun from_vector(data: vector<u8>): Bytes32 {
        assert!(vector::length(&data) == 32, 0);
        Bytes32 { data }
    }

    public fun into_vector(b32: Bytes32): vector<u8> {
        let Bytes32 { data } = b32;
        data
    }

    public fun data(self: &Bytes32): vector<u8> {
        self.data
    }

    public fun from_vector_addresses(data: vector<address>): vector<Bytes32> {
        let length = vector::length(&data);
        let v = vector::empty<Bytes32>();

        let i = 0;
        while (i < length) {
            vector::push_back(&mut v, from_vector(address::to_bytes(*vector::borrow(&data, i))));
            i = i + 1;
        };

        v
    }
}