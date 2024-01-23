module gmsui::merkle_tree {
    use std::vector::{Self};
    use sui::hash::{keccak256};
    use sui::address::{Self};

    use gmsui::utils::{Self};
    use gmsui::bytes32::{Self, Bytes32};

    public fun verify_v1(proof: vector<address>, root: address, leaf: address): bool {
        let proof_length = vector::length(&proof);

        let _proof = vector::empty<Bytes32>();
        let i = 0;
        while (i < proof_length) {
            vector::push_back(&mut _proof, bytes32::from_vector(address::to_bytes(*vector::borrow(&proof, i))));
            i = i + 1;
        };
        let _root = bytes32::from_vector(address::to_bytes(root));
        let _leaf = bytes32::from_vector(address::to_bytes(leaf));
        verify(_proof, _root, _leaf)
    }

    public fun verify(proof: vector<Bytes32>, root: Bytes32, leaf: Bytes32): bool {
        bytes32::data(&process_proof(proof, leaf)) == bytes32::data(&root)
    }

    fun process_proof(proof: vector<Bytes32>, leaf: Bytes32): Bytes32 {
        let current_digest = leaf;
        let proof_length = vector::length(&proof);
        let i = 0;
        while (i < proof_length){
            let p = *vector::borrow(&proof, i);
            current_digest = hash_pair(current_digest, p);
            i = i + 1;
        };
        current_digest
    }

    fun hash_pair(a: Bytes32, b: Bytes32): Bytes32 {
        let data_a = bytes32::data(&a);
        let data_b = bytes32::data(&b);
        if (utils::max_vector_u8(data_a, data_b) == data_a) {
            (data_a, data_b) = (data_b, data_a);
        };

        let v = vector::empty<u8>();
        vector::append(&mut v, data_a);
        vector::append(&mut v, data_b);
        efficient_hash(&v)
    }

    fun efficient_hash(bytes: &vector<u8>): Bytes32 {
        let keccak_bytes = keccak256(bytes);
        let hash_prefix = vector::empty<u8>();
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut hash_prefix, *vector::borrow(&keccak_bytes, i));
            i = i + 1;
        };
        bytes32::from_vector(hash_prefix)
    }

    public fun leaf_from_vector(data: &vector<u8>): Bytes32 {
        let v = vector<u8>[0];
        let i = 0;
        while (i < vector::length(data)) {
            vector::push_back(&mut v, *vector::borrow(data, i));
            i = i + 1;
        };
        efficient_hash(&v)
    }
}