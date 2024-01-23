module gmsui::utils {
    use std::vector::{Self};

    public fun max_vector_u8(x: vector<u8>, y: vector<u8>): vector<u8> {
        let len_x = vector::length(&x);
        let len_y = vector::length(&y);
        if (len_x != len_y) {
            if (len_x > len_y) {
                return x
            } else {
                return y
            }
        };

        let i = 0;
        while (i < len_x) {
            let value_x = *vector::borrow(&x, i);
            let value_y = *vector::borrow(&y, i);
            if (value_x > value_y) {
                return x
            } else if (value_y > value_x) {
                return y
            };
            i = i + 1;
        };
        x
    }
}