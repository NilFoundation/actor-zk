//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <nil/crypto3/algebra/curves/bn128.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/zk/snark/components/hashes/sha256/sha256_component.hpp>
#include <nil/crypto3/zk/snark/components/set_commitment/set_commitment_component.hpp>

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename CurveType>
void test_all_set_commitment_components() {
    typedef typename CurveType::scalar_field_type FieldType;
    test_set_commitment_component<FieldType, crh_with_bit_out_component<FieldType>>();
    test_set_commitment_component<FieldType, sha256_two_to_one_hash_component<FieldType>>();
}

int main(void) {
    test_all_set_commitment_components<curves::bn128>();
    test_all_set_commitment_components<curves::edwards>();
    test_all_set_commitment_components<curves::mnt4>();
    test_all_set_commitment_components<curves::mnt6>();
}