//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

//#define BOOST_TEST_MODULE proof_of_work_test

#include <string>
#include <random>
#include <regex>

#include <nil/actor/testing/random.hh>
#include <nil/actor/testing/test_case.hh>
#include <nil/actor/testing/thread_test_case.hh>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/pallas/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>

#include <nil/actor/zk/commitments/detail/polynomial/proof_of_work.hpp>

#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/actor/zk/transcript/fiat_shamir.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::actor::zk::commitments;

ACTOR_THREAD_TEST_CASE(pow_basic_test) {
    using keccak = nil::crypto3::hashes::keccak_1600<512>;
    constexpr std::uint8_t grinding_bits = 16;
    using pow_type = nil::actor::zk::commitments::proof_of_work<keccak, std::uint64_t, grinding_bits>;
    nil::actor::zk::transcript::fiat_shamir_heuristic_sequential<keccak> transcript;
    auto old_transcript_1 = transcript, old_transcript_2 = transcript;

    std::uint64_t mask = ((std::uint64_t(2)<<grinding_bits)-1) << (sizeof(mask)*8-grinding_bits);
    BOOST_CHECK(mask == pow_type::mask);

    auto result = pow_type::generate(transcript);
    BOOST_CHECK(pow_type::verify(old_transcript_1, result));
    // manually reimplement verify to ensure that changes in implementation didn't break it
    std::array<std::uint8_t, sizeof(result)> bytes;
    for(int j = 0; j < sizeof(result) ; ++j ) {
        bytes[j] = std::uint8_t( (result >> (sizeof(result)-1-j)*8) & 0xFF);
    }

    std::cout << "test transcript input:" << std::hex << std::setfill('0');
    for(auto x:bytes) {
        std::cout << std::setw(2) << std::size_t(x) << " ";
    }
    std::cout << std::endl;

    old_transcript_2(bytes);
    auto chal = old_transcript_2.template int_challenge<std::uint64_t>();

    std::cout << "mask     : " << std::setw(sizeof(mask)*2) << mask << std::endl;
    std::cout << "challenge: " << std::setw(sizeof(mask)*2) << chal << std::endl;
    BOOST_CHECK((chal & mask) == 0);

    // check that random stuff doesn't pass verify
    using hard_pow_type = nil::actor::zk::commitments::proof_of_work<keccak, std::uint64_t, 63>;
    BOOST_CHECK(!hard_pow_type::verify(old_transcript_1, result));
}

ACTOR_THREAD_TEST_CASE(pow_poseidon_basic_test) {
    using curve_type = curves::pallas;
    using field_type = curve_type::base_field_type;
    using integral_type = typename field_type::integral_type;
    using policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
    using poseidon = nil::crypto3::hashes::poseidon<policy>;
    using pow_type = nil::actor::zk::commitments::field_proof_of_work<poseidon, field_type, 16>;

    const integral_type expected_mask = integral_type(0xFFFF000000000000) << (field_type::modulus_bits - 64);
    nil::actor::zk::transcript::fiat_shamir_heuristic_sequential<poseidon> transcript;
    auto old_transcript_1 = transcript, old_transcript_2 = transcript;

    auto seed = nil::actor::testing::local_random_engine();

    nil::crypto3::random::algebraic_engine<field_type> rnd_engine = nil::crypto3::random::algebraic_engine<field_type>(seed);

    auto result = pow_type::generate(transcript,  rnd_engine);
    BOOST_CHECK(expected_mask == pow_type::mask);
    BOOST_CHECK(pow_type::verify(old_transcript_1, result));

    // manually reimplement verify to ensure that changes in implementation didn't break it
    old_transcript_2(result);
    auto chal = old_transcript_2.template challenge<field_type>();
    BOOST_CHECK((integral_type(chal.data) & expected_mask) == 0);

    using hard_pow_type = nil::actor::zk::commitments::field_proof_of_work<poseidon, field_type, 32>;
    // check that random stuff doesn't pass verify
    BOOST_CHECK(!hard_pow_type::verify(old_transcript_1, result));
}

ACTOR_THREAD_TEST_CASE(special_poseidon_test) {
    using curve_type = curves::pallas;
    using field_type = curve_type::base_field_type;
    using integral_type = typename field_type::integral_type;
    using policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
    using poseidon = nil::crypto3::hashes::poseidon<policy>;
    using pow_type = nil::actor::zk::commitments::proof_of_work<poseidon, field_type, 16>;

    const integral_type expected_mask = integral_type(0xFFFF000000000000) << (field_type::modulus_bits - 64);
    nil::actor::zk::transcript::fiat_shamir_heuristic_sequential<poseidon> transcript;
    auto old_transcript_1 = transcript, old_transcript_2 = transcript;

    auto result = pow_type::generate(transcript);
    BOOST_CHECK(expected_mask == pow_type::mask);
    BOOST_CHECK(pow_type::verify(old_transcript_1, result));

    // manually reimplement verify to ensure that changes in implementation didn't break it
    old_transcript_2(result);
    auto chal = old_transcript_2.template challenge<field_type>();
    BOOST_CHECK((integral_type(chal.data) & expected_mask) == 0);

    using hard_pow_type = nil::actor::zk::commitments::proof_of_work<poseidon, field_type, 32>;
    // check that random stuff doesn't pass verify
    BOOST_CHECK(!hard_pow_type::verify(old_transcript_1, result));
}
