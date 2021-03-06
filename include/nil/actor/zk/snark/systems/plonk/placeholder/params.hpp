//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef ACTOR_ZK_PLONK_PLACEHOLDER_PARAMS_HPP
#define ACTOR_ZK_PLONK_PLACEHOLDER_PARAMS_HPP

#include <nil/actor/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/actor/zk/commitments/polynomial/lpc.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace snark {
                template<typename FieldType,
                         typename ArithmetizationParams,
                         typename MerkleTreeHashType = crypto3::hashes::keccak_1600<512>,
                         typename TranscriptHashType = crypto3::hashes::keccak_1600<512>, std::size_t Lambda = 40,
                         std::size_t R = 1, std::size_t M = 2>
                struct placeholder_params {

                    typedef MerkleTreeHashType merkle_hash_type;
                    typedef TranscriptHashType transcript_hash_type;

                    constexpr static const std::size_t witness_columns =
                        ArithmetizationParams::WitnessColumns;
                    constexpr static const std::size_t public_input_columns =
                        ArithmetizationParams::PublicInputColumns;
                    constexpr static const std::size_t constant_columns =
                        ArithmetizationParams::ConstantColumns;
                    constexpr static const std::size_t selector_columns =
                        ArithmetizationParams::SelectorColumns;

                    using arithmetization_params = ArithmetizationParams;

                    constexpr static const typename FieldType::value_type delta =
                        crypto3::algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;

                    typedef typename commitments::fri<FieldType, MerkleTreeHashType,
                        TranscriptHashType, M, 1>::params_type commitment_params_type;
                    
                    typedef commitments::list_polynomial_commitment_params<MerkleTreeHashType, 
                            TranscriptHashType, Lambda, R, M>
                            batched_commitment_params_type;

                    using runtime_size_commitment_scheme_type =
                        commitments::batched_lpc<FieldType, batched_commitment_params_type, 0, false>;
                    using witness_commitment_scheme_type =
                        commitments::batched_lpc<FieldType, batched_commitment_params_type, witness_columns, true>;
                    using public_input_commitment_scheme_type =
                        commitments::batched_lpc<FieldType, batched_commitment_params_type, public_input_columns, true>;
                    using constant_commitment_scheme_type =
                        commitments::batched_lpc<FieldType, batched_commitment_params_type, constant_columns, true>;
                    using selector_commitment_scheme_type =
                        commitments::batched_lpc<FieldType, batched_commitment_params_type, selector_columns, true>;
                    using special_commitment_scheme_type =
                        commitments::batched_lpc<FieldType, batched_commitment_params_type, 2, true>;
                    using permutation_commitment_scheme_type =
                        commitments::list_polynomial_commitment<FieldType, batched_commitment_params_type>;
                    using quotient_commitment_scheme_type =
                        commitments::list_polynomial_commitment<FieldType, batched_commitment_params_type>;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace actor
}    // namespace nil

#endif    // ACTOR_ZK_PLONK_PLACEHOLDER_PARAMS_HPP
