//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef ACTOR_PROOF_OF_WORK_HPP
#define ACTOR_PROOF_OF_WORK_HPP

#include <boost/property_tree/ptree.hpp>

#include <cstdint>

#include <nil/actor/math/detail/utility.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/actor/zk/transcript/fiat_shamir.hpp>


namespace nil {
    namespace actor {
        namespace zk {
            namespace commitments {
                template<typename TranscriptHashType, typename FieldType, std::uint8_t GrindingBits=16>
                class field_proof_of_work {
                public:
                    using transcript_hash_type = TranscriptHashType;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using value_type = typename FieldType::value_type;
                    using integral_type = typename FieldType::integral_type;

                    constexpr static const integral_type mask =
                        (GrindingBits > 0 ?
                            ((integral_type(2) << GrindingBits - 1) - 1) << (FieldType::modulus_bits - GrindingBits)
                            : 0);

                    static inline boost::property_tree::ptree get_params() {
                        boost::property_tree::ptree params;
                        params.put("mask", mask);
                        return params;
                    }

                    static inline value_type generate(transcript_type &transcript,
                        nil::crypto3::random::algebraic_engine<FieldType> random_engine) {

                        value_type pow_seed = random_engine();

                        /* Enough work for ~ two minutes on 48 cores */
                        std::size_t per_block = 1<<23;

                        std::atomic<bool> challenge_found = false;
                        std::atomic<std::size_t> pow_value_offset;

                        while( true ) {
                            math::detail::block_execution(
                                per_block, smp::count,
                                [&transcript, &pow_seed, &challenge_found, &pow_value_offset](std::size_t pow_start, std::size_t pow_finish) {
                                    std::size_t i = pow_start;
                                    while ( i < pow_finish ) {
                                        if (challenge_found) {
                                            break;
                                        }
                                        transcript_type tmp_transcript = transcript;
                                        tmp_transcript(pow_seed + i);
                                        integral_type pow_result = integral_type(tmp_transcript.template challenge<FieldType>().data);
                                        if ( ((pow_result & mask) == 0) && !challenge_found ) {
                                            challenge_found = true;
                                            pow_value_offset = i;
                                            break;
                                        }
                                        ++i;
                                    }
                                }).get();

                            if (challenge_found) {
                                break;
                            }
                            pow_seed += per_block;
                        }

                        transcript(pow_seed + (std::size_t)pow_value_offset);
                        transcript.template challenge<FieldType>();
                        return pow_seed + (std::size_t)pow_value_offset;
                    }

                    static inline bool verify(transcript_type &transcript, value_type const& proof_of_work) {
                        transcript(proof_of_work);
                        integral_type result = integral_type(transcript.template challenge<FieldType>().data);
                        return ((result & mask) == 0);
                    }
                };

                template<typename TranscriptHashType,
                    std::uint8_t grinding_bits,
                    typename output_type,
                    typename Enable = void>
                class proof_of_work;

                template<typename TranscriptHashType,
                    std::uint8_t grinding_bits,
                    typename output_type,
                    typename std::enable_if_t<!crypto3::hashes::is_poseidon<TranscriptHashType>::value> >
                class proof_of_work {
                public:
                    constexpr static output_type mask = (grinding_bits > 0 ?
                            ((output_type(2) << grinding_bits ) - 1) << (sizeof(output_type)*8 - grinding_bits)
                            : 0);
                    using transcript_hash_type = TranscriptHashType;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

                    static inline boost::property_tree::ptree get_params() {
                        boost::property_tree::ptree params;
                        params.put("mask", mask);
                        return params;
                    }

                    static inline output_type generate(transcript_type &transcript) {

                        output_type pow_seed = 0;
                        /* Enough work for ~ two minutes on 48 cores */
                        std::size_t per_block = 1<<23;

                        std::atomic<bool> challenge_found = false;
                        std::atomic<std::size_t> pow_value_offset;

                        while( true ) {
                            math::detail::block_execution(
                                per_block, smp::count,
                                [&transcript, &pow_seed, &challenge_found, &pow_value_offset]
                                (std::size_t pow_start, std::size_t pow_finish) {
                                    std::size_t i = pow_start;
                                    while ( i < pow_finish ) {
                                        if (challenge_found) {
                                            break;
                                        }
                                        std::vector<std::uint8_t> bytes(sizeof(output_type));
                                        for(int j = 0; j < sizeof(output_type) ; ++j ) {
                                            bytes[j] = std::uint8_t( ((pow_seed+i) >> (sizeof(output_type)-1-j)*8) & 0xFF);
                                        }

                                        transcript_type tmp_transcript = transcript;

                                        output_type proof_of_work_value = pow_seed + i;
                                        tmp_transcript(bytes);
                                        output_type pow_result = tmp_transcript.template int_challenge<output_type>();
                                        if ( ((pow_result & mask) == 0) && !challenge_found ) {
                                            challenge_found = true;
                                            pow_value_offset = i;
                                            break;
                                        }
                                        ++i;
                                    }
                                }).get();

                            if (challenge_found) {
                                break;
                            }
                            pow_seed += per_block;
                        }
                        output_type proof_of_work_value = pow_seed + pow_value_offset;

                        std::vector<std::uint8_t> bytes(sizeof(output_type));
                        for(int j = 0; j < sizeof(output_type) ; ++j ) {
                            bytes[j] = std::uint8_t( (proof_of_work_value >> (sizeof(output_type)-1-j)*8) & 0xFF);
                        }
                        transcript(bytes);
                        auto pow_result = transcript.template int_challenge<output_type>();
                        output_type result = 0;
                        for (int i = 0; i < sizeof(output_type); ++i ) {
                            result <<= 8;
                            result |= bytes[i];
                        }
                        return result;
                    }

                    static inline bool verify(transcript_type &transcript, output_type proof_of_work) {
                        std::vector<std::uint8_t> bytes(sizeof(output_type));
                        for(int j = 0; j < sizeof(output_type) ; ++j ) {
                            bytes[j] = std::uint8_t( (proof_of_work>> (sizeof(output_type)-1-j)*8) & 0xFF);
                        }
                        output_type result = transcript.template int_challenge<output_type>();
                        return ((result & mask) == 0);
                    }
                };

                /* Specialization for poseidon */
                template<typename TranscriptHashType,
                    std::uint8_t grinding_bits>
                class proof_of_work<
                    TranscriptHashType,
                    grinding_bits,
                    typename TranscriptHashType::policy_type::field_type::value_type,
                    typename std::enable_if_t<crypto3::hashes::is_poseidon<TranscriptHashType>::value> > {
                public:
                    using transcript_hash_type = TranscriptHashType;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using field_type = typename transcript_hash_type::policy_type::field_type;
                    using output_type = typename field_type::value_type;
//                    using value_type = typename output_type::value_type;
                    using integral_type = typename output_type::integral_type;
                    constexpr static integral_type mask = (grinding_bits > 0 ?
                            ((integral_type(2) << (grinding_bits-1) ) - 1) << (sizeof(output_type)*8 - grinding_bits)
                            : 0);

                    static inline boost::property_tree::ptree get_params() {
                        boost::property_tree::ptree params;
                        params.put("mask", mask);
                        return params;
                    }

                    static inline output_type generate(transcript_type &transcript) {

                        output_type pow_seed = 0;
                        /* Enough work for ~ two minutes on 48 cores */
                        std::size_t per_block = 1<<23;

                        std::atomic<bool> challenge_found = false;
                        std::atomic<std::size_t> pow_value_offset;

                        while( true ) {
                            math::detail::block_execution(
                                per_block, smp::count,
                                [&transcript, &pow_seed, &challenge_found, &pow_value_offset]
                                (std::size_t pow_start, std::size_t pow_finish) {
                                    std::size_t i = pow_start;
                                    while ( i < pow_finish ) {
                                        if (challenge_found) {
                                            break;
                                        }

                                        transcript_type tmp_transcript = transcript;
                                        tmp_transcript(pow_seed + i);
                                        integral_type pow_result = integral_type(tmp_transcript.template challenge<field_type>().data);
                                        if ( ((pow_result & mask) == 0) && !challenge_found ) {
                                            challenge_found = true;
                                            pow_value_offset = i;
                                            break;
                                        }
                                        ++i;
                                    }
                                }).get();

                            if (challenge_found) {
                                break;
                            }
                            pow_seed += per_block;
                        }
                        transcript(pow_seed + (std::size_t)pow_value_offset);
                        transcript.template challenge<field_type>();
                        return output_type(pow_seed + (std::size_t)pow_value_offset);
                    }

                    static inline bool verify(transcript_type &transcript, output_type const& proof_of_work) {
                        transcript(proof_of_work);
                        integral_type result = integral_type(transcript.template challenge<field_type>().data);
                        return ((result & mask) == 0);
                    }
                };
            }
        }
    }
}

#endif  // ACTOR_PROOF_OF_WORK_HPP
