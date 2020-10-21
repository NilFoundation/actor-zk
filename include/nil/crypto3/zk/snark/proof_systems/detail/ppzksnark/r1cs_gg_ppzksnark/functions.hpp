//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for a ppzkSNARK for R1CS with a security proof
// in the generic group (GG) model.
//
// This includes:
//- class for proving key
//- class for verification key
//- class for processed verification key
//- class for key pair (proving key & verification key)
//- class for proof
//- generator algorithm
//- prover algorithm
//- verifier algorithm (with strong or weak input consistency)
//- online verifier algorithm (with strong or weak input consistency)
//
// The implementation instantiates the protocol of \[Gro16].
//
//
// Acronyms:
//
//- R1CS = "Rank-1 Constraint Systems"
//- ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//
// References:
//
//\[Gro16]:
// "On the Size of Pairing-based Non-interactive Arguments",
// Jens Groth,
// EUROCRYPT 2016,
// <https://eprint.iacr.org/2016/260>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_FUNCTIONS_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_FUNCTIONS_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/params.hpp>

////#include <nil/crypto3/algebra/multiexp/default.hpp>

//#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

//#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct r1cs_gg_ppzksnark_functions {

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS GG-ppzkSNARK.
                         */
                        struct proving_key {

                            typename CurveType::g1_type alpha_g1;
                            typename CurveType::g1_type beta_g1;
                            typename CurveType::g2_type beta_g2;
                            typename CurveType::g1_type delta_g1;
                            typename CurveType::g2_type delta_g2;

                            typename CurveType::g1_vector A_query;    // this could be a sparse vector if we had multiexp for those
                            knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> B_query;
                            typename CurveType::g1_vector H_query;
                            typename CurveType::g1_vector L_query;

                            constraint_system<CurveType> constraint_system;

                            proving_key() {};
                            proving_key<CurveType> &
                                operator=(const proving_key<CurveType> &other) = default;
                            proving_key(const proving_key<CurveType> &other) = default;
                            proving_key(proving_key<CurveType> &&other) = default;
                            proving_key(
                                typename CurveType::g1_type &&alpha_g1,
                                typename CurveType::g1_type &&beta_g1,
                                typename CurveType::g2_type &&beta_g2,
                                typename CurveType::g1_type &&delta_g1,
                                typename CurveType::g2_type &&delta_g2,
                                typename CurveType::g1_vector &&A_query,
                                knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> &&B_query,
                                typename CurveType::g1_vector &&H_query,
                                typename CurveType::g1_vector &&L_query,
                                constraint_system<CurveType> &&constraint_system) :
                                alpha_g1(std::move(alpha_g1)),
                                beta_g1(std::move(beta_g1)), beta_g2(std::move(beta_g2)), delta_g1(std::move(delta_g1)),
                                delta_g2(std::move(delta_g2)), A_query(std::move(A_query)), B_query(std::move(B_query)),
                                H_query(std::move(H_query)), L_query(std::move(L_query)),
                                constraint_system(std::move(constraint_system)) {};

                            std::size_t G1_size() const {
                                return 1 + A_query.size() + B_query.domain_size() + H_query.size() + L_query.size();
                            }

                            std::size_t G2_size() const {
                                return 1 + B_query.domain_size();
                            }

                            std::size_t G1_sparse_size() const {
                                return 1 + A_query.size() + B_query.size() + H_query.size() + L_query.size();
                            }

                            std::size_t G2_sparse_size() const {
                                return 1 + B_query.size();
                            }

                            std::size_t size_in_bits() const {
                                return A_query.size() * CurveType::g1_type::value_bits + B_query.size_in_bits() +
                                        H_query.size() * CurveType::g1_type::value_bits + 
                                        L_query.size() * CurveType::g1_type::value_bits +
                                        1 * CurveType::g1_type::value_bits +
                                        1 * CurveType::g2_type::value_bits;
                            }

                            bool operator==(const proving_key<CurveType> &other) const {
                                return (this->alpha_g1 == other.alpha_g1 && this->beta_g1 == other.beta_g1 &&
                                        this->beta_g2 == other.beta_g2 && this->delta_g1 == other.delta_g1 &&
                                        this->delta_g2 == other.delta_g2 && this->A_query == other.A_query &&
                                        this->B_query == other.B_query && this->H_query == other.H_query &&
                                        this->L_query == other.L_query && this->constraint_system == other.constraint_system);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS GG-ppzkSNARK.
                         */
                        struct verification_key {

                            typename CurveType::gt_type alpha_g1_beta_g2;
                            typename CurveType::g2_type gamma_g2;
                            typename CurveType::g2_type delta_g2;

                            accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1;

                            verification_key() = default;
                            verification_key(
                                const typename CurveType::gt_type &alpha_g1_beta_g2,
                                const typename CurveType::g2_type &gamma_g2,
                                const typename CurveType::g2_type &delta_g2,
                                const accumulation_vector<typename CurveType::g1_type> &gamma_ABC_g1) :
                                alpha_g1_beta_g2(alpha_g1_beta_g2),
                                gamma_g2(gamma_g2), delta_g2(delta_g2), gamma_ABC_g1(gamma_ABC_g1) {};

                            std::size_t G1_size() const {
                                return gamma_ABC_g1.size();
                            }

                            std::size_t G2_size() const {
                                return 2;
                            }

                            std::size_t GT_size() const {
                                return 1;
                            }

                            std::size_t size_in_bits() const {
                                // TODO: include GT size
                                return (gamma_ABC_g1.size_in_bits() + 2 * CurveType::g2_type::value_bits);
                            }

                            bool operator==(const verification_key<CurveType> &other) const {
                                return (this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 && this->gamma_g2 == other.gamma_g2 &&
                                        this->delta_g2 == other.delta_g2 && this->gamma_ABC_g1 == other.gamma_ABC_g1);
                            }

                            static verification_key<CurveType>
                                dummy_verification_key(const std::size_t input_size) {
                                verification_key<CurveType> result;
                                result.alpha_g1_beta_g2 = field_random_element<typename CurveType::scalar_field_type>() *
                                                          field_random_element<typename CurveType::gt_type>();
                                result.gamma_g2 = curve_random_element<typename CurveType::g2_type>();
                                result.delta_g2 = curve_random_element<typename CurveType::g2_type>();

                                typename CurveType::g1_type base = curve_random_element<typename CurveType::g1_type>();
                                typename CurveType::g1_vector v;
                                for (std::size_t i = 0; i < input_size; ++i) {
                                    v.emplace_back(curve_random_element<typename CurveType::g1_type>());
                                }

                                result.gamma_ABC_g1 =
                                    accumulation_vector<typename CurveType::g1_type>(std::move(base), std::move(v));

                                return result;
                            }
                        };

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS GG-ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        class processed_verification_key {
                            using pairing_policy = typename CurveType::pairing_policy;
                        public:


                            typename CurveType::gt_type vk_alpha_g1_beta_g2;
                            typename pairing_policy::G2_precomp vk_gamma_g2_precomp;
                            typename pairing_policy::G2_precomp vk_delta_g2_precomp;

                            accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1;

                            bool operator==(const processed_verification_key &other) const {
                                return (this->vk_alpha_g1_beta_g2 == other.vk_alpha_g1_beta_g2 &&
                                        this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
                                        this->vk_delta_g2_precomp == other.vk_delta_g2_precomp &&
                                        this->gamma_ABC_g1 == other.gamma_ABC_g1);
                            }
                        };

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS GG-ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        struct keypair {

                            proving_key<CurveType> pk;
                            verification_key<CurveType> vk;

                            keypair() = default;
                            keypair(const keypair<CurveType> &other) = default;
                            keypair(proving_key<CurveType> &&pk,
                                                      verification_key<CurveType> &&vk) :
                                pk(std::move(pk)),
                                vk(std::move(vk)) {
                            }

                            keypair(keypair<CurveType> &&other) = default;
                        };

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the R1CS GG-ppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        struct proof {

                            typename CurveType::g1_type g_A;
                            typename CurveType::g2_type g_B;
                            typename CurveType::g1_type g_C;

                            proof() {
                                // invalid proof with valid curve points
                                this->g_A = typename CurveType::g1_type::one();
                                this->g_B = typename CurveType::g2_type::one();
                                this->g_C = typename CurveType::g1_type::one();
                            }
                            proof(typename CurveType::g1_type &&g_A, typename CurveType::g2_type &&g_B,
                                                    typename CurveType::g1_type &&g_C) :
                                g_A(std::move(g_A)),
                                g_B(std::move(g_B)), g_C(std::move(g_C)) {};

                            std::size_t G1_size() const {
                                return 2;
                            }

                            std::size_t G2_size() const {
                                return 1;
                            }

                            std::size_t size_in_bits() const {
                                return G1_size() * CurveType::g1_type::value_bits +
                                       G2_size() * CurveType::g2_type::value_bits;
                            }

                            bool is_well_formed() const {
                                //return (g_A.is_well_formed() && g_B.is_well_formed() && g_C.is_well_formed());
                                // uncomment
                                // when is_well_formed ready
                                return true;

                            }

                            bool operator==(const proof<CurveType> &other) const {
                                return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C);
                            }
                        };

                        /***************************** Main algorithms *******************************/

                        /**
                         * A generator algorithm for the R1CS GG-ppzkSNARK.
                         *
                         * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
                         */
                        static keypair<CurveType>
                            generator(const constraint_system<CurveType> &cs) {

                            using pairing_policy = typename CurveType::pairing_policy;

                            /* Make the B_query "lighter" if possible */
                            constraint_system<CurveType> r1cs_copy(cs);
                            r1cs_copy.swap_AB_if_beneficial();

                            /* Generate secret randomness */
                            const typename CurveType::scalar_field_type::value_type t =
                                field_random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type alpha =
                                field_random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type beta =
                                field_random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type gamma =
                                field_random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type delta =
                                field_random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type gamma_inverse = gamma.inversed();
                            const typename CurveType::scalar_field_type::value_type delta_inverse = delta.inversed();

                            /* A quadratic arithmetic program evaluated at t. */
                            qap_instance_evaluation<typename CurveType::scalar_field_type> qap =
                                r1cs_to_qap_instance_map_with_evaluation(r1cs_copy, t);

                            std::size_t non_zero_At = 0;
                            std::size_t non_zero_Bt = 0;
                            for (std::size_t i = 0; i < qap.num_variables + 1; ++i) {
                                if (!qap.At[i].is_zero()) {
                                    ++non_zero_At;
                                }
                                if (!qap.Bt[i].is_zero()) {
                                    ++non_zero_Bt;
                                }
                            }

                            /* qap.{At,Bt,Ct,Ht} are now in unspecified state, but we do not use them later */
                            std::vector<typename CurveType::scalar_field_type::value_type> At = std::move(qap.At);
                            std::vector<typename CurveType::scalar_field_type::value_type> Bt = std::move(qap.Bt);
                            std::vector<typename CurveType::scalar_field_type::value_type> Ct = std::move(qap.Ct);
                            std::vector<typename CurveType::scalar_field_type::value_type> Ht = std::move(qap.Ht);

                            /* The gamma inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * gamma^{-1}. */
                            std::vector<typename CurveType::scalar_field_type::value_type> gamma_ABC;
                            gamma_ABC.reserve(qap.num_inputs);

                            const typename CurveType::scalar_field_type::value_type gamma_ABC_0 =
                                (beta * At[0] + alpha * Bt[0] + Ct[0]) * gamma_inverse;
                            for (std::size_t i = 1; i < qap.num_inputs + 1; ++i) {
                                gamma_ABC.emplace_back((beta * At[i] + alpha * Bt[i] + Ct[i]) * gamma_inverse);
                            }

                            /* The delta inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * delta^{-1}. */
                            std::vector<typename CurveType::scalar_field_type::value_type> Lt;
                            Lt.reserve(qap.num_variables - qap.num_inputs);

                            const std::size_t Lt_offset = qap.num_inputs + 1;
                            for (std::size_t i = 0; i < qap.num_variables - qap.num_inputs; ++i) {
                                Lt.emplace_back((beta * At[Lt_offset + i] + alpha * Bt[Lt_offset + i] + Ct[Lt_offset + i]) *
                                                delta_inverse);
                            }

                            /**
                             * Note that H for Groth's proof system is degree d-2, but the QAP
                             * reduction returns coefficients for degree d polynomial H (in
                             * style of PGHR-type proof systems)
                             */
                            Ht.resize(Ht.size() - 2);

        #ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or
                                                                                 // call omp_set_num_threads()
        #else
                            const std::size_t chunks = 1;
        #endif

                            const typename CurveType::g1_type g1_generator = curve_random_element<typename CurveType::g1_type>();
                            const std::size_t g1_scalar_count = non_zero_At + non_zero_Bt + qap.num_variables;
                            const std::size_t g1_scalar_size = CurveType::scalar_field_type::value_bits;
                            const std::size_t g1_window_size = 128;
                                //algebra::get_exp_window_size<typename CurveType::g1_type>(g1_scalar_count);
                                // uncomment
                                // when get_exp_window_size ready

                            std::vector<std::vector<typename CurveType::g1_type>> g1_table;
                            /*algebra::window_table<typename CurveType::g1_type> g1_table =
                                algebra::get_window_table(g1_scalar_size, g1_window_size, g1_generator);*/
                            // uncomment
                            // when get_window_table ready

                            const typename CurveType::g2_type G2_gen = curve_random_element<typename CurveType::g2_type>();
                            const std::size_t g2_scalar_count = non_zero_Bt;
                            const std::size_t g2_scalar_size = CurveType::scalar_field_type::value_bits;
                            std::size_t g2_window_size = 128;
                                //algebra::get_exp_window_size<typename CurveType::g2_type>(g2_scalar_count);
                                // uncomment
                                // when get_exp_window_size ready

                            std::vector<std::vector<typename CurveType::g2_type>> g2_table;
                            /*algebra::window_table<typename CurveType::g2_type> g2_table =
                                algebra::get_window_table(g2_scalar_size, g2_window_size, G2_gen);*/
                            // uncomment
                            // when get_window_table ready

                            typename CurveType::g1_type alpha_g1 = g1_generator;
                            typename CurveType::g1_type beta_g1 = g1_generator;
                            typename CurveType::g2_type beta_g2 = G2_gen;
                            typename CurveType::g1_type delta_g1 = g1_generator;
                            typename CurveType::g2_type delta_g2 = G2_gen;
                            
                            /*typename CurveType::g1_type alpha_g1 = alpha * g1_generator;
                            typename CurveType::g1_type beta_g1 = beta * g1_generator;
                            typename CurveType::g2_type beta_g2 = beta * G2_gen;
                            typename CurveType::g1_type delta_g1 = delta * g1_generator;
                            typename CurveType::g2_type delta_g2 = delta * G2_gen;*/
                                // uncomment
                                // when multiplication ready

                            typename CurveType::g1_vector A_query;
                            //= batch_exp(g1_scalar_size, g1_window_size, g1_table, At);
                            // uncomment
                                // when batch_exp ready
        #ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(A_query);
        #endif

                            knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> B_query /*=
                                kc_batch_exp(CurveType::scalar_field_type::value_bits, g2_window_size, g1_window_size,
                                             g2_table, g1_table, CurveType::scalar_field_type::value_type::one(),
                                             CurveType::scalar_field_type::value_type::one(), Bt, chunks)*/;

                                // uncomment
                                // when multiexp ready

                            // NOTE: if USE_MIXED_ADDITION is defined,
                            // kc_batch_exp will convert its output to special form internally

                            typename CurveType::g1_vector H_query ;
                            //= batch_exp_with_coeff(g1_scalar_size, g1_window_size, g1_table, qap.Zt * delta_inverse, Ht);
                                // uncomment
                                // when batch_exp_with_coeff ready
        #ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(H_query);
        #endif

                            typename CurveType::g1_vector L_query ;
                            //= batch_exp(g1_scalar_size, g1_window_size, g1_table, Lt);
                            // uncomment
                                // when batch_exp ready
        #ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(L_query);
        #endif

                            typename CurveType::gt_type alpha_g1_beta_g2 = pairing_policy::reduced_pairing(alpha_g1, beta_g2);
                            typename CurveType::g2_type gamma_g2 = G2_gen;
                            //typename CurveType::g2_type gamma_g2 = gamma * G2_gen;
                            // uncomment
                                // when multiplication ready

                            typename CurveType::g1_type gamma_ABC_g1_0 = g1_generator;
                            //typename CurveType::g1_type gamma_ABC_g1_0 = gamma_ABC_0 * g1_generator;
                            // uncomment
                                // when multiplication ready
                            typename CurveType::g1_vector gamma_ABC_g1_values ;
                            //= batch_exp(g1_scalar_size, g1_window_size, g1_table, gamma_ABC);
                                // uncomment
                                // when batch_exp ready

                            accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1(std::move(gamma_ABC_g1_0),
                                                                                          std::move(gamma_ABC_g1_values));

                            verification_key<CurveType> vk = verification_key<CurveType>(
                                alpha_g1_beta_g2, gamma_g2, delta_g2, gamma_ABC_g1);

                            proving_key<CurveType> pk =
                                proving_key<CurveType>(std::move(alpha_g1),
                                                                         std::move(beta_g1),
                                                                         std::move(beta_g2),
                                                                         std::move(delta_g1),
                                                                         std::move(delta_g2),
                                                                         std::move(A_query),
                                                                         std::move(B_query),
                                                                         std::move(H_query),
                                                                         std::move(L_query),
                                                                         std::move(r1cs_copy));

                            return keypair<CurveType>(std::move(pk), std::move(vk));
                        }

                        /**
                         * A prover algorithm for the R1CS GG-ppzkSNARK.
                         *
                         * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                         * produces a proof (of knowledge) that attests to the following statement:
                         *               ``there exists Y such that CS(X,Y)=0''.
                         * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                         */
                        static proof<CurveType> prover(const proving_key<CurveType> &pk,
                                                const primary_input<CurveType> &primary_input,
                                                const auxiliary_input<CurveType> &auxiliary_input) {

                            const qap_witness<typename CurveType::scalar_field_type> qap_wit = r1cs_to_qap_witness_map(
                                pk.constraint_system, primary_input, auxiliary_input, CurveType::scalar_field_type::value_type::zero(),
                                CurveType::scalar_field_type::value_type::zero(), CurveType::scalar_field_type::value_type::zero());

                            /* We are dividing degree 2(d-1) polynomial by degree d polynomial
                               and not adding a PGHR-style ZK-patch, so our H is degree d-2 */
                            assert(!qap_wit.coefficients_for_H[qap_wit.degree - 2].is_zero());
                            assert(qap_wit.coefficients_for_H[qap_wit.degree - 1].is_zero());
                            assert(qap_wit.coefficients_for_H[qap_wit.degree].is_zero());

                            /* Choose two random field elements for prover zero-knowledge. */
                            const typename CurveType::scalar_field_type::value_type r = field_random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type s = field_random_element<typename CurveType::scalar_field_type>();

        #ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or
                                                                                 // call omp_set_num_threads()
        #else
                            const std::size_t chunks = 1;
        #endif

                            // TODO: sort out indexing
                            std::vector<typename CurveType::scalar_field_type::value_type> const_padded_assignment(
                                1, CurveType::scalar_field_type::value_type::one());
                            const_padded_assignment.insert(const_padded_assignment.end(), qap_wit.coefficients_for_ABCs.begin(),
                                                           qap_wit.coefficients_for_ABCs.end());

                            typename CurveType::g1_type evaluation_At = CurveType::g1_type::zero();
                                /*algebra::multi_exp_with_mixed_addition<typename CurveType::g1_type,
                                                                       typename CurveType::scalar_field_type,
                                                                       algebra::multi_exp_method_BDLO12>(
                                    pk.A_query.begin(),
                                    pk.A_query.begin() + qap_wit.num_variables() + 1,
                                    const_padded_assignment.begin(),
                                    const_padded_assignment.begin() + qap_wit.num_variables() + 1,
                                    chunks);*/

                                   // uncomment
                                    // when multi_exp_with_mixed_addition ready

                            knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> evaluation_Bt;

                                /*kc_multi_exp_with_mixed_addition<typename CurveType::g2_type, typename CurveType::g1_type,
                                                                 typename CurveType::scalar_field_type,
                                                                 algebra::multi_exp_method_BDLO12>(
                                    pk.B_query,
                                    0,
                                    qap_wit.num_variables() + 1,
                                    const_padded_assignment.begin(),
                                    const_padded_assignment.begin() + qap_wit.num_variables() + 1,
                                    chunks);*/

                                     // uncomment
                                    // when kc_multi_exp_with_mixed_addition ready
                            typename CurveType::g1_type evaluation_Ht = CurveType::g1_type::zero();
                                /*algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                   algebra::multi_exp_method_BDLO12>(
                                    pk.H_query.begin(),
                                    pk.H_query.begin() + (qap_wit.degree - 1),
                                    qap_wit.coefficients_for_H.begin(),
                                    qap_wit.coefficients_for_H.begin() + (qap_wit.degree - 1),
                                    chunks);*/

                                   // uncomment
                                    // when multi_exp ready
                            typename CurveType::g1_type evaluation_Lt = CurveType::g1_type::zero();
                                /*algebra::multi_exp_with_mixed_addition<typename CurveType::g1_type,
                                                                       typename CurveType::scalar_field_type,
                                                                       algebra::multi_exp_method_BDLO12>(
                                    pk.L_query.begin(),
                                    pk.L_query.end(),
                                    const_padded_assignment.begin() + qap_wit.num_inputs() + 1,
                                    const_padded_assignment.begin() + qap_wit.num_variables() + 1,
                                    chunks);*/

                                   // uncomment
                                    // when multi_exp_with_mixed_addition ready

                            /* A = alpha + sum_i(a_i*A_i(t)) + r*delta */
                            typename CurveType::g1_type g1_A = pk.alpha_g1 + evaluation_At;
                            //typename CurveType::g1_type g1_A = pk.alpha_g1 + evaluation_At + r * pk.delta_g1;
                            // uncomment
                            // when multiplication ready

                            /* B = beta + sum_i(a_i*B_i(t)) + s*delta */
                            typename CurveType::g1_type g1_B = pk.beta_g1 + evaluation_Bt.h;
                            typename CurveType::g2_type g2_B = pk.beta_g2 + evaluation_Bt.g;
                            //typename CurveType::g1_type g1_B = pk.beta_g1 + evaluation_Bt.h + s * pk.delta_g1;
                            //typename CurveType::g2_type g2_B = pk.beta_g2 + evaluation_Bt.g + s * pk.delta_g2;
                            // uncomment
                            // when multiplication ready

                            /* C = sum_i(a_i*((beta*A_i(t) + alpha*B_i(t) + C_i(t)) + H(t)*Z(t))/delta) + A*s + r*b - r*s*delta
                             */
                            typename CurveType::g1_type g1_C;
                            //     = evaluation_Ht + evaluation_Lt + s * g1_A + r * g1_B - (r * s) * pk.delta_g1;
                            // uncomment
                            // when multiplication ready

                            proof<CurveType> proof =
                                proof<CurveType>(std::move(g1_A), std::move(g2_B), std::move(g1_C));

                            return proof;
                        }

                        /*
                          Below are four variants of verifier algorithm for the R1CS GG-ppzkSNARK.

                          These are the four cases that arise from the following two choices:

                          (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
                          In the latter case, we call the algorithm an "online verifier".

                          (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                          Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                          weak input consistency requires that |primary_input| <= CS.num_inputs (and
                          the primary input is implicitly padded with zeros up to length CS.num_inputs).
                        */

                        /****************************** Miscellaneous ********************************/

                        /**
                         * Convert a (non-processed) verification key into a processed verification key.
                         */
                        static processed_verification_key<CurveType>
                            verifier_process_vk(const verification_key<CurveType> &vk) {

                            using pairing_policy = typename CurveType::pairing_policy;

                            processed_verification_key<CurveType> pvk;
                            pvk.vk_alpha_g1_beta_g2 = vk.alpha_g1_beta_g2;
                            pvk.vk_gamma_g2_precomp = pairing_policy::precompute_g2(vk.gamma_g2);
                            pvk.vk_delta_g2_precomp = pairing_policy::precompute_g2(vk.delta_g2);
                            //pvk.gamma_ABC_g1 = vk.gamma_ABC_g1;
                            // when ready

                            return pvk;
                        }

                        /**
                         * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                         * (1) accepts a processed verification key, and
                         * (2) has weak input consistency.
                         */
                        static bool online_verifier_weak_IC( const processed_verification_key<CurveType> &pvk,
                                                                        const primary_input<CurveType> &primary_input,
                                                                        const proof<CurveType> &proof) {

                            using pairing_policy = typename CurveType::pairing_policy;

                            assert(pvk.gamma_ABC_g1.domain_size() >= primary_input.size());

                            accumulation_vector<typename CurveType::g1_type> accumulated_IC ;
                                /*const accumulation_vector<typename CurveType::g1_type> accumulated_IC 
                                 = pvk.gamma_ABC_g1.template accumulate_chunk<typename CurveType::scalar_field_type>(
                                    primary_input.begin(), primary_input.end(), 0);*/
                            // uncomment
                            // when accumulate_chunk ready
                            const typename CurveType::g1_type &acc = accumulated_IC.first;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }
                            const typename pairing_policy::G1_precomp proof_g_A_precomp = pairing_policy::precompute_g1(proof.g_A);
                            const typename pairing_policy::G2_precomp proof_g_B_precomp = pairing_policy::precompute_g2(proof.g_B);
                            const typename pairing_policy::G1_precomp proof_g_C_precomp = pairing_policy::precompute_g1(proof.g_C);
                            const typename pairing_policy::G1_precomp acc_precomp = pairing_policy::precompute_g1(acc);

                            const typename pairing_policy::Fqk_type::value_type QAP1 = pairing_policy::miller_loop(proof_g_A_precomp, proof_g_B_precomp);
                            const typename pairing_policy::Fqk_type::value_type QAP2 = pairing_policy::double_miller_loop(
                                acc_precomp, pvk.vk_gamma_g2_precomp, proof_g_C_precomp, pvk.vk_delta_g2_precomp);
                            const typename CurveType::gt_type QAP =
                                pairing_policy::final_exponentiation(QAP1 * QAP2.unitary_inversed());

                            if (QAP != pvk.vk_alpha_g1_beta_g2) {
                                result = false;
                            }

                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                         * (1) accepts a non-processed verification key, and
                         * (2) has weak input consistency.
                         */
                        static bool verifier_weak_IC(const verification_key<CurveType> &vk,
                                                                const primary_input<CurveType> &primary_input,
                                                                const proof<CurveType> &proof) {
                            processed_verification_key<CurveType> pvk =
                                verifier_process_vk<CurveType>(vk);
                            bool result = online_verifier_weak_IC<CurveType>(pvk, primary_input, proof);
                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                         * (1) accepts a processed verification key, and
                         * (2) has strong input consistency.
                         */
                        static bool online_verifier_strong_IC(
                            const processed_verification_key<CurveType> &pvk,
                            const primary_input<CurveType> &primary_input,
                            const proof<CurveType> &proof) {
                            bool result = true;

                            if (pvk.gamma_ABC_g1.domain_size() != primary_input.size()) {
                                result = false;
                            } else {
                                result = online_verifier_weak_IC(pvk, primary_input, proof);
                            }

                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                         * (1) accepts a non-processed verification key, and
                         * (2) has strong input consistency.
                         */
                        static bool verifier_strong_IC(
                            const verification_key<CurveType> &vk,
                            const primary_input<CurveType> &primary_input,
                            const proof<CurveType> &proof) {
                            processed_verification_key<CurveType> pvk =
                                verifier_process_vk<CurveType>(vk);
                            bool result = online_verifier_strong_IC<CurveType>(pvk, primary_input, proof);
                            return result;
                        }

                        /**
                         * For debugging purposes (of verifier_component):
                         *
                         * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                         * (1) accepts a non-processed verification key,
                         * (2) has weak input consistency, and
                         * (3) uses affine coordinates for elliptic-curve computations.
                         */
                        static bool affine_verifier_weak_IC( const verification_key<CurveType> &vk,
                                                                        const primary_input<CurveType> &primary_input,
                                                                        const proof<CurveType> &proof) {

                            using pairing_policy = typename CurveType::pairing_policy;

                            assert(vk.gamma_ABC_g1.domain_size() >= primary_input.size());

                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_gamma_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.gamma_g2);
                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_delta_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.delta_g2);

                            const accumulation_vector<typename CurveType::g1_type> accumulated_IC =
                                vk.gamma_ABC_g1.template accumulate_chunk<typename CurveType::scalar_field_type>(
                                    primary_input.begin(), primary_input.end(), 0);
                            const typename CurveType::g1_type &acc = accumulated_IC.first;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }

                            const typename pairing_policy::affine_ate_G1_precomp proof_g_A_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_A);
                            const typename pairing_policy::affine_ate_G2_precomp proof_g_B_precomp =
                                pairing_policy::affine_ate_precompute_G2(proof.g_B);
                            const typename pairing_policy::affine_ate_G1_precomp proof_g_C_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_C);
                            const typename pairing_policy::affine_ate_G1_precomp acc_precomp =
                                pairing_policy::affine_ate_precompute_G1(acc);

                            const typename pairing_policy::Fqk::value_type QAP_miller = CurveType::affine_ate_e_times_e_over_e_miller_loop(
                                acc_precomp, pvk_vk_gamma_g2_precomp, proof_g_C_precomp, pvk_vk_delta_g2_precomp,
                                proof_g_A_precomp, proof_g_B_precomp);
                            const typename CurveType::gt_type QAP =
                                pairing_policy::final_exponentiation(QAP_miller.unitary_inversed());

                            if (QAP != vk.alpha_g1_beta_g2) {
                                result = false;
                            }
                            return result;
                        }

                    };
                }    // namespace detail
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_FUNCTIONS_HPP