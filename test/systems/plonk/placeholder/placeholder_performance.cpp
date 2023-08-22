//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

//#define BOOST_TEST_MODULE placeholder_test

#include <string>
#include <random>
#include <iostream>
#include <fstream>
#include <vector>

#include <nil/actor/testing/test_case.hh>
#include <nil/actor/testing/thread_test_case.hh>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/actor/math/algorithms/calculate_domain_set.hpp>
#include <nil/actor/math/domains/evaluation_domain.hpp>
#include <nil/actor/math/polynomial/lagrange_interpolation.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/gates_argument.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/actor/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/actor/zk/transcript/fiat_shamir.hpp>
#include <nil/actor/zk/commitments/polynomial/fri.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/variable_mt.hpp>
#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/flat_expression_mt.hpp>
#include <nil/crypto3/marshalling/math/types/expression_mt.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_mt.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/copy_constraint_mt.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>

#include "circuits.hpp"

using namespace nil::actor;
using namespace nil::actor::zk;
using namespace nil::actor::zk::snark;

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
    using dist_type = std::uniform_int_distribution<int>;
    static std::random_device random_engine;

    std::vector<std::size_t> step_list;
    std::size_t steps_sum = 0;
    while (steps_sum != r) {
        if (r - steps_sum <= max_step) {
            while (r - steps_sum != 1) {
                step_list.emplace_back(r - steps_sum - 1);
                steps_sum += step_list.back();
            }
            step_list.emplace_back(1);
            steps_sum += step_list.back();
        } else {
            step_list.emplace_back(dist_type(1, max_step)(random_engine));
            steps_sum += step_list.back();
        }
    }
    return step_list;
}

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log, const int max_step = 1) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 4;

    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<nil::actor::math::evaluation_domain<FieldType>>> domain_set =
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r).get();

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;
    params.step_list = generate_random_step_list(r, max_step);

    return params;
}

using curve_type = nil::crypto3::algebra::curves::pallas;
using FieldType = typename curve_type::base_field_type;

// lpc params
constexpr static const std::size_t m = 2;

constexpr static const std::size_t table_rows_log = 4;
constexpr static const std::size_t table_rows = 1 << table_rows_log;
constexpr static const std::size_t permutation_size = 4;
constexpr static const std::size_t usable_rows = (1 << table_rows_log) - 3;

struct placeholder_test_params {
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<512>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 2;

    using arithmetization_params =
        plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

struct placeholder_test_params_lookups {
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<512>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 0;
    constexpr static const std::size_t constant_columns = 3;
    constexpr static const std::size_t selector_columns = 1;

    using arithmetization_params =
        plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

struct placeholder_fibonacci_params {
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<512>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 1;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 1;

    using arithmetization_params =
        plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = 4;
    constexpr static const std::size_t m = 2;
};

constexpr static const std::size_t table_columns =
    placeholder_test_params::witness_columns + placeholder_test_params::public_input_columns;

typedef commitments::fri<
    FieldType,
    placeholder_test_params::merkle_hash_type,
    placeholder_test_params::transcript_hash_type,
    placeholder_test_params::lambda, m, 4
> fri_type;

typedef placeholder_params<FieldType, typename placeholder_test_params::arithmetization_params> circuit_2_params;
typedef placeholder_params<FieldType, typename placeholder_fibonacci_params::arithmetization_params> circuit_fib_params;
typedef placeholder_params<FieldType, typename placeholder_test_params_lookups::arithmetization_params>
    circuit_3_params;


ACTOR_THREAD_TEST_CASE(placeholder_large_fibonacci_test) {
    constexpr std::size_t rows_log = 10;
    std::cout << std::endl << "Fibonacci test rows_log = "<< rows_log << std::endl;

    auto circuit = circuit_test_fib<FieldType, rows_log>();

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_fib_params>;

    typedef commitments::lpc<FieldType, circuit_fib_params::batched_commitment_params_type> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(rows_log);

    plonk_table_description<FieldType, typename circuit_fib_params::arithmetization_params> desc;

    desc.rows_amount = 1 << rows_log;
    desc.usable_rows_amount = desc.rows_amount - 3;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
                                                                   
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1};

    typename placeholder_public_preprocessor<FieldType, circuit_fib_params>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<FieldType, circuit_fib_params>::process(
            constraint_system, assignments.public_table(), desc, fri_params, columns_with_copy_constraints.size()).get();

    typename placeholder_private_preprocessor<FieldType, circuit_fib_params>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<FieldType, circuit_fib_params>::process(
            constraint_system, assignments.private_table(), desc, fri_params).get();

    auto proof = placeholder_prover<FieldType, circuit_fib_params>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, fri_params);

    bool verifier_res = placeholder_verifier<FieldType, circuit_fib_params>::process(
        preprocessed_public_data, proof, constraint_system, fri_params);
    BOOST_CHECK(verifier_res);
    std::cout << "==========================================================="<<std::endl;
}
/*
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexp
    r std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 5;
    constexpr std::size_t ConstantColumns = 5;
    constexpr std::size_t SelectorColumns = 30;

    using ArithmetizationParams =
        nil::actor::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns,
                                                                SelectorColumns>;
    using ConstraintSystemType =
        nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using TableDescriptionType =
        nil::actor::zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams>;
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using value_marshalling_type = nil::crypto3::marshalling::types::plonk_constraint_system<TTypeBase, ConstraintSystemType>;
    using columns_rotations_type = std::array<std::set<int>, ArithmetizationParams::total_columns>;
    using ColumnType = nil::actor::zk::snark::plonk_column<BlueprintFieldType>;
    using TableAssignmentType =
        nil::actor::zk::snark::plonk_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
    const std::size_t Lambda = 2;
    using Hash = nil::crypto3::hashes::keccak_1600<256>;
    using placeholder_params_type =
        nil::actor::zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;
    using types = nil::actor::zk::snark::detail::placeholder_policy<BlueprintFieldType, placeholder_params_type>;
    using FRIScheme =
        typename nil::actor::zk::commitments::fri<BlueprintFieldType, typename placeholder_params_type::merkle_hash_type,
                                                    typename placeholder_params_type::transcript_hash_type, Lambda, 2, 4>;
    using FRIParamsType = typename FRIScheme::params_type;

columns_rotations_type load_columns_rotations(
    const ConstraintSystemType &constraint_system,  const TableDescriptionType &table_description
) {
    using variable_type = typename nil::actor::zk::snark::plonk_variable<typename ConstraintSystemType::field_type>;

    columns_rotations_type result;
    for (const auto& gate: constraint_system.gates()) {
        for (const auto& constraint: gate.constraints) {
            nil::actor::math::expression_for_each_variable_visitor<variable_type> visitor(
                [&table_description, &result](const variable_type& var) {
                    if (var.relative) {
                        std::size_t column_index = table_description.global_index(var);
                        result[column_index].insert(var.rotation);
                    }
                });
            visitor.visit(constraint);
        }
    }

    for (const auto& gate: constraint_system.lookup_gates()) {
        for (const auto& constraint: gate.constraints) {
            for (const auto& lookup_input: constraint.lookup_input) {
                const auto& var = lookup_input.vars[0];
                if (var.relative) {
                    std::size_t column_index = table_description.global_index(var);
                    result[column_index].insert(var.rotation);
                }
            }
        }
    }

    for (std::size_t i = 0; i < ArithmetizationParams::total_columns; i++) {
        result[i].insert(0);
    }

    return result;
}

bool read_buffer_from_file(std::ifstream &ifile, std::vector<std::uint8_t> &v) {
    char c;
    char c1;
    uint8_t b;

    ifile >> c;
    if (c != '0')
        return false;
    ifile >> c;
    if (c != 'x')
        return false;
    while (ifile) {
        std::string str = "";
        ifile >> c >> c1;
        if (!isxdigit(c) || !isxdigit(c1))
            return false;
        str += c;
        str += c1;
        b = stoi(str, 0, 0x10);
        v.push_back(b);
    }
    return true;
}

template<typename BlueprintFieldType, typename ArithmetizationParams, typename ColumnType>
std::tuple<std::size_t, std::size_t,
           nil::actor::zk::snark::plonk_table<BlueprintFieldType, ArithmetizationParams, ColumnType>>
    load_assignment_table(std::istream &istr) {
    using PrivateTableType =
        nil::actor::zk::snark::plonk_private_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
    using PublicTableType =
        nil::actor::zk::snark::plonk_public_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
    using TableAssignmentType =
        nil::actor::zk::snark::plonk_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
    std::size_t usable_rows;
    std::size_t rows_amount;

    typename PrivateTableType::witnesses_container_type witness;
    typename PublicTableType::public_input_container_type public_input;
    typename PublicTableType::constant_container_type constant;
    typename PublicTableType::selector_container_type selector;

    istr >> usable_rows;
    istr >> rows_amount;

    for (size_t i = 0; i < witness.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
        ColumnType column;
        typename BlueprintFieldType::integral_type num;
        for (size_t j = 0; j < rows_amount; j++) {
            istr >> num;
            column.push_back(typename BlueprintFieldType::value_type(num));
        }
        witness[i] = column;
    }

    for (size_t i = 0; i < public_input.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
        ColumnType column;
        typename BlueprintFieldType::integral_type num;
        for (size_t j = 0; j < rows_amount; j++) {
            istr >> num;
            column.push_back(typename BlueprintFieldType::value_type(num));
        }
        public_input[i] = column;
    }

    for (size_t i = 0; i < constant.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
        ColumnType column;
        typename BlueprintFieldType::integral_type num;
        for (size_t j = 0; j < rows_amount; j++) {
            istr >> num;
            column.push_back(typename BlueprintFieldType::value_type(num));
        }
        constant[i] = column;
    }
    for (size_t i = 0; i < selector.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
        ColumnType column;
        typename BlueprintFieldType::integral_type num;
        for (size_t j = 0; j < rows_amount; j++) {
            istr >> num;
            column.push_back(typename BlueprintFieldType::value_type(num));
        }
        selector[i] = column;
    }
    return std::make_tuple(
        usable_rows, rows_amount,
        TableAssignmentType(PrivateTableType(witness), PublicTableType(public_input, constant, selector)));
}

void load_circuit_and_table(ConstraintSystemType &circuit, TableAssignmentType &table, TableDescriptionType &table_description, std::string input_folder_path){
    std::string ifile_path;
    std::string iassignment_path;

    ifile_path = input_folder_path + "/circuit.crct";
    iassignment_path = input_folder_path + "/assignment.tbl";

    std::ifstream ifile;
    ifile.open(ifile_path);
    if (!ifile.is_open()) {
        std::cout << "Cannot find input file " << ifile_path << std::endl;
        BOOST_ASSERT(false);
    }
    std::vector<std::uint8_t> v;
    if (!read_buffer_from_file(ifile, v)) {
        std::cout << "Cannot parse input file " << ifile_path << std::endl;
        BOOST_ASSERT(false);
    }
    ifile.close();

    value_marshalling_type marshalled_data;
    auto read_iter = v.begin();
    auto status = marshalled_data.read(read_iter, v.size());
    circuit = nil::crypto3::marshalling::types::make_plonk_constraint_system<ConstraintSystemType, Endianness>(
            marshalled_data);

    std::ifstream iassignment;
    iassignment.open(iassignment_path);
    if (!iassignment) {
        std::cout << "Cannot open " << iassignment_path << std::endl;
        BOOST_ASSERT(false);
    }

    std::tie(table_description.usable_rows_amount, table_description.rows_amount, table) =
        load_assignment_table<BlueprintFieldType, ArithmetizationParams, ColumnType>(iassignment);
    iassignment.close();
}

ACTOR_THREAD_TEST_CASE(placeholder_merkle_tree_sha2_test) {
    std::cout << std::endl << "Merkle tree SHA2 performance test" <<  std::endl;

    ConstraintSystemType constraint_system;
    TableAssignmentType assignment_table;
    TableDescriptionType table_description;

    load_circuit_and_table(constraint_system, assignment_table, table_description, "../libs/actor/zk/test/systems/plonk/placeholder/data/merkle_tree_sha2");
    auto columns_rotations = load_columns_rotations(constraint_system, table_description);

    std::size_t table_rows_log = std::ceil(std::log2(table_description.rows_amount));
    auto fri_params = create_fri_params<FRIScheme, BlueprintFieldType>(table_rows_log);
    std::size_t permutation_size =
        table_description.witness_columns + table_description.public_input_columns + table_description.constant_columns;

    typename nil::actor::zk::snark::placeholder_public_preprocessor<
        BlueprintFieldType, placeholder_params_type>::preprocessed_data_type public_preprocessed_data =
        nil::actor::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params_type>::process(
            constraint_system, assignment_table.public_table(), table_description, fri_params, permutation_size).get();
    typename nil::actor::zk::snark::placeholder_private_preprocessor<
        BlueprintFieldType, placeholder_params_type>::preprocessed_data_type private_preprocessed_data =
        nil::actor::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params_type>::process(
            constraint_system, assignment_table.private_table(), table_description, fri_params
        ).get();
        
    using ProofType = nil::actor::zk::snark::placeholder_proof<BlueprintFieldType, placeholder_params_type>;
    ProofType proof = nil::actor::zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params_type>::process(
        public_preprocessed_data, private_preprocessed_data, table_description, constraint_system, assignment_table,
        fri_params);

    bool verifier_res =
        nil::actor::zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params_type>::process(
            public_preprocessed_data, proof, constraint_system, fri_params);

    BOOST_CHECK(verifier_res);

    std::cout << "==========================================================="<<std::endl;
}

ACTOR_THREAD_TEST_CASE(placeholder_many_hashes_test) {
    std::cout << std::endl << "Many_hashes performance test" <<  std::endl;

    ConstraintSystemType constraint_system;
    TableAssignmentType assignment_table;
    TableDescriptionType table_description;

    load_circuit_and_table(constraint_system, assignment_table, table_description, "../libs/actor/zk/test/systems/plonk/placeholder/data/many_hashes");
    auto columns_rotations = load_columns_rotations(constraint_system, table_description);

    std::size_t table_rows_log = std::ceil(std::log2(table_description.rows_amount));
    auto fri_params = create_fri_params<FRIScheme, BlueprintFieldType>(table_rows_log);
    std::size_t permutation_size =
        table_description.witness_columns + table_description.public_input_columns + table_description.constant_columns;

    std::cout << "Public preprocessor" << std::endl;
    typename nil::actor::zk::snark::placeholder_public_preprocessor<
        BlueprintFieldType, placeholder_params_type>::preprocessed_data_type public_preprocessed_data =
        nil::actor::zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params_type>::process(
            constraint_system, assignment_table.public_table(), table_description, fri_params, permutation_size).get();
    std::cout << "Private preprocessor" << std::endl;
    typename nil::actor::zk::snark::placeholder_private_preprocessor<
        BlueprintFieldType, placeholder_params_type>::preprocessed_data_type private_preprocessed_data =
        nil::actor::zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params_type>::process(
            constraint_system, assignment_table.private_table(), table_description, fri_params
        ).get();
        
    std::cout << "Private preprocessor" << std::endl;
    using ProofType = nil::actor::zk::snark::placeholder_proof<BlueprintFieldType, placeholder_params_type>;
    ProofType proof = nil::actor::zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params_type>::process(
        public_preprocessed_data, private_preprocessed_data, table_description, constraint_system, assignment_table,
        fri_params);

    bool verifier_res =
        nil::actor::zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params_type>::process(
            public_preprocessed_data, proof, constraint_system, fri_params);

    BOOST_CHECK(verifier_res);

    std::cout << "===========================================================" << std::endl;
}
*/