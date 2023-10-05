//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef ACTOR_ZK_PLONK_PLACEHOLDER_PROFILING_HPP
#define ACTOR_ZK_PLONK_PLACEHOLDER_PROFILING_HPP

#include <algorithm>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/actor/math/algorithms/make_evaluation_domain.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/params.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace snark {

                template<typename PlaceholderParams>
                struct placeholder_profiling;

                template<typename PlaceholderParams>
                void print_placeholder_params(
                    const typename placeholder_public_preprocessor<
                        typename PlaceholderParams::field_type, 
                        PlaceholderParams
                    >::preprocessed_data_type &preprocessed_data,
                    const typename PlaceholderParams::commitment_scheme_type &commitment_scheme,
                    std::string filename,
                    std::string circuit_name = "Sample proof"
                ){
                    boost::property_tree::ptree root;
                    root.put("test_name", circuit_name);
                    root.put("modulus", PlaceholderParams::field_type::modulus);
                    root.put("rows_amount", preprocessed_data.common_data.rows_amount);
                    root.put("usable_rows_amount", preprocessed_data.common_data.usable_rows_amount);
                    root.put("omega", preprocessed_data.common_data.basic_domain->get_domain_element(1));
                    root.put("verification_key", preprocessed_data.common_data.vk.to_string());
                    
                    boost::property_tree::ptree ar_params_node;
                    boost::property_tree::ptree witness_node;
                    witness_node.put("", PlaceholderParams::witness_columns);
                    ar_params_node.push_back(std::make_pair("", witness_node));
                    boost::property_tree::ptree public_input_node;
                    public_input_node.put("", PlaceholderParams::public_input_columns);
                    ar_params_node.push_back(std::make_pair("", public_input_node));
                    boost::property_tree::ptree constant_node;
                    constant_node.put("", PlaceholderParams::constant_columns);
                    ar_params_node.push_back(std::make_pair("", constant_node));
                    boost::property_tree::ptree selector_node;
                    selector_node.put("", PlaceholderParams::selector_columns);
                    ar_params_node.push_back(std::make_pair("", witness_node));
                    root.add_child("ar_params", ar_params_node);

                    boost::property_tree::ptree c_rotations_node;
                    for( std::size_t i = 0; i < preprocessed_data.common_data.columns_rotations.size(); i++ ){
                        boost::property_tree::ptree column_node;
                        for( int r: preprocessed_data.common_data.columns_rotations[i]){
                            boost::property_tree::ptree rotation_node;
                            rotation_node.put("", r);
                            column_node.push_back(std::make_pair("", rotation_node));
                        }
                        c_rotations_node.push_back(std::make_pair("", column_node));
                    }
                    root.add_child("columns_rotations_node", c_rotations_node);

                    boost::property_tree::ptree commitment_scheme_params_node = commitment_scheme.get_params();
                    root.add_child("commitment_params_node", commitment_scheme_params_node);

                    std::ofstream out;
                    out.open(filename);
                    boost::property_tree::write_json(out, root);
                    out.close();
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace actor
}    // namespace nil

#endif    // ACTOR_ZK_PLONK_PLACEHOLDER_PROFILING_HPP
