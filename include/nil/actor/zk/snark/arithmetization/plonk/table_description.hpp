//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef ACTOR_ZK_PLONK_PLACEHOLDER_TABLE_DESCRIPTION_HPP
#define ACTOR_ZK_PLONK_PLACEHOLDER_TABLE_DESCRIPTION_HPP

#include <nil/actor/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ArithmetizationParams>
                struct plonk_table_description {
                    constexpr static const std::size_t witness_columns =
                        ArithmetizationParams::WitnessColumns;
                    constexpr static const std::size_t public_input_columns =
                        ArithmetizationParams::PublicInputColumns;
                    constexpr static const std::size_t constant_columns =
                        ArithmetizationParams::ConstantColumns;
                    constexpr static const std::size_t selector_columns =
                        ArithmetizationParams::SelectorColumns;

                    std::size_t rows_amount = 0;
                    std::size_t usable_rows_amount = 0;

                    std::size_t global_index(const plonk_variable<FieldType> &a) const {
                        switch (a.type)
                        {
                        case plonk_variable<FieldType>::column_type::witness:
                            return a.index;
                        case plonk_variable<FieldType>::column_type::public_input:
                            return witness_columns + a.index;
                        case plonk_variable<FieldType>::column_type::constant:
                            return witness_columns +
                            public_input_columns + a.index;
                        case plonk_variable<FieldType>::column_type::selector:
                            return witness_columns +
                            public_input_columns +
                            constant_columns + a.index;
                        }
                    }

                    std::size_t table_width() const {
                        return witness_columns +
                            public_input_columns +
                            constant_columns +
                            selector_columns;
                    }
                };

#ifdef ZK_RUNTIME_CIRCUIT_DEFINITION
                template<typename FieldType>
                struct plonk_table_description {
                    std::size_t witness_columns;
                    std::size_t public_input_columns;
                    std::size_t constant_columns;
                    std::size_t selector_columns;

                    std::size_t rows_amount = 0;
                    std::size_t usable_rows_amount = 0;

                    std::size_t global_index(const plonk_variable<FieldType> &a) const {
                        switch (a.type)
                        {
                        case plonk_variable<FieldType>::column_type::witness:
                            return a.index;
                        case plonk_variable<FieldType>::column_type::public_input:
                            return witness_columns + a.index;
                        case plonk_variable<FieldType>::column_type::constant:
                            return witness_columns +
                            public_input_columns + a.index;
                        case plonk_variable<FieldType>::column_type::selector:
                            return witness_columns +
                            public_input_columns +
                            constant_columns + a.index;
                        }
                    }

                    std::size_t table_width() const {
                        return witness_columns +
                            public_input_columns +
                            constant_columns +
                            selector_columns;
                    }
                };
#endif
            }    // namespace snark
        }        // namespace zk
    }            // namespace actor
}    // namespace nil

#endif    // ACTOR_ZK_PLONK_PLACEHOLDER_TABLE_DESCRIPTION_HPP