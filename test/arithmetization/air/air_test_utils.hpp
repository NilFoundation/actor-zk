#ifndef STARKWARE_AIR_AIR_TEST_UTILS_H_
#define STARKWARE_AIR_AIR_TEST_UTILS_H_

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <nil/crypto3/zk/snark/arithmetization/air/air.hpp>
#include <nil/crypto3/zk/snark/arithmetization/air/trace.hpp>

namespace starkware {

    /*
      A basic and flexible AIR class, used for testing.
    */
    class DummyAir : public Air {
    public:
        explicit DummyAir(uint64_t trace_length) : Air(trace_length) {
        }

        uint64_t GetCompositionPolynomialDegreeBound() const override {
            return 2 * TraceLength();
        }

        uint64_t NumRandomCoefficients() const override {
            return 2 * constraints.size();
        }

        uint64_t NumColumns() const override {
            return n_columns;
        }

        template<typename FieldElementT>
        ExtensionFieldElement ConstraintsEval(gsl::span<const FieldElementT> neighbors,
                                              gsl::span<const ExtensionFieldElement>
                                                  composition_neighbors,
                                              gsl::span<const FieldElementT>
                                                  periodic_columns,
                                              gsl::span<const ExtensionFieldElement>
                                                  random_coefficients,
                                              gsl::span<const FieldElementT>
                                                  point_powers,
                                              gsl::span<const BaseFieldElement>
                                                  shifts) const {
            ASSERT_RELEASE(random_coefficients.size() == NumRandomCoefficients(),
                           "Wrong number of random coefficients.");
            ExtensionFieldElement res = ExtensionFieldElement::Zero();
            for (const auto &constraint : constraints) {
                res += constraint(
                    std::vector<ExtensionFieldElement> {neighbors.begin(), neighbors.end()},
                    std::vector<ExtensionFieldElement> {composition_neighbors.begin(), composition_neighbors.end()},
                    std::vector<ExtensionFieldElement> {periodic_columns.begin(), periodic_columns.end()},
                    random_coefficients, std::vector<ExtensionFieldElement> {point_powers.begin(), point_powers.end()},
                    shifts);
            }
            return res;
        }

        std::unique_ptr<CompositionPolynomial> CreateCompositionPolynomial(const BaseFieldElement &trace_generator,
                                                                           gsl::span<const ExtensionFieldElement>
                                                                               random_coefficients) const override {
            typename CompositionPolynomialImpl<DummyAir>::Builder builder(periodic_columns.size());

            for (size_t i = 0; i < periodic_columns.size(); ++i) {
                builder.AddPeriodicColumn(periodic_columns[i], i);
            }

            return builder.BuildUniquePtr(UseOwned(this), trace_generator, TraceLength(), random_coefficients,
                                          point_exponents, BatchPow(trace_generator, gen_exponents));
        }

        /*
          A helper function for tests that do not specify a generator.
        */
        std::unique_ptr<CompositionPolynomial>
            CreateCompositionPolynomial(gsl::span<const ExtensionFieldElement> random_coefficients) const {
            return CreateCompositionPolynomial(GetSubGroupGenerator(TraceLength()), random_coefficients);
        }

        std::vector<std::pair<int64_t, uint64_t>> GetMask() const override {
            return mask;
        }

        size_t n_columns = 0;
        std::vector<std::pair<int64_t, uint64_t>> mask;

        std::vector<PeriodicColumn> periodic_columns;
        std::vector<uint64_t> point_exponents;
        std::vector<uint64_t> gen_exponents;
        std::vector<std::function<ExtensionFieldElement(gsl::span<const ExtensionFieldElement> neighbors,
                                                        gsl::span<const ExtensionFieldElement>
                                                            composition_neighbors,
                                                        gsl::span<const ExtensionFieldElement>
                                                            periodic_columns,
                                                        gsl::span<const ExtensionFieldElement>
                                                            random_coefficients,
                                                        gsl::span<const ExtensionFieldElement>
                                                            point_powers,
                                                        gsl::span<const BaseFieldElement>
                                                            shifts)>>
            constraints;
    };

    /*
      Returns the degree after applying the air constraints, given the provided random coefficients, on
      the provided trace. Used for air-constraints unit testing. This function assumes the random
      coefficients are used only to bind constraints together, meaning, the number of constraints is
      exactly half the number of random coefficients and the composition polynomial is of the form:
      \sum constraint_i(x) * (coeff_{2*i} + coeff_{2*i+1} * x^{n_i}).
    */
    int64_t ComputeCompositionDegree(const Air &air, const Trace &trace,
                                     gsl::span<const ExtensionFieldElement> random_coefficients,
                                     size_t num_of_cosets = 2) {
        ASSERT_RELEASE((trace.Width() > 0) && (trace.Length() > 0), "Trace must not be empty.");

        // Evaluation domain specifications.
        const size_t coset_size = trace.Length();
        const size_t evaluation_domain_size = Pow2(Log2Ceil(air.GetCompositionPolynomialDegreeBound() * num_of_cosets));
        const size_t n_cosets = SafeDiv(evaluation_domain_size, coset_size);
        EvaluationDomain domain(coset_size, n_cosets);
        auto cosets = domain.CosetOffsets();
        const Coset source_domain_coset(coset_size, BaseFieldElement::One());

        // Allocate storage for trace LDE evaluations.
        std::unique_ptr<LdeManager<BaseFieldElement>> lde_manager =
            MakeLdeManager<BaseFieldElement>(source_domain_coset);
        std::vector<std::vector<BaseFieldElement>> trace_lde;
        trace_lde.reserve(trace.Width());
        for (size_t i = 0; i < trace.Width(); ++i) {
            lde_manager->AddEvaluation(trace.GetColumn(i));
            trace_lde.push_back(BaseFieldElement::UninitializedVector(coset_size));
        }

        // Construct composition polynomial.
        std::unique_ptr<CompositionPolynomial> composition_poly =
            air.CreateCompositionPolynomial(domain.TraceGenerator(), random_coefficients);

        // Evaluate composition.
        std::vector<ExtensionFieldElement> evaluation =
            ExtensionFieldElement::UninitializedVector(evaluation_domain_size);
        for (size_t i = 0; i < n_cosets; ++i) {
            const BaseFieldElement &coset_offset = cosets[BitReverse(i, SafeLog2(n_cosets))];
            lde_manager->EvalOnCoset(coset_offset,
                                     std::vector<gsl::span<BaseFieldElement>>(trace_lde.begin(), trace_lde.end()));

            constexpr uint64_t kTaskSize = 256;

            composition_poly->EvalOnCosetBitReversedOutput(
                coset_offset, std::vector<gsl::span<const BaseFieldElement>>(trace_lde.begin(), trace_lde.end()), {},
                gsl::make_span(evaluation).subspan(i * coset_size, coset_size), kTaskSize);
        }

        // Compute degree.
        const auto coset = Coset(evaluation_domain_size, BaseFieldElement::One());
        const auto lde = MakeLdeManager<ExtensionFieldElement>(coset, /*eval_in_natural_order=*/false);
        lde->AddEvaluation(std::move(evaluation));
        return lde->GetEvaluationDegree(0);
    }

}    // namespace starkware

#endif    // STARKWARE_AIR_AIR_TEST_UTILS_H_
