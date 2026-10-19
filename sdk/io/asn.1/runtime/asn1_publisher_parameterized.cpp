/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_publisher_parameterized.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *   Considerations for `asn1_modules` in a multi-threaded environment:
 *   - Whenever possible, use `add` and `get` operations that do not modify the current pointer.
 */

#include <hotplace/sdk/io/asn.1/asn1_advisor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>

namespace hotplace {
namespace io {

void asn1_publisher::prepare_parameterized() {
    // ParameterizedAssignment
    // ParameterizedTypeAssignment
    // ParameterizedValueAssignment
    add_handler(
        "ParameterList", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ParameterList", {"ParameterList", ",", "Parameter"})
            // production("ParameterList", {"Parameter"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    add_handler(
        "Parameter", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("Parameter", {"TypeIdentifier"})
            // production("Parameter", {"Type"})
            // production("Parameter", {symid, ":", symid})
            // production("Parameter", {symuser, ":", "TypeIdentifier"})
            // production("Parameter", {"Type", ":", "TypeIdentifier"})
            // production("Parameter", {"Type", ":", symid})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ParameterizedType
    add_handler(
        "ActualParameterList", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ActualParameterList", {"ActualParameterList", ",", "ActualParameter"})
            // production("ActualParameterList", {"ActualParameter"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ActualParameter
    add_handler(
        "ActualParameter", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ActualParameter", {"Type"})
            // production("ActualParameter", {"ValueElement"})
            // production("ActualParameter", {"{", "DefinitiveOidComponentList", "}"})
            // production("ActualParameter", {"{", "ValueElementList", "}"})
            // production("ActualParameter", {"{", "}"})
            // production("ActualParameter", {"TypeIdentifier"})

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
            }

            asn1_semantic_node asn;
            asn.symbol = node->symbol;
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ParameterizedValue
}

}  // namespace io
}  // namespace hotplace
