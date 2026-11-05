/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_publisher_parameterized.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/io/asn.1/asn1_advisor.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>

namespace hotplace {
namespace io {

void asn1_publisher::prepare_parameterized() {
    add_handler(
        "ParameterizedType", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ParameterizedType", {symid, "{", "ActualParameterList", "}"})
            // production("ParameterizedType", {"TypeIdentifier", "{", "ActualParameterList", "}"})

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
    // ParameterizedAssignment
    add_handler(
        "ParameterizedTypeAssignment", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ParameterizedTypeAssignment", {symid, "{", "ParameterList", "}", symassign, "Type"})
            // production("ParameterizedTypeAssignment", {symid, "{", "ParameterList", "}", symassign, "Type", "Constraint"})
            // production("ParameterizedTypeAssignment", {symuser, "{", "ParameterList", "}", symassign, "Type"})
            // production("ParameterizedTypeAssignment", {symuser, "{", "ParameterList", "}", symassign, "Type", "Constraint"})

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
            {
                const auto& name = rhs[0].value;
                auto& pt = context.get_paramtypes();
                auto obj = rhs[5].object;
                if (7 == size) {
                    // constraint
                }
                asn.object = asn1_parameterized_type::define(std::move(pt), name, obj);
                rhs[5].release();
            }
            context.push(std::move(asn));

            return errorcode_t::success;
        });
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
            if (1 == size) {
                auto& param0 = rhs[0];
                context.get_paramtypes().push_back({param0.value});
            } else if (3 == size) {
                auto& param0 = rhs[0];
                auto& param2 = rhs[2];
                context.get_paramtypes().push_back({param0.value, param2.value});
            }
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
            std::string oldsymbol = rhs[0].symbol;
            asn.symbol = node->symbol;
            if ("ActualParameter" == oldsymbol) {
                int debug = 1;
            }
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
            // if (1 == size) {
            //     asn.pt = std::move(rhs[0].pt);
            // }
            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ParameterizedValue
}

}  // namespace io
}  // namespace hotplace
