/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_publisher.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>

namespace hotplace {
namespace io {

asn1_publisher::asn1_publisher() {}

asn1_publisher::~asn1_publisher() {}

return_t asn1_publisher::build(const parse_tree* pt, asn1_object** object) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pt || nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *object = nullptr;

        prepare();
        prepare_constraints();

        asn1_publisher_context context;

        auto lambda = [&](parser_action_t action, parse_treenode* node) -> return_t {
            return_t test = errorcode_t::success;
            if (parser_action_t::shift == action) {
                asn1_semantic_node asn;
                asn.symbol = node->symbol;
                asn.value = node->value;
                context.push(std::move(asn));
            } else if (parser_action_t::reduce == action) {
                auto iter = _handler_map.find(node->symbol);
                if (_handler_map.end() != iter) {
                    test = iter->second(node, context);
                } else {
                    auto size = node->sizeof_rhs();
                    if (context.size() < size)
                        test = errorcode_t::invalid_context;
                    else
                        test = default_handler(node, context);
                }
            }
            return test;
        };
        parse_tree_visitor visitor(lambda);
        ret = pt->accept(&visitor);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (1 != context.size()) {
            ret = errorcode_t::internal_error;  // not implemented
            __leave2;
        }

        auto top = context.pop();
        *object = top.object;
        top.release();  // *object own top.object
    }
    __finally2 {}
    return ret;
}

}  // namespace io
}  // namespace hotplace
