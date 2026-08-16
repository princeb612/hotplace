/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_der_visitor.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/system/trace.hpp>
// #include <hotplace/sdk/io/asn.1/basic/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
// #include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
// #include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
// #include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>
// #include <hotplace/sdk/io/asn.1/basic/visitor/asn1_ast_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_der_visitor.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>

namespace hotplace {
namespace io {

asn1_der_visitor::asn1_der_visitor(binary_t* b, asn1_runtime* runtime, const asn1_value* value) : _b(b), _runtime(runtime), _value(value) {}

asn1_der_visitor::~asn1_der_visitor() {}

void asn1_der_visitor::visit(asn1_object* object) {
    if (nullptr == object) return;

    auto lambda = [this](asn1_object* item) -> void { _runtime->update_linkage(item); };
    asn1_visitor visitor(_runtime, lambda);
    visitor.visit(object);

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal,
                          [&](basic_stream& dbs) -> void { print_ast(object, dbs, asn1_ast_flag_ansicolor); });
    }
#endif

    // chain encoding
    object->represent(get_binary(), _value);
}

binary_t* asn1_der_visitor::get_binary() { return _b; }

}  // namespace io
}  // namespace hotplace
