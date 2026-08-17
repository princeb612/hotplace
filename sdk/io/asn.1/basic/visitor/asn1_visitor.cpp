/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_visitor.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/basic/visitor/asn1_visitor.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>

namespace hotplace {
namespace io {

asn1_visitor::asn1_visitor(asn1_runtime* runtime, std::function<void(asn1_object*)> func) : _runtime(runtime), _func(func) {}

void asn1_visitor::visit(asn1_object* object) {
    if (nullptr == object) return;
    if (_func) _func(object);

    auto entity = object->get_component_entity();
    switch (entity) {
        case asn1_entity_tagged_type: {
            visit(object->get_tag());
            visit(object->get_object());
        } break;
        case asn1_entity_referenced_type: {
            auto ref = (asn1_referenced_type*)object;
            if (ref->is_definition())
                visit(object->get_object());
            else {
                if (_runtime) {
                    auto refobj = _runtime->get(ref->get_reference());
                    if (refobj) visit(refobj);
                }
            }
        } break;
        case asn1_entity_sequence:
        case asn1_entity_set:
        case asn1_entity_choice: {
            auto cont = (asn1_container*)object;
            cont->for_each([&](asn1_object* item) -> bool {
                visit(item);
                return true;
            });
        } break;
        case asn1_entity_sequence_of:
        case asn1_entity_set_of: {
            auto obj = object->get_object();
            if (obj) visit(obj);
        } break;
        default: {
        } break;
    }
}

}  // namespace io
}  // namespace hotplace
