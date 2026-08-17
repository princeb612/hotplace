/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_tag.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tag.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime_context.hpp>

namespace hotplace {
namespace io {

asn1_tag::asn1_tag(uint8 ctype, uint64 cnumber, uint8 tmode) : asn1_object(asn1_entity_tag, "", nullptr), _class_type(ctype), _class_number(cnumber), _tag_mode(tmode) {}

asn1_tag::asn1_tag(const asn1_tag& other) : asn1_object(other), _class_type(other._class_type), _class_number(other._class_number), _tag_mode(other._tag_mode) {}

asn1_tag::~asn1_tag() {}

asn1_tag* asn1_tag::clone() { return new asn1_tag(*this); }

asn1_tag* asn1_tag::addref() {
    asn1_object::addref();
    return this;
}

uint8 asn1_tag::get_class() const { return _class_type; }

uint64 asn1_tag::get_class_number() const { return _class_number; }

uint8 asn1_tag::get_tag_type() const { return _tag_mode; }

bool asn1_tag::is_implicit() const {
    auto mode = _tag_mode;
    if (mode == asn1_automatic) {
        auto contexts = asn1_runtime_context::get_instance();
        auto runtime = contexts->current();
        mode = runtime->runas_automatic();
    }
    return (asn1_implicit == mode);
}

bool asn1_tag::is_explicit() const {
    auto mode = _tag_mode;
    if (mode == asn1_automatic) {
        auto contexts = asn1_runtime_context::get_instance();
        auto runtime = contexts->current();
        mode = runtime->runas_automatic();
    }
    return (asn1_explicit == mode);
}

void asn1_tag::represent(stream_t* s, const asn1_value* value) const {
    if (s) {
        if (get_class() & asn1_class_mask) {
            auto resource = asn1_resource::get_instance();

            s->printf("[");
            if (false == asn1_is_context(get_class())) {
                s->printf("%s", resource->get_class_name(get_class()).c_str());
                s->printf(" ");
            }

            s->printf("%i", get_class_number());

            s->printf("]");

            if (get_tag_type()) {
                s->printf(" %s", resource->get_tagtype_name(get_tag_type()).c_str());
            }
        }
    }
}

bool asn1_tag::represent(binary_t* b, const asn1_value* value, uint16 flags) const {
    uint8 ident = get_class() | get_ident();
    if (b && (false == is_suppressed())) {
        asn1_encode::write_identifier(*b, ident, get_class_number());
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
