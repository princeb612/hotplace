/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_paramvalue.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp>

namespace hotplace {
namespace io {

asn1_paramvalue::asn1_paramvalue(asn1_entity_t e) : type(asn1_paramvalue_t::entity), entity(e) {}

asn1_paramvalue::asn1_paramvalue(const char* s) : type(asn1_paramvalue_t::literal) {
    if (s) name = s;
}

asn1_paramvalue::asn1_paramvalue(asn1_object* o) : type(asn1_paramvalue_t::object), object(o) {}

asn1_paramvalue::asn1_paramvalue(const variant& v) : type(asn1_paramvalue_t::value), value(v) {}

asn1_paramvalue::asn1_paramvalue(variant&& v) : type(asn1_paramvalue_t::value), value(std::move(v)) {}

asn1_paramvalue::asn1_paramvalue(const asn1_paramvalue& other) { *this = other; }

asn1_paramvalue::asn1_paramvalue(asn1_paramvalue&& other) { *this = std::move(other); }

asn1_paramvalue& asn1_paramvalue::operator=(const asn1_paramvalue& other) {
    type = other.type;
    name = other.name;
    object = other.object;
    value = other.value;
    return *this;
}

asn1_paramvalue& asn1_paramvalue::operator=(asn1_paramvalue&& other) {
    std::swap(type, other.type);
    name = std::move(other.name);
    std::swap(object, other.object);
    value = std::move(other.value);
    return *this;
}

void asn1_paramvalue::represent(stream_t* s, const asn1_value*) const {
    switch (type) {
        case asn1_paramvalue_t::entity: {
        } break;
        case asn1_paramvalue_t::literal: {
            s->printf("%s", name.c_str());
        } break;
        case asn1_paramvalue_t::object: {
        } break;
        case asn1_paramvalue_t::value: {
            vtprintf(s, this->value, vtprintf_style_t::vtprintf_style_asn1);
        } break;
        default: {
        } break;
    }
}

}  // namespace io
}  // namespace hotplace
