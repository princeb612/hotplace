/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_tagged_type.cpp
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
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp>

namespace hotplace {
namespace io {

asn1_tagged_type::asn1_tagged_type(int ctype, int cnumber, int tmode, asn1_entity_t entity)
    : asn1_tagged_type("", new asn1_tag(ctype, cnumber, tmode), new asn1_builtin_type(entity)) {}

asn1_tagged_type::asn1_tagged_type(int ctype, int cnumber, int tmode, asn1_object* object) : asn1_tagged_type("", new asn1_tag(ctype, cnumber, tmode), object) {}

asn1_tagged_type::asn1_tagged_type(asn1_tag* tag, asn1_entity_t entity) : asn1_tagged_type("", tag, new asn1_builtin_type(entity)) {}

asn1_tagged_type::asn1_tagged_type(asn1_tag* tag, asn1_object* object) : asn1_tagged_type("", tag, object) {}

asn1_tagged_type::asn1_tagged_type(const std::string& name, int ctype, int cnumber, int tmode, asn1_entity_t entity)
    : asn1_tagged_type(name, new asn1_tag(ctype, cnumber, tmode), new asn1_builtin_type(entity)) {}

asn1_tagged_type::asn1_tagged_type(const std::string& name, int ctype, int cnumber, int tmode, asn1_object* object)
    : asn1_tagged_type(name, new asn1_tag(ctype, cnumber, tmode), object) {}

asn1_tagged_type::asn1_tagged_type(const std::string& name, asn1_tag* tag, asn1_entity_t entity) : asn1_tagged_type(name, tag, new asn1_builtin_type(entity)) {}

asn1_tagged_type::asn1_tagged_type(const std::string& name, asn1_tag* tag, asn1_object* object) : asn1_type(asn1_entity_tagged_type, name, object, tag) {}

asn1_tagged_type::~asn1_tagged_type() {}

asn1_tagged_type* asn1_tagged_type::clone() { return new asn1_tagged_type(*this); }

asn1_tagged_type* asn1_tagged_type::addref() {
    asn1_object::addref();
    return this;
}

asn1_tag* asn1_tagged_type::get_tag() const { return (asn1_tag*)asn1_object::get_tag(); }

void asn1_tagged_type::represent(stream_t* s, const asn1_value* value) const {
    if (false == get_name().empty()) s->printf("%s ", get_name().c_str());

    get_tag()->represent(s, value);

    auto obj = get_object();
    if (obj) {
        s->printf(" ");
        obj->represent(s, value);
    }
}

bool asn1_tagged_type::represent(binary_t* b, const asn1_value* value, uint16 flags) const {
    auto tag = get_tag();
    auto obj = get_object();
    bool ret = true;
    size_t snapshot = b->size();

    auto is_implicit = tag->is_implicit();
    if (is_implicit) {
        obj->suppress();
    } else {
        obj->unsuppress();
    }

    tag->test_and_set_constructed();  // TODO
    tag->represent(b, value);

    size_t pos = b->size();

    ret = obj->represent(b, value, flags);

    if (false == is_suppressed()) {
        asn1_encode::write_length(*b, b->size() - pos, pos);
    }

    if ((asn1_visitor_choice == flags) && (false == ret)) {
        b->resize(snapshot);  // rollback
    }

    return ret;
}

}  // namespace io
}  // namespace hotplace
