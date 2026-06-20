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
#include <hotplace/sdk/io/asn.1/asn1_builtin_type.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_referenced_type.hpp>
#include <hotplace/sdk/io/asn.1/asn1_tagged_type.hpp>

namespace hotplace {
namespace io {

asn1_tagged_type::asn1_tagged_type(int ctype, int cnumber, int tmode, asn1_entity_t entity)
    : asn1_type(asn1_entity_tagged_type, "", new asn1_builtin_type(entity), new asn1_tag(ctype, cnumber, tmode)) {}

asn1_tagged_type::asn1_tagged_type(int ctype, int cnumber, int tmode, asn1_object* object)
    : asn1_type(asn1_entity_tagged_type, "", object, new asn1_tag(ctype, cnumber, tmode)) {}

asn1_tagged_type::asn1_tagged_type(asn1_tag* tag, asn1_entity_t entity) : asn1_type(asn1_entity_tagged_type, "", new asn1_builtin_type(entity)) {}

asn1_tagged_type::asn1_tagged_type(asn1_tag* tag, asn1_object* object) : asn1_type(asn1_entity_tagged_type, "", object, tag) {}

asn1_tagged_type::asn1_tagged_type(const std::string& name, int ctype, int cnumber, int tmode, asn1_entity_t entity)
    : asn1_type(asn1_entity_tagged_type, name, new asn1_builtin_type(entity), new asn1_tag(ctype, cnumber, tmode)) {}

asn1_tagged_type::asn1_tagged_type(const std::string& name, int ctype, int cnumber, int tmode, asn1_object* object)
    : asn1_type(asn1_entity_tagged_type, name, object, new asn1_tag(ctype, cnumber, tmode)) {}

asn1_tagged_type::asn1_tagged_type(const std::string& name, asn1_tag* tag, asn1_entity_t entity)
    : asn1_type(asn1_entity_tagged_type, name, new asn1_builtin_type(entity)) {}

asn1_tagged_type::asn1_tagged_type(const std::string& name, asn1_tag* tag, asn1_object* object) : asn1_type(asn1_entity_tagged_type, name, object, tag) {}

asn1_tagged_type::~asn1_tagged_type() {}

asn1_tagged_type* asn1_tagged_type::clone() { return new asn1_tagged_type(*this); }

asn1_tagged_type* asn1_tagged_type::addref() {
    asn1_object::addref();
    return this;
}

void asn1_tagged_type::represent(uint32 depth, stream_t* s, asn1_value* value) {
    if (false == get_name().empty()) s->printf("%s ", get_name().c_str());

    get_tag()->represent(depth + 1, s, value);

    auto obj = get_object();
    if (obj) {
        s->printf(" ");
        obj->represent(depth + 1, s, value);
    }
}

bool asn1_tagged_type::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    auto tag = get_tag();
    auto obj = get_object();

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
        trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
            dbs.fill(depth << 1, ' ');
            dbs.println("ASN.1 tagged type");
            if (false == get_name().empty()) {
                dbs.fill(depth << 1, ' ');
                dbs.println("- %s", get_name().c_str());
            }
        });
    }
#endif

    bool ret = true;
    size_t snapshot = b->size();

    auto is_implicit = tag->is_implicit();
    if (is_implicit) {
        obj->suppress();
    } else {
        obj->unsuppress();
    }

    tag->represent(depth + 1, b, value);

    size_t pos = b->size();

    ret = obj->represent(depth + 1, b, value, flags);

    if (false == is_suppressed()) {
        asn1_encode::t_asn1_length_octets<size_t>(*b, b->size() - pos, pos);
    }

    if ((asn1_visitor_choice == flags) && (false == ret)) {
        b->resize(snapshot);  // rollback
    }

    return ret;
}

asn1_tag* asn1_tagged_type::get_tag() const { return (asn1_tag*)asn1_object::get_tag(); }

}  // namespace io
}  // namespace hotplace
