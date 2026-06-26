/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_integer.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/stream/vtprintf.hpp>
#include <hotplace/sdk/io/asn.1/asn1_encode.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/asn1_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/detail/asn1_integer.hpp>

namespace hotplace {
namespace io {

asn1_integer::asn1_integer() : asn1_integer("") {}

asn1_integer::asn1_integer(const std::string& name) : asn1_builtin_type(name, asn1_entity_integer) {}

asn1_integer::asn1_integer(const std::initializer_list<std::pair<std::string, int>>& items) : asn1_integer("", items) {}

asn1_integer::asn1_integer(const std::string& name, const std::initializer_list<std::pair<std::string, int>>& items) : asn1_builtin_type("", asn1_entity_integer) {
    add(items);
}

asn1_integer::~asn1_integer() {}

asn1_integer* asn1_integer::clone() { return new asn1_integer(*this); }

asn1_integer* asn1_integer::addref() {
    asn1_builtin_type::addref();
    return this;
}

asn1_integer& asn1_integer::operator<<(const std::initializer_list<std::pair<std::string, int>>& items) { return add(items); }

asn1_integer& asn1_integer::add(const std::initializer_list<std::pair<std::string, int>>& items) {
    for (const auto& item : items) {
        _nnl.emplace(item.first, item.second);
        _reverse.emplace(item.second, item.first);
    }
    return *this;
}

void asn1_integer::represent(uint32 depth, stream_t* s, asn1_value* value) {
    asn1_builtin_type::represent(depth, s, value);

    if (false == _reverse.empty()) {
        s->printf(" {");
        if (false == _reverse.empty()) {
            auto iter = _reverse.begin();
            s->printf("%s(%i)", iter->second.c_str(), iter->first);
            ++iter;
            while (_reverse.end() != iter) {
                s->printf(", %s(%i)", iter->second.c_str(), iter->first);
                ++iter;
            }
        }
        s->printf("}");
    }
}

bool asn1_integer::represent(uint32 depth, binary_t* b, asn1_value* value, uint16 flags) {
    debug_print(depth);

    if (value) {
        auto name = resolve_name();
        debug_print(depth, name);

        auto snapshot = b->size();

        asn1_encode::write_ident_octets(*b, this);
        auto pos = b->size();
        auto test = value->encode_namedlist(*b, this, name, _nnl);
        asn1_encode::t_asn1_length_octets<size_t>(*b, b->size() - pos, pos);

        if (false == test) {
            b->resize(snapshot);  // rollback
        }
    }

    return true;
}

}  // namespace io
}  // namespace hotplace
