/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_paramtype.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp>

namespace hotplace {
namespace io {

asn1_paramtype::asn1_paramtype(const std::string& t) : type(t) {}

asn1_paramtype::asn1_paramtype(const std::string& t, const std::string& n) : type(t), name(n) {}

asn1_paramtype::asn1_paramtype(const asn1_paramtype& other) { *this = other; }

asn1_paramtype::asn1_paramtype(asn1_paramtype&& other) { *this = std::move(other); }

asn1_paramtype& asn1_paramtype::operator=(const asn1_paramtype& other) {
    type = other.type;
    name = other.name;
    return *this;
}

asn1_paramtype& asn1_paramtype::operator=(asn1_paramtype&& other) {
    type = std::move(other.type);
    name = std::move(other.name);
    return *this;
}

bool asn1_paramtype::operator==(const asn1_paramtype& other) const { return (type == other.type) && (name == other.name); }
bool asn1_paramtype::operator<(const asn1_paramtype& other) const {
    if (type < other.type)
        return true;
    else if (type == other.type)
        return (name < other.name);
    else
        return false;
}

void asn1_paramtype::represent(stream_t* s, const asn1_value*) const {
    s->printf("%s", type.c_str());
    if (false == name.empty()) {
        s->printf(":%s", name.c_str());
    }
}

}  // namespace io
}  // namespace hotplace
