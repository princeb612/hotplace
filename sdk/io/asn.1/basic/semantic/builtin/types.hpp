/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_BUILTIN_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_BUILTIN_TYPES__

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_builtin_type.hpp>

namespace hotplace {
namespace io {

class asn1_boolean : public asn1_builtin_type {
   public:
    asn1_boolean() : asn1_builtin_type(asn1_entity_boolean) {}
    asn1_boolean(const std::string& name) : asn1_builtin_type(name, asn1_entity_boolean) {}
    asn1_boolean(const std::string& name, bool value) : asn1_builtin_type(name, asn1_entity_boolean, value) {}
    virtual ~asn1_boolean() = default;
};

class asn1_octstring : public asn1_builtin_type {
   public:
    asn1_octstring() : asn1_builtin_type(asn1_entity_octstring) {}
    asn1_octstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_octstring) {}
    asn1_octstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_octstring, value) {}
    virtual ~asn1_octstring() = default;
};

class asn1_null : public asn1_builtin_type {
   public:
    asn1_null() : asn1_builtin_type(asn1_entity_null) {}
    asn1_null(const std::string& name) : asn1_builtin_type(name, asn1_entity_null) {}
    virtual ~asn1_null() = default;
};

class asn1_oid : public asn1_builtin_type {
   public:
    asn1_oid() : asn1_builtin_type(asn1_entity_oid) {}
    asn1_oid(const std::string& name) : asn1_builtin_type(name, asn1_entity_oid) {}
    asn1_oid(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_oid, value) {}
    virtual ~asn1_oid() = default;
};

// asn1_entity_objdesc
// asn1_entity_extern

class asn1_real : public asn1_builtin_type {
   public:
    asn1_real() : asn1_builtin_type(asn1_entity_real) {}
    asn1_real(const std::string& name) : asn1_builtin_type(name, asn1_entity_real) {}
    asn1_real(const std::string& name, const float& value) : asn1_builtin_type(name, asn1_entity_real, value) {}
    asn1_real(const std::string& name, const double& value) : asn1_builtin_type(name, asn1_entity_real, value) {}
    virtual ~asn1_real() = default;
};

// asn1_entity_embedpdv

class asn1_utf8string : public asn1_builtin_type {
   public:
    asn1_utf8string() : asn1_builtin_type(asn1_entity_utf8string) {}
    asn1_utf8string(const std::string& name) : asn1_builtin_type(name, asn1_entity_utf8string) {}
    asn1_utf8string(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_utf8string, value) {}
    virtual ~asn1_utf8string() = default;
};

class asn1_reloid : public asn1_builtin_type {
   public:
    asn1_reloid() : asn1_builtin_type(asn1_entity_reloid) {}
    asn1_reloid(const std::string& name) : asn1_builtin_type(name, asn1_entity_reloid) {}
    asn1_reloid(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_reloid, value) {}
    virtual ~asn1_reloid() = default;
};

class asn1_numstring : public asn1_builtin_type {
   public:
    asn1_numstring() : asn1_builtin_type(asn1_entity_numstring) {}
    asn1_numstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_numstring) {}
    asn1_numstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_numstring, value) {}
    virtual ~asn1_numstring() = default;
};

class asn1_printstring : public asn1_builtin_type {
   public:
    asn1_printstring() : asn1_builtin_type(asn1_entity_printstring) {}
    asn1_printstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_printstring) {}
    asn1_printstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_printstring, value) {}
    virtual ~asn1_printstring() = default;
};

class asn1_teletexstring : public asn1_builtin_type {
   public:
    asn1_teletexstring() : asn1_builtin_type(asn1_entity_teletexstring) {}
    asn1_teletexstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_teletexstring) {}
    asn1_teletexstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_teletexstring, value) {}
    virtual ~asn1_teletexstring() = default;
};

class asn1_videotexstring : public asn1_builtin_type {
   public:
    asn1_videotexstring() : asn1_builtin_type(asn1_entity_videotexstring) {}
    asn1_videotexstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_videotexstring) {}
    asn1_videotexstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_videotexstring, value) {}
    virtual ~asn1_videotexstring() = default;
};

class asn1_ia5string : public asn1_builtin_type {
   public:
    asn1_ia5string() : asn1_builtin_type(asn1_entity_ia5string) {}
    asn1_ia5string(const std::string& name) : asn1_builtin_type(name, asn1_entity_ia5string) {}
    asn1_ia5string(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_ia5string, value) {}
    virtual ~asn1_ia5string() = default;
};

class asn1_utctime : public asn1_builtin_type {
   public:
    asn1_utctime() : asn1_builtin_type(asn1_entity_utctime) {}
    asn1_utctime(const std::string& name) : asn1_builtin_type(name, asn1_entity_utctime) {}
    asn1_utctime(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_utctime, value) {}
    virtual ~asn1_utctime() = default;
};

class asn1_generalizedtime : public asn1_builtin_type {
   public:
    asn1_generalizedtime() : asn1_builtin_type(asn1_entity_generalizedtime) {}
    asn1_generalizedtime(const std::string& name) : asn1_builtin_type(name, asn1_entity_generalizedtime) {}
    asn1_generalizedtime(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_generalizedtime, value) {}
    virtual ~asn1_generalizedtime() = default;
};

class asn1_graphicstring : public asn1_builtin_type {
   public:
    asn1_graphicstring() : asn1_builtin_type(asn1_entity_graphicstring) {}
    asn1_graphicstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_graphicstring) {}
    asn1_graphicstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_graphicstring, value) {}
    virtual ~asn1_graphicstring() = default;
};

class asn1_visiblestring : public asn1_builtin_type {
   public:
    asn1_visiblestring() : asn1_builtin_type(asn1_entity_visiblestring) {}
    asn1_visiblestring(const std::string& name) : asn1_builtin_type(name, asn1_entity_visiblestring) {}
    asn1_visiblestring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_visiblestring, value) {}
    virtual ~asn1_visiblestring() = default;
};

class asn1_generalstring : public asn1_builtin_type {
   public:
    asn1_generalstring() : asn1_builtin_type(asn1_entity_generalstring) {}
    asn1_generalstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_generalstring) {}
    asn1_generalstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_generalstring, value) {}
    virtual ~asn1_generalstring() = default;
};

class asn1_universalstring : public asn1_builtin_type {
   public:
    asn1_universalstring() : asn1_builtin_type(asn1_entity_universalstring) {}
    asn1_universalstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_universalstring) {}
    asn1_universalstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_universalstring, value) {}
    virtual ~asn1_universalstring() = default;
};

class asn1_cstring : public asn1_builtin_type {
   public:
    asn1_cstring() : asn1_builtin_type(asn1_entity_cstring) {}
    asn1_cstring(const std::string& name) : asn1_builtin_type(name, asn1_entity_cstring) {}
    asn1_cstring(const std::string& name, const std::string& value) : asn1_builtin_type(name, asn1_entity_cstring, value) {}
    virtual ~asn1_cstring() = default;
};

// asn1_entity_bmpstring
// asn1_entity_date
// asn1_entity_timeofday
// asn1_entity_datetime
// asn1_entity_duration

}  // namespace io
}  // namespace hotplace

#endif
