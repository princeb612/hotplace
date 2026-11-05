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

class HOTPLACE_IO_API asn1_boolean : public asn1_builtin_type {
   public:
    asn1_boolean();
    asn1_boolean(const std::string& name);
    asn1_boolean(const std::string& name, bool value);
    virtual ~asn1_boolean();
};

class HOTPLACE_IO_API asn1_octstring : public asn1_builtin_type {
   public:
    asn1_octstring();
    asn1_octstring(const std::string& name);
    asn1_octstring(const std::string& name, const std::string& value);
    virtual ~asn1_octstring();
};

class HOTPLACE_IO_API asn1_null : public asn1_builtin_type {
   public:
    asn1_null();
    asn1_null(const std::string& name);
    virtual ~asn1_null();
};

class HOTPLACE_IO_API asn1_oid : public asn1_builtin_type {
   public:
    asn1_oid();
    asn1_oid(const std::string& name);
    asn1_oid(const std::string& name, const std::string& value);
    virtual ~asn1_oid();
};

// asn1_entity_objdesc
// asn1_entity_extern

class HOTPLACE_IO_API asn1_real : public asn1_builtin_type {
   public:
    asn1_real();
    asn1_real(const std::string& name);
    asn1_real(const std::string& name, const float& value);
    asn1_real(const std::string& name, const double& value);
    virtual ~asn1_real();
};

// asn1_entity_embedpdv

class HOTPLACE_IO_API asn1_utf8string : public asn1_builtin_type {
   public:
    asn1_utf8string();
    asn1_utf8string(const std::string& name);
    asn1_utf8string(const std::string& name, const std::string& value);
    virtual ~asn1_utf8string();
};

class HOTPLACE_IO_API asn1_reloid : public asn1_builtin_type {
   public:
    asn1_reloid();
    asn1_reloid(const std::string& name);
    asn1_reloid(const std::string& name, const std::string& value);
    virtual ~asn1_reloid();
};

class HOTPLACE_IO_API asn1_numstring : public asn1_builtin_type {
   public:
    asn1_numstring();
    asn1_numstring(const std::string& name);
    asn1_numstring(const std::string& name, const std::string& value);
    virtual ~asn1_numstring();
};

class HOTPLACE_IO_API asn1_printstring : public asn1_builtin_type {
   public:
    asn1_printstring();
    asn1_printstring(const std::string& name);
    asn1_printstring(const std::string& name, const std::string& value);
    virtual ~asn1_printstring();
};

class HOTPLACE_IO_API asn1_teletexstring : public asn1_builtin_type {
   public:
    asn1_teletexstring();
    asn1_teletexstring(const std::string& name);
    asn1_teletexstring(const std::string& name, const std::string& value);
    virtual ~asn1_teletexstring();
};

class HOTPLACE_IO_API asn1_videotexstring : public asn1_builtin_type {
   public:
    asn1_videotexstring();
    asn1_videotexstring(const std::string& name);
    asn1_videotexstring(const std::string& name, const std::string& value);
    virtual ~asn1_videotexstring();
};

class HOTPLACE_IO_API asn1_ia5string : public asn1_builtin_type {
   public:
    asn1_ia5string();
    asn1_ia5string(const std::string& name);
    asn1_ia5string(const std::string& name, const std::string& value);
    virtual ~asn1_ia5string();
};

class HOTPLACE_IO_API asn1_utctime : public asn1_builtin_type {
   public:
    asn1_utctime();
    asn1_utctime(const std::string& name);
    asn1_utctime(const std::string& name, const std::string& value);
    virtual ~asn1_utctime();
};

class HOTPLACE_IO_API asn1_generalizedtime : public asn1_builtin_type {
   public:
    asn1_generalizedtime();
    asn1_generalizedtime(const std::string& name);
    asn1_generalizedtime(const std::string& name, const std::string& value);
    virtual ~asn1_generalizedtime();
};

class HOTPLACE_IO_API asn1_graphicstring : public asn1_builtin_type {
   public:
    asn1_graphicstring();
    asn1_graphicstring(const std::string& name);
    asn1_graphicstring(const std::string& name, const std::string& value);
    virtual ~asn1_graphicstring();
};

class HOTPLACE_IO_API asn1_visiblestring : public asn1_builtin_type {
   public:
    asn1_visiblestring();
    asn1_visiblestring(const std::string& name);
    asn1_visiblestring(const std::string& name, const std::string& value);
    virtual ~asn1_visiblestring();
};

class HOTPLACE_IO_API asn1_generalstring : public asn1_builtin_type {
   public:
    asn1_generalstring();
    asn1_generalstring(const std::string& name);
    asn1_generalstring(const std::string& name, const std::string& value);
    virtual ~asn1_generalstring();
};

class HOTPLACE_IO_API asn1_universalstring : public asn1_builtin_type {
   public:
    asn1_universalstring();
    asn1_universalstring(const std::string& name);
    asn1_universalstring(const std::string& name, const std::string& value);
    virtual ~asn1_universalstring();
};

class HOTPLACE_IO_API asn1_cstring : public asn1_builtin_type {
   public:
    asn1_cstring();
    asn1_cstring(const std::string& name);
    asn1_cstring(const std::string& name, const std::string& value);
    virtual ~asn1_cstring();
};

// asn1_entity_bmpstring
// asn1_entity_date
// asn1_entity_timeofday
// asn1_entity_datetime
// asn1_entity_duration

}  // namespace io
}  // namespace hotplace

#endif
