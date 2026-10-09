/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_template.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1TEMPLATE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_SEMANTIC_ASN1TEMPLATE__

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

/**
 * @remarks
 *          -- Parameterized Type (Template)
 *          FRAME{TypeParam, INTEGER:maxSize} ::= SEQUENCE {
 *              header  INTEGER,
 *              payload TypeParam,
 *              length  INTEGER (0..maxSize)
 *          }
 *          -- Parameterized Type (Instantiation)
 *          MyPacket ::= FRAME{ OCTET STRING, 1024 }
 *
 *          HEADER{INTEGER:defaultPriority} ::= SEQUENCE {
 *              version   INTEGER,
 *              priority  INTEGER DEFAULT defaultPriority
 *          }
 *          ControlHeader ::= HEADER{ 5 }
 *
 *          TLV-BUFFER{TypeParam, INTEGER:maxLen} ::= SEQUENCE {
 *              allocatedLength INTEGER (0..65535),
 *              maxCapacity     INTEGER (maxLen),
 *              payload         TypeParam
 *          }
 *          MyBuffer ::= TLV-BUFFER{ OCTET STRING, 2048 }
 *
 *          COMMAND-ENVELOPE{TypeParam, INTEGER:msgId} ::= SEQUENCE {
 *              commandId INTEGER (msgId),
 *              timestamp GeneralizedTime,
 *              data      TypeParam
 *          }
 *          ReadUserCmd ::= COMMAND-ENVELOPE{ UserReadRequest, 101 }
 *
 *          // sketch
 *          auto frame_template = asn1_template::define(
 *              "FRAME",
 *              {
 *                  asn1_param_type{"TypeParam"},
 *                  asn1_param_value{"maxSize", asn1_entity_integer}
 *              },
 *              new asn1_sequence(
 *                  new asn1_integer("header"),
 *                  asn1_param_type::generate("payload", "TypeParam"),
 *                  asn1_builder::build(asn1_entity_integer, "length",
 *                      [](asn1_object* builtin) -> void {
 *                          auto max_val = asn1_param_value::refer<int64>("maxSize");
 *                          builtin->get_constraints().add(new asn1_constraint_range_i(0, max_val));
 *                      }
 *                  )
 *              )
 *          );
 *          auto mypacket1 = frame_template->specialize("MyPacket", {asn1_entity_octetstring, 1024});
 *
 *          asn1_object* custom_type = asn1_referenced_type::define("CustomHeaderType", asn1_entity_visiblestring);
 *          auto mypacket2 = frame_template->specialize("MyPacket2", {custom_type, 2048});
 *          custom_type->release();
 */

enum class asn1_param_family_t {
    type,
    value,
};
enum class asn1_param_source_t {
    builtin,
    reference,
};

class asn1_deferred : public asn1_object {
   public:
    asn1_deferred();
};

class asn1_param_t {
   public:
    asn1_param_t(asn1_entity_t t);
    asn1_param_t(asn1_object* obj);
    asn1_param_t(int64 value);
    asn1_param_t(const std::string& value);
    virtual ~asn1_param_t();

    asn1_param_t(const asn1_param_t& other);
    asn1_param_t(asn1_param_t&& other);

    asn1_param_t& operator=(const asn1_param_t& other);
    asn1_param_t& operator=(asn1_param_t&& other);

   protected:
    asn1_param_t();

   private:
    asn1_param_family_t _family;
    asn1_param_source_t _source;
};

class asn1_param_type : public asn1_param_t {
   public:
    asn1_param_type();

    static asn1_deferred* generate(const std::string& name, const std::string& param);
};

class asn1_param_value : public asn1_param_t {
   public:
    asn1_param_value();

    template <typename T>
    static T refer(const std::string& param) {
        // ...
        return T();
    }
};

class asn1_template {
   public:
    asn1_template();
    ~asn1_template();

    static asn1_template* define(const char* name, const std::vector<asn1_param_t>& parameters, asn1_object* object);

   private:
    std::vector<asn1_param_t> parameters;
};

}  // namespace io
}  // namespace hotplace

#endif
