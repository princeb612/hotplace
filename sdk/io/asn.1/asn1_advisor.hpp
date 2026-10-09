/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_advisor.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1ADVISOR__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1ADVISOR__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/asn.1/runtime/types.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>
#include <hotplace/sdk/io/parser/glr_parser.hpp>
#include <hotplace/sdk/io/parser/lalr1_parser.hpp>
#include <hotplace/sdk/io/parser/types.hpp>
#include <map>
#include <set>
#include <vector>

namespace hotplace {
namespace io {

struct asn1_entity_resource_t {
    asn1_entity_t type;
    const char* token;
    asn1_perm_t permission;
};

extern const struct asn1_entity_resource_t resource_asn1_entities[];
extern const size_t sizeof_resource_asn1_entities;

class asn1_advisor {
   public:
    static asn1_advisor* get_instance();

    std::string get_component_entity_name(asn1_entity_t entity) const;
    std::string get_entity_name(uint8 ident, asn1_entity_t entity) const;
    asn1_entity_t get_entity(const std::string& name) const;
    asn1_perm_t get_perm(asn1_entity_t entity) const;
    std::string get_class_name(int c) const;
    uint8 get_class(const std::string& name) const;
    /**
     * @brief   IMPLICIT/EXPLICIT/DEFAULT/OPTIONAL
     */
    std::string nameof_mode(uint16 t, bool ismodule = false) const;
    uint8 valueof_mode(const std::string& name) const;

    /**
     * publisher
     */
    asn1_publisher* get_publisher();
    /**
     * @brief   parser
     * @remarks
     *          if LALR(1)
     *              if imported then return get_notation_parser_by_import
     *              else return get_notation_parser_by_build
     *          elif GLR
     *              if imported then return get_parser_by_import
     *              else return get_parser_by_build
     *          else return return get_parser_by_build
     */
    parser_t& get_parser(parser_type_t type, bool imported);
    /**
     * LALR(1) vs GLR grammar
     *  LALR(1) CFG for ASN.1 Notation
     *  GLR     CFG for ASN.1 Notation, Module, Parameterized, Information Object Class
     */
    parser_t& get_notation_parser_by_build();
    parser_t& get_notation_parser_by_import();
    parser_t& get_parser_by_build();
    parser_t& get_parser_by_import();

   protected:
    asn1_advisor();
    void load_resource();
    void doload_resource();
    return_t prepare_lalr1_notation_parser(parser_t& parser);
    return_t import_lalr1_notation_parser(lalr1_parser& parser);
    return_t prepare_glr_parser(parser_t& parser);
    return_t import_glr_parser(glr_parser& parser);

   private:
    static asn1_advisor _instance;

    critical_section _lock;
    std::map<asn1_entity_t, std::string> _type_id;
    std::map<std::string, asn1_entity_t> _type_rid;
    std::map<asn1_entity_t, asn1_perm_t> _type_perm;
    std::map<uint16, std::string> _class_id;
    std::map<std::string, int> _class_rid;
    std::map<uint16, std::string> _mode_id;
    std::map<std::string, int> _mode_rid;

    asn1_publisher _publisher;
    lalr1_parser _lalr1_parser_by_build;
    lalr1_parser _lalr1_parser_by_import;
    glr_parser _glr_parser_by_build;
    glr_parser _glr_parser_by_import;
};

}  // namespace io
}  // namespace hotplace

#endif
