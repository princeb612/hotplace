/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_resource.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1RESOURCE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_ASN1RESOURCE__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>
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

class asn1_resource {
   public:
    static asn1_resource* get_instance();

    std::string get_component_entity_name(asn1_entity_t entity) const;
    std::string get_entity_name(uint8 ident, asn1_entity_t entity) const;
    asn1_entity_t get_entity(const std::string& name) const;
    asn1_perm_t get_perm(asn1_entity_t entity) const;
    std::string get_class_name(int c) const;
    uint8 get_class(const std::string& name) const;
    /**
     * @brief   IMPLICIT/EXPLICIT/DEFAULT/OPTIONAL
     */
    std::string nameof_mode(uint16 t) const;
    uint8 valueof_mode(const std::string& name) const;

   protected:
    asn1_resource();
    void load_resource();
    void doload_resource();

   private:
    static asn1_resource _instance;

    critical_section _lock;
    std::map<asn1_entity_t, std::string> _type_id;
    std::map<std::string, asn1_entity_t> _type_rid;
    std::map<asn1_entity_t, asn1_perm_t> _type_perm;
    std::map<int, std::string> _class_id;
    std::map<std::string, int> _class_rid;
    std::map<int, std::string> _mode_id;
    std::map<std::string, int> _mode_rid;
};

/**
 * LALR(1) vs GLR grammar
 *  LALR(1) CFG for ASN.1 Notation
 *  GLR     CFG for ASN.1 Notation, Module, Parameterized, Information Object Class
 */
parser_t& get_lalr1_parser_asn1_notation_by_build();
parser_t& get_lalr1_parser_asn1_notation_by_import();
parser_t& get_glr_parser_asn1_by_build();
parser_t& get_glr_parser_asn1_by_import();

extern const std::vector<parser_production> asn1_notation_productions;
extern const std::set<std::string> asn1_notation_terminals;
extern const std::map<std::pair<uint32, std::string>, parser_action> asn1_notation_action_table;
extern const std::map<std::pair<uint32, std::string>, uint32> asn1_notation_goto_table;
extern const std::vector<parser_production> asn1_allin1_productions;
extern const std::multimap<std::pair<uint32, std::string>, parser_action> asn1_allin1_action_table;
extern const std::map<std::pair<uint32, std::string>, uint32> asn1_allin1_goto_table;
extern const std::set<std::string> asn1_allin1_terminals;

}  // namespace io
}  // namespace hotplace

#endif
