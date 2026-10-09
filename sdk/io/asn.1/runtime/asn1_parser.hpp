/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parser.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * Loading symbols for the lexical analyzer and building the LALR ACTION and GOTO tables were heavy tasks.
 * Although the initial design was a simple singleton, it was modified to pre-build and load the ACTION and GOTO tables.
 * As the lexical analyzer and context were shifted to module, this adopted a lightweight proxy interface structure.
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1PARSER__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1PARSER__

#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/asn.1/asn1_advisor.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <hotplace/sdk/io/parser/lalr1_parser.hpp>
#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   parser
 * @remarks
 *          transform : notation -> token tree -> asn1_object*
 *
 */
class asn1_parser {
   public:
    asn1_parser(parser_type_t type = parser_type_t::glr, bool imported = true);

    /**
     * @brief   parse
     * @param   const char* notation [in]
     * @param   size_t size [in]
     * @param   asn1_build_resultset& result [out]
     * @remarks
     *          sketch
     *          notation -> tokens -> parse tree -> result
     */
    return_t parse(const char* notation, asn1_build_resultset& result);
    return_t parse(const char* notation, size_t size, asn1_build_resultset& result);
    /**
     * @param   const char* notation [in]
     * @param   size_t size [in]
     * @param   parse_tree* pt [out]
     */
    return_t parse(const char* notation, parse_tree* pt);
    return_t parse(const char* notation, size_t size, parse_tree* pt);

    /**
     * @param   const char* notation [in]
     * @param   size_t size [in]
     * @param   std::vector<parser_token>& tokens [out]
     */
    return_t to_tokens(const char* notation, size_t size, std::vector<parser_token>& tokens);
    /**
     * @param   const std::vector<parser_token>& tokens [in]
     * @param   parse_tree* pt [out]
     */
    return_t to_parsetree(const std::vector<parser_token>& tokens, parse_tree* pt);
    /**
     * @param   parse_tree* pt [in]
     * @param   asn1_build_resultset& result [out]
     */
    return_t to_result(parse_tree* pt, asn1_build_resultset& result);

    lexical_analyzer& get_lexer();
    parser_t& get_parser();

   protected:
    void load();

   private:
    mutable critical_section _lock;
    lexical_context _lexcontext;
    lexical_analyzer _lex;
    int _ready;
    parser_type_t _type;
    bool _imported;
};

}  // namespace io
}  // namespace hotplace

#endif
