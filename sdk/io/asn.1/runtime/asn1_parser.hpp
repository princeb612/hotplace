/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parser.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1PARSER__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1PARSER__

#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <hotplace/sdk/io/parser/lalr_parser.hpp>
#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   parser
 * @remarks
 *          transform : notation -> token tree -> asn1_object*
 */
class asn1_parser {
   public:
    static asn1_parser* get_instance();

    struct asn1_token_t {
        int token;
    };

    // TODO new asn1_object at runtime ...
    return_t parse(asn1_runtime* runtime, const char* notation, parse_tree* pt = nullptr);

    lexical_analyzer& get_lex();
    lalr_parser& get_lalr();

   protected:
    asn1_parser();

    void load();
    bool prepare();

   private:
    static asn1_parser _instance;

    critical_section _lock;
    lexical_analyzer _lex;
    lalr_parser _lalr;
    int _flag;
};

}  // namespace io
}  // namespace hotplace

#endif
