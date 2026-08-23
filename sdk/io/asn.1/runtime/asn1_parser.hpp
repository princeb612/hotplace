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
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <hotplace/sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

/**
 * @brief   parser
 * @remarks
 *          transform : notation -> token tree -> asn1_object*
 */
class asn1_parser {
   public:
    struct asn1_token_t {
        int token;
    };
    asn1_parser();

    parser& get_parser();

    return_t parse(asn1_runtime* runtime, const char* notation);

   protected:
    void prepare();

   private:
    parser _parser;
    t_tree<asn1_token_t> _tree;
};

}  // namespace io
}  // namespace hotplace

#endif
