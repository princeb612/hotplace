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
 * As the lexical analyzer and context were shifted to runtime, this adopted a lightweight proxy interface structure.
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1PARSER__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1PARSER__

#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
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
    asn1_parser();

    return_t parse(asn1_runtime* runtime, const char* notation, parse_tree* pt = nullptr) const;
};

}  // namespace io
}  // namespace hotplace

#endif
