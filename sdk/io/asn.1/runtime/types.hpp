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

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_TYPES__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_TYPES__

#include <hotplace/sdk/base/nostd/tree.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>

namespace hotplace {
namespace io {

class asn1_builder;
class asn1_bytestream;
class asn1_weakly_typed;
class asn1_strongly_typed;
class asn1_parser;
class asn1_runtime;
class asn1_runtime_context;

return_t print_ast(const asn1_object* object, basic_stream& bs, uint32 flags = asn1_ast_flag_ansicolor);
return_t print_ast(const asn1_runtime* object, basic_stream& bs, uint32 flags = asn1_ast_flag_ansicolor);

}  // namespace io
}  // namespace hotplace

#endif
