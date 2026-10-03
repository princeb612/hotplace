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
class asn1_publisher;
class asn1_runtime;
class asn1_runtime_context;

enum class asn1_build_t {
    unknown,
    module_definition,  // module definition (.asn1)
    assignments,        // no module definition and assignment
    non_assignment,     // non-assignment (SimpleType, Tag, etc.)
};

struct asn1_build_resultset {
    asn1_build_t type{asn1_build_t::unknown};
    std::vector<std::string> module_names;
    asn1_object* object{nullptr};

    asn1_build_resultset() = default;
    asn1_build_resultset(const asn1_build_resultset&) = delete;
    asn1_build_resultset& operator=(const asn1_build_resultset&) = delete;
    ~asn1_build_resultset() { clear(); }
    // remove all asn1_runtime from asn1_runtime_context
    void clear();
    // do not remove asn1_runtime
    void release_name(const std::string& name);
    void moveto(const std::string& prefix, const std::string& target);
};

return_t print_ast(const asn1_object* object, basic_stream& bs, uint32 flags = asn1_ast_flag_ansicolor);
return_t print_ast(const asn1_runtime* object, basic_stream& bs, uint32 flags = asn1_ast_flag_ansicolor);

}  // namespace io
}  // namespace hotplace

#endif
