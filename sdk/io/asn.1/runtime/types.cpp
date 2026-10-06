/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime_context.hpp>
#include <hotplace/sdk/io/asn.1/runtime/types.hpp>

namespace hotplace {
namespace io {

void asn1_build_resultset::clear() {
    type = asn1_build_t::unknown;
    auto rtcontext = asn1_runtime_context::get_instance();
    for (const auto& name : module_names) {
        rtcontext->remove(name);
    }
    module_names.clear();
    if (object) {
        object->release();
        object = nullptr;
    }
}

void asn1_build_resultset::release_name(const std::string& name) {
    auto it = std::find(module_names.begin(), module_names.end(), name);
    if (it != module_names.end()) {
        module_names.erase(it);
    }
}

}  // namespace io
}  // namespace hotplace
