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

void asn1_build_resultset::moveto(const std::string& prefix, const std::string& target) {
    auto rtcontext = asn1_runtime_context::get_instance();
    auto targetrt = rtcontext->get(target);
    if (targetrt) {
        std::vector<std::string> temp_names;
        for (const auto& item : module_names) {
            if (0 == item.compare(0, prefix.size(), prefix)) {
                auto runtime = rtcontext->get(item);
                runtime->for_each([targetrt](asn1_object* obj) -> void {
                    obj->addref();
                    targetrt->add(obj);
                });
                rtcontext->remove(item);
            } else {
                temp_names.push_back(item);
            }
        }
        module_names = std::move(temp_names);
    }
}

}  // namespace io
}  // namespace hotplace
