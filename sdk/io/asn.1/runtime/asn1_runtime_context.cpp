/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_runtime_context.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime_context.hpp>

namespace hotplace {
namespace io {

asn1_runtime_context asn1_runtime_context::_instance;

asn1_runtime_context* asn1_runtime_context::get_instance() { return &_instance; }

asn1_runtime_context::asn1_runtime_context() : _current(nullptr), _default(nullptr) {}

asn1_runtime_context::~asn1_runtime_context() {
    critical_section_guard guard(_lock);

    for (auto& pair : _contexts) {
        auto context = pair.second;
        context->release();
    }

    if (_default) _default->release();
}

return_t asn1_runtime_context::set(asn1_runtime* runtime) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == runtime) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);
        auto pib = _contexts.emplace(runtime->get_name(), runtime);
        if (pib.second) {
            runtime->addref();
            _current = runtime;
        } else {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {}
    return ret;
}

bool asn1_runtime_context::select(const std::string& name) {
    critical_section_guard guard(_lock);

    auto iter = _contexts.find(name);
    if (_contexts.end() == iter) {
        return false;
    } else {
        _current = iter->second;
        return true;
    }
}

bool asn1_runtime_context::remove(const std::string& name) {
    critical_section_guard guard(_lock);

    auto iter = _contexts.find(name);
    if (_contexts.end() == iter) {
        return false;
    } else {
        auto runtime = iter->second;
        runtime->release();

        _contexts.erase(iter);
        _current = (_default ? _default : nullptr);
        return true;
    }
}

asn1_runtime* asn1_runtime_context::current() { return _current ? _current : use_default(); }

asn1_runtime* asn1_runtime_context::use_default() {
    const auto name = "<DEFAULT>";

    if (nullptr == _default) {
        critical_section_guard guard(_lock);
        if (nullptr == _default) {
            _default = new asn1_runtime(name);
        }
    }
    return _current = _default;
}

}  // namespace io
}  // namespace hotplace
