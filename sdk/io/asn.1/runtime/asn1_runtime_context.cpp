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

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime_context.hpp>

namespace hotplace {
namespace io {

asn1_runtime_context asn1_runtime_context::_instance;

asn1_runtime_context* asn1_runtime_context::get_instance() { return &_instance; }

asn1_runtime_context::asn1_runtime_context() : _default(nullptr) {}

asn1_runtime_context::~asn1_runtime_context() {
    critical_section_guard guard(_lock);

    for (auto& pair : _contexts) {
        auto context = pair.second;
        context->release();
    }

    if (_default) _default->release();
}

return_t asn1_runtime_context::add(asn1_runtime* runtime) {
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
        } else {
            ret = errorcode_t::already_exist;
        }
    }
    __finally2 {}
    return ret;
}

asn1_runtime* asn1_runtime_context::add(const std::string& name) {
    critical_section_guard guard(_lock);

    auto iter = _contexts.find(name);
    if (_contexts.end() == iter) {
        auto runtime = new asn1_runtime(name);
        _contexts.emplace(name, runtime);
        return runtime;
    } else {
        return iter->second;
    }
}

asn1_runtime* asn1_runtime_context::get(const std::string& name) const {
    critical_section_guard guard(_lock);
    auto iter = _contexts.find(name);
    if (_contexts.end() == iter) {
        return nullptr;
    } else {
        return iter->second;
    }
}

bool asn1_runtime_context::exist(const std::string& name) const {
    critical_section_guard guard(_lock);
    auto iter = _contexts.find(name);
    if (_contexts.end() == iter) {
        return false;
    } else {
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
        return true;
    }
}

asn1_runtime* asn1_runtime_context::get_default() {
    const auto name = "<DEFAULT>";

    if (nullptr == _default) {
        critical_section_guard guard(_lock);
        if (nullptr == _default) {
            _default = new asn1_runtime(name);
        }
    }
    return _default;
}

static std::string temp_prefix = "_TEMP_";

std::string asn1_runtime_context::temp_name() const {
    std::string name;
    struct timespec ts;
    datetime now;
    now.gettimespec(&ts);

    basic_stream bs;
    valist va;

    va << temp_prefix << ts.tv_sec << ts.tv_nsec;
    bs.vaprintf("{1}{2:h}{3:h}", va);  // _TEMP_6ac10ffb17321ca4

    name = bs.c_str();
    return name;
}

void asn1_runtime_context::sweep_temp() {
    const std::string prefix = temp_prefix;

    critical_section_guard guard(_lock);

    // Find first key >= temp_prefix in O(log N)
    auto it = _contexts.lower_bound(prefix);

    while (it != _contexts.end() && (0 == it->first.compare(0, prefix.size(), prefix))) {
        auto runtime = it->second;
        runtime->release();
        it = _contexts.erase(it);
    }
}

}  // namespace io
}  // namespace hotplace
