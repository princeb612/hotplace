/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   binary.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdarg.h>
#include <string.h>

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>  // binary32_from_fp32, binary64_from_fp64
#include <ostream>

namespace hotplace {

return_t binary_push(binary_t& target, byte_t value) {
    target.push_back(value);
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, const std::string& value) {
    if (true == value.empty()) {
        // do nothing
    } else {
        target.reserve(target.size() + value.size());
        target.insert(target.end(), value.begin(), value.end());
    }
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, const binary_t& value) {
    if (true == value.empty()) {
        // do nothing
    } else {
        target.reserve(target.size() + value.size());
        target.insert(target.end(), value.begin(), value.end());
    }
    return errorcode_t::success;
}

return_t binary_append(binary_t& target, const char* value) {
    return_t ret = errorcode_t::success;
    if (nullptr == value) {
        ret = errorcode_t::invalid_parameter;
    } else {
        const size_t len = strlen(value);
        if (0 != len) {
            target.reserve(target.size() + len);
            target.insert(target.end(), value, value + len);
        }
    }
    return ret;
}

return_t binary_append(binary_t& target, const char* buf, size_t size) {
    return_t ret = errorcode_t::success;
    if (nullptr == buf) {
        ret = errorcode_t::invalid_parameter;
    } else {
        if (0 != size) {
            target.reserve(target.size() + size);
            target.insert(target.end(), buf, buf + size);
        }
    }
    return ret;
}

return_t binary_append(binary_t& target, const byte_t* buf, size_t size) {
    return_t ret = errorcode_t::success;
    if (nullptr == buf) {
        ret = errorcode_t::invalid_parameter;
    } else {
        if (0 != size) {
            target.reserve(target.size() + size);
            target.insert(target.end(), buf, buf + size);
        }
    }
    return ret;
}

return_t binary_append(binary_t& target, const byte_t* buf, size_t from, size_t to) {
    return_t ret = errorcode_t::success;
    if ((nullptr == buf) || (from >= to)) {
        ret = errorcode_t::invalid_parameter;
    } else {
        const size_t len = to - from;
        target.reserve(target.size() + len);
        target.insert(target.end(), buf + from, buf + to);
    }
    return ret;
}

return_t binary_load(binary_t& target, size_t bnlen, const byte_t* data, size_t len) {
    return_t ret = errorcode_t::success;
    if (nullptr == data) {
        ret = errorcode_t::invalid_parameter;
    } else {
        target.resize(bnlen);
        if (len > bnlen) {
            len = bnlen;
        }
        memcpy(target.data() + (bnlen - len), data, len);
    }
    return ret;
}

return_t binary_fill(binary_t& target, size_t count, const byte_t& value) {
    if (count > 0) {
        const size_t pos = target.size();
        target.resize(pos + count);
        memset(target.data() + pos, value, count);
    }
    return errorcode_t::success;
}

std::string to_string(const binary_t& bin) {
    if (true == bin.empty()) {
        return std::string();
    } else {
        return std::string(reinterpret_cast<const char*>(bin.data()), bin.size());
    }
}

binary_t to_binary(const std::string& source) { return binary_t(source.begin(), source.end()); }

}  // namespace hotplace
