/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/keyvalue.hpp>

namespace hotplace {
namespace io {

key_value::key_value(uint32 flags) : _flags(flags) {
    // do nothing
}

key_value::~key_value() {
    // do nothing
}

key_value& key_value::set(uint32 flags) {
    _flags = flags;
    return *this;
}

return_t key_value::set(const char* name, const char* value, int mode) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == name || nullptr == value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string key(name);
        if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
            std::transform(key.begin(), key.end(), key.begin(), tolower);
        }

        critical_section_guard guard(_lock);
        keyvalue_map_pib_t pib = _keyvalues.insert(std::make_pair(key, value));
        if (false == pib.second) {
            if (key_value_mode_t::update == mode) {
                pib.first->second = value;
            } else {
                ret = errorcode_t::already_exist;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t key_value::set(std::string key, std::string value, int mode) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
            std::transform(key.begin(), key.end(), key.begin(), tolower);
        }

        critical_section_guard guard(_lock);
        keyvalue_map_pib_t pib = _keyvalues.insert(std::make_pair(key, value));
        if (false == pib.second) {
            if (key_value_mode_t::update == mode) {
                pib.first->second = value;
            } else {
                ret = errorcode_t::already_exist;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t key_value::update(const char* name, const char* value) { return set(name, value, key_value_mode_t::update); }

return_t key_value::remove(const char* name) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string key(name);
        if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
            std::transform(key.begin(), key.end(), key.begin(), tolower);
        }

        critical_section_guard guard(_lock);
        keyvalue_map_t::iterator iter = _keyvalues.find(key);
        if (_keyvalues.end() != iter) {
            _keyvalues.erase(iter);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t key_value::clear() {
    return_t ret = errorcode_t::success;

    __try2 {
        critical_section_guard guard(_lock);
        _keyvalues.clear();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool key_value::exist(const char* name) {
    bool ret_value = false;

    __try2 {
        if (nullptr == name) {
            __leave2;
        }

        std::string key(name);
        if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
            std::transform(key.begin(), key.end(), key.begin(), tolower);
        }

        critical_section_guard guard(_lock);
        keyvalue_map_t::iterator iter = _keyvalues.find(key);
        if (_keyvalues.end() != iter) {
            ret_value = true;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const char* key_value::operator[](const char* name) {
    const char* ret_value = nullptr;

    __try2 {
        if (nullptr == name) {
            __leave2;
        }

        std::string key(name);
        if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
            std::transform(key.begin(), key.end(), key.begin(), tolower);
        }

        critical_section_guard guard(_lock);
        keyvalue_map_t::iterator iter = _keyvalues.find(key);
        if (_keyvalues.end() != iter) {
            ret_value = iter->second.c_str();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

return_t key_value::query(const char* name, std::string& value) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string key(name);
        if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
            std::transform(key.begin(), key.end(), key.begin(), tolower);
        }

        critical_section_guard guard(_lock);
        keyvalue_map_t::iterator iter = _keyvalues.find(key);
        if (_keyvalues.end() != iter) {
            value = iter->second;
        } else {
            ret = errorcode_t::not_found;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

std::string key_value::get(std::string const& name) {
    std::string ret_value;
    query(name.c_str(), ret_value);
    return ret_value;
}

return_t key_value::copy(key_value& rhs, int mode) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(rhs._lock);
    keyvalue_map_t& source = rhs._keyvalues;

    ret = copyfrom(source, mode);
    return ret;
}

return_t key_value::copyfrom(std::unordered_map<std::string, std::string>& source, int mode) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);

    if (key_value_mode_t::move == mode) {
        _keyvalues.clear();
        _keyvalues.insert(source.begin(), source.end());
    } else {
#if __cplusplus >= 201103L  // c++11
        for_each(source.begin(), source.end(), [this, mode](std::pair<std::string, std::string> p) {
            auto iter = _keyvalues.find(p.first);
            if (_keyvalues.end() == iter) {
                _keyvalues.insert(p);
            } else {
                if (key_value_mode_t::update == mode) {
                    iter->second = p.second;
                }
            }
        });
#else
        for (keyvalue_map_t::iterator source_iter = source.begin(); source_iter != source.end(); source_iter++) {
            std::string key = source_iter->first;
            std::string value = source_iter->second;
            keyvalue_map_t::iterator iter = _keyvalues.find(key);
            if (_keyvalues.end() == iter) {
                _keyvalues.insert(std::make_pair(key, value));
            } else {
                if (key_value_mode_t::update == mode) {
                    iter->second = value;
                }
            }
        }
#endif
    }

    return ret;
}

return_t key_value::copyto(std::unordered_map<std::string, std::string>& target) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    target = _keyvalues;
    return ret;
}

key_value& key_value::operator=(key_value& rhs) {
    clear();
    copy(rhs, key_value_mode_t::update);
    return *this;
}

key_value& key_value::operator<<(key_value& rhs) {
    copy(rhs, key_value_mode_t::update);
    return *this;
}

void key_value::foreach (std::function<void(std::string const&, std::string const&, void*)> func, void* param) {
    critical_section_guard guard(_lock);
    keyvalue_map_t::iterator iter;
    for (iter = _keyvalues.begin(); iter != _keyvalues.end(); iter++) {
        func(iter->first, iter->second, param);
    }
}

}  // namespace io
}  // namespace hotplace
