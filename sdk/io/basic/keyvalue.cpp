/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/io/basic/keyvalue.hpp>

namespace hotplace {
namespace io {

key_value::key_value(uint32 flags) : _flags(flags), _order(0) {
    // do nothing
}

key_value::key_value(const key_value& object) {
    _keyvalues = object._keyvalues;
    _order_map = object._order_map;
    _reverse_order_map = object._reverse_order_map;
    _flags = object._flags;
    _order = object._order;
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
        } else {
            ++_order;
            _order_map.insert({_order, name});  // c++11, Aggregate initialization
            _reverse_order_map.insert({name, _order});
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t key_value::set(std::string const& key, std::string const& value, int mode) {
    return_t ret = errorcode_t::success;
    ret = set(key.c_str(), value.c_str(), mode);
    return ret;
}

return_t key_value::update(const char* name, const char* value) { return set(name, value, key_value_mode_t::update); }

return_t key_value::update(std::string const& name, std::string const& value) { return update(name.c_str(), value.c_str()); }

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
        key_reverse_order_map_t::iterator reverse_order_iter = _reverse_order_map.find(key);
        _order_map.erase(reverse_order_iter->second);
        _reverse_order_map.erase(reverse_order_iter);
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
        _order = 0;
        _order_map.clear();
        _reverse_order_map.clear();
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

        ret = query(std::string(name), value);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t key_value::query(std::string const& name, std::string& value) {
    return_t ret = errorcode_t::success;

    __try2 {
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

return_t key_value::copyfrom(std::map<std::string, std::string>& source, int mode) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);

    if (key_value_mode_t::move == mode) {
        clear();
    }

    for (keyvalue_map_t::iterator source_iter = source.begin(); source_iter != source.end(); source_iter++) {
        std::string key = source_iter->first;
        std::string value = source_iter->second;
        set(key, value, mode);
    }

    return ret;
}

return_t key_value::copyto(std::map<std::string, std::string>& target) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    target = _keyvalues;
    return ret;
}

key_value& key_value::operator<<(key_value& rhs) {
    copy(rhs, key_value_mode_t::update);
    return *this;
}

void key_value::foreach (std::function<void(std::string const&, std::string const&, void*)> func, void* param) {
    critical_section_guard guard(_lock);
    key_order_map_t::iterator order_iter;
    for (order_iter = _order_map.begin(); order_iter != _order_map.end(); order_iter++) {
        keyvalue_map_t::iterator iter = _keyvalues.find(order_iter->second);
        func(iter->first, iter->second, param);
    }
}

bool key_value::empty() { return _keyvalues.size() == 0; }

size_t key_value::size() { return _keyvalues.size(); }

}  // namespace io
}  // namespace hotplace
