/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_KEYVALUE__
#define __HOTPLACE_SDK_BASE_BASIC_KEYVALUE__

#include <algorithm>
#include <deque>
#include <functional>
#include <map>
#include <sdk/base/basic/types.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/datetime.hpp>

namespace hotplace {

enum key_value_flag_t {
    key_value_case_sensitive = (1 << 0),
};

/**
 * kv_move      clear and assign
 * kv_update    drop older data
 * kv_keep      older data
 */
enum key_value_mode_t { kv_move = 0, kv_update, kv_keep };

/**
 * @brief key-value configuation
 * @remarks
 */
template <typename value_t = std::string>
class t_stringkey_value {
   public:
    /**
     * @brief constructor
     * @param uint32 flags [inopt]
     */
    t_stringkey_value<value_t>(uint32 flags = key_value_flag_t::key_value_case_sensitive) : _flags(flags), _order(0) {}

    t_stringkey_value<value_t>(const t_stringkey_value<value_t> &object) {
        _keyvalues = object._keyvalues;
        _order_map = object._order_map;
        _reverse_order_map = object._reverse_order_map;
        _flags = object._flags;
        _order = object._order;
    }
    /**
     * @brief destructor
     */
    ~t_stringkey_value<value_t>() {}

    /**
     * @brief set
     * @param uint32 flags [in]
     */
    t_stringkey_value<value_t> &set(uint32 flags) {
        _flags = flags;
        return *this;
    }

    /**
     * @brief   add, update
     * @param   const std::string&  name    [IN]
     * @param   const value_t&      value   [IN]
     * @param   uint32              mode    [INOPT] see key_value_mode_t
     * @return  error code (see error.hpp)
     * @remarks
     *          set (key1, value1, key_value_mode_t::kv_keep); // return errorcode_t::success
     *          set (key1, value2, key_value_mode_t::kv_keep); // return errorcode_t::already_exist
     *          set (key1, value2, key_value_mode_t::kv_update); // kv_update, return errorcode_t::success
     */
    return_t set(const std::string &name, const value_t &value, int mode = key_value_mode_t::kv_update) {
        return_t ret = errorcode_t::success;

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);

            keyvalue_map_pib_t pib = _keyvalues.insert(std::make_pair(key, value));
            if (false == pib.second) {
                if (key_value_mode_t::kv_update == mode) {
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
    /**
     * @brief   update
     * @param   const std::string&  name    [in]
     * @param   const value_t&      value   [in]
     * @return  error code (see error.hpp)
     * @remarks
     *          set(name, value, key_value_mode_t::kv_update);
     */
    return_t update(const std::string &name, const value_t &value) { return set(name, value, key_value_mode_t::kv_update); }
    /**
     * @brief   remove
     * @param   const std::string&  name    [IN]
     * @return  error code (see error.hpp)
     */
    return_t remove(const std::string &name) {
        return_t ret = errorcode_t::success;

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);

            typename keyvalue_map_t::iterator iter = _keyvalues.find(key);
            if (_keyvalues.end() != iter) {
                _keyvalues.erase(iter);
            }

            typename key_reverse_order_map_t::iterator reverse_order_iter = _reverse_order_map.find(key);
            _order_map.erase(reverse_order_iter->second);
            _reverse_order_map.erase(reverse_order_iter);
        }
        __finally2 {
            // do nothing
        }
        return ret;
    }
    /**
     * @brief   clear
     * @return  error code (see error.hpp)
     */
    return_t clear() {
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
    /**
     * @brief   exist
     * @remarks
     *          kv.update ("key", "value");
     *          result = exist ("key"); // true
     *          result = exist ("value"); // false
     */
    bool exist(const std::string &name) {
        bool ret_value = false;

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);
            typename keyvalue_map_t::iterator iter = _keyvalues.find(key);
            if (_keyvalues.end() != iter) {
                ret_value = true;
            }
        }
        __finally2 {
            // do nothing
        }
        return ret_value;
    }
    /**
     * @brief   return value by key
     * @param   const std::string& name
     * @remarks
     *          kv.update ("key", "value");
     *          value = kv ["key"]; // "value"
     *          value = kv ["value"]; // nullptr
     */
    value_t operator[](const std::string &name) {
        value_t ret_value = value_t();

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);
            typename keyvalue_map_t::iterator iter = _keyvalues.find(key);
            if (_keyvalues.end() != iter) {
                ret_value = iter->second.c_str();
            }
        }
        __finally2 {
            // do nothing
        }
        return ret_value;
    }
    /**
     * @brief   query
     * @param   const std::string&  name    [IN]
     * @param   value_t&            value   [OUT]
     * @return  error code (see error.hpp)
     * @remarks
     *          kv.update ("key", "value");
     *          kv.query ("key", value); // "value"
     *          kv.query ("value", value); // ""
     */
    return_t query(const std::string &name, value_t &value) {
        return_t ret = errorcode_t::success;

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);
            typename keyvalue_map_t::iterator iter = _keyvalues.find(key);
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
    value_t get(const std::string &name) {
        value_t ret_value = value_t();
        query(name, ret_value);
        return ret_value;
    }

    /**
     * @brief   copy
     * @param   t_stringkey_value&      rhs   [IN]
     * @param   int             mode  [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          kv1 [ ("key1", "value1"), ("key2", "value2") ]
     *          kv2 [ ("key2", "item2"), ("key3", "item3") ]
     *
     *          result of kv1.copy (kv2, key_value_mode_t::kv_move)   is kv1 [ ("key2", "item2"), ("key3", "item3") ]
     *          result of kv1.copy (kv2, key_value_mode_t::kv_update) is kv1 [ ("key1", "value1"), ("key2", "item2"), ("key3", "item3") ]
     *          result of kv1.copy (kv2, key_value_mode_t::kv_keep)   is kv1 [ ("key1", "value1"), ("key2", "value2"), ("key3", "item3") ]
     */
    return_t copy(t_stringkey_value<value_t> &rhs, int mode = key_value_mode_t::kv_update) {
        return_t ret = errorcode_t::success;

        critical_section_guard guard(rhs._lock);
        keyvalue_map_t &source = rhs._keyvalues;

        ret = copyfrom(source, mode);
        return ret;
    }

    /**
     * @brief   copy
     * @return  error code (see error.hpp)
     * @sa      copy
     */
    return_t copyfrom(const std::map<std::string, value_t> &source, int mode) {
        return_t ret = errorcode_t::success;

        critical_section_guard guard(_lock);

        if (key_value_mode_t::kv_move == mode) {
            clear();
        }

        for (const auto &pair : source) {
            set(pair.first, pair.second, mode);
        }

        return ret;
    }
    return_t copyto(std::map<std::string, value_t> &target) {
        return_t ret = errorcode_t::success;

        critical_section_guard guard(_lock);
        target = _keyvalues;
        return ret;
    }

    /**
     * @brief   foreach
     * @param   std::function<void(const std::string&, const std::string&, void*)> func [in]
     * @param   void* param [inopt]
     */
    void foreach (std::function<void(const std::string &, const value_t &, void *)> func, void *param = nullptr) {
        critical_section_guard guard(_lock);
        for (const auto &pair : _order_map) {
            typename keyvalue_map_t::iterator iter = _keyvalues.find(pair.second);
            func(iter->first, iter->second, param);
        }
    }

    /**
     * @brief   operator <<
     * @param   t_stringkey_value& rhs [in]
     * @return  t_stringkey_value&
     * @remarks copy with key_value_mode_t::kv_update
     */
    t_stringkey_value<value_t> &operator<<(t_stringkey_value<value_t> &rhs) {
        copy(rhs, key_value_mode_t::kv_update);
        return *this;
    }

    bool empty() { return _keyvalues.size() == 0; }
    size_t size() { return _keyvalues.size(); }

   protected:
   private:
    /* key, value */
    typedef std::map<std::string, value_t> keyvalue_map_t;
    typedef std::pair<typename keyvalue_map_t::iterator, bool> keyvalue_map_pib_t;

    typedef std::map<int, std::string> key_order_map_t;
    typedef std::map<std::string, int> key_reverse_order_map_t;

    critical_section _lock;
    keyvalue_map_t _keyvalues;
    key_order_map_t _order_map;
    key_reverse_order_map_t _reverse_order_map;
    uint32 _flags;
    uint32 _order;
};

typedef t_stringkey_value<std::string> skey_value;

/**
 * integer value
 */
template <typename key_t, typename value_t>
class t_key_value {
   public:
    typedef std::map<key_t, value_t> keyvalue_map_t;
    typedef std::pair<typename keyvalue_map_t::iterator, bool> keyvalue_map_pib_t;

    t_key_value<key_t, value_t>() {}
    t_key_value<key_t, value_t>(const t_key_value<key_t, value_t> &rhs) { _keyvalue_map = rhs._keyvalue_map; }

    t_key_value<key_t, value_t> &set(key_t key, const value_t &value) {
        return_t ret = errorcode_t::success;

        critical_section_guard guard(_lock);
        keyvalue_map_pib_t pib = _keyvalue_map.insert(std::make_pair(key, value));
        if (false == pib.second) {
            pib.first->second = value;
        }

        return *this;
    }
    value_t get(const key_t &key) {
        value_t value = value_t();

        critical_section_guard guard(_lock);
        typename keyvalue_map_t::iterator iter = _keyvalue_map.find(key);
        if (_keyvalue_map.end() != iter) {
            value = iter->second;
        }

        return value;
    }
    value_t inc(const key_t &key) {
        critical_section_guard guard(_lock);
        auto value = _keyvalue_map[key];
        _keyvalue_map[key] = ++value;
        return value;
    }
    t_key_value<key_t, value_t> &operator=(const t_key_value<key_t, value_t> &rhs) {
        critical_section_guard guard(_lock);
        _keyvalue_map.clear();
        _keyvalue_map = rhs._keyvalue_map;
        return *this;
    }
    return_t copyfrom(const t_key_value<key_t, value_t> *rhs) {
        return_t ret = errorcode_t::success;
        if (nullptr == rhs) {
            ret = errorcode_t::invalid_parameter;
        } else {
            critical_section_guard guard(_lock);
            _keyvalue_map.clear();
            _keyvalue_map = rhs->_keyvalue_map;
        }
        return ret;
    }

   private:
    critical_section _lock;
    keyvalue_map_t _keyvalue_map;
};

}  // namespace hotplace

#endif
