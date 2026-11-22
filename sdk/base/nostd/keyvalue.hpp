/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   keyvalue.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_KEYVALUE__
#define __HOTPLACE_SDK_BASE_BASIC_KEYVALUE__

#include <algorithm>
#include <atomic>
#include <deque>
#include <functional>
#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <map>
#include <mutex>

namespace hotplace {

enum key_value_flag_t : uint32 {
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
template <typename TYPE = std::string>
class t_stringkey_value {
   public:
    /**
     * @brief constructor
     * @param uint32 flags [inopt]
     */
    t_stringkey_value(uint32 flags = key_value_flag_t::key_value_case_sensitive) : _flags(flags), _order(0) {}

    t_stringkey_value(const t_stringkey_value& object) {
        _keyvalues = object._keyvalues;
        _order_map = object._order_map;
        _reverse_order_map = object._reverse_order_map;
        _flags = object._flags;
        _order = object._order;
    }
    /**
     * @brief destructor
     */
    ~t_stringkey_value() {}

    /**
     * @brief set
     * @param uint32 flags [in]
     */
    t_stringkey_value& set(uint32 flags) {
        _flags = flags;
        return *this;
    }

    /**
     * @brief   add, update
     * @param   const std::string&  name    [IN]
     * @param   const TYPE&      value   [IN]
     * @param   uint32              mode    [INOPT] see key_value_mode_t
     * @return  error code (see error.hpp)
     * @remarks
     *          set (key1, value1, key_value_mode_t::kv_keep); // return errorcode_t::success
     *          set (key1, value2, key_value_mode_t::kv_keep); // return errorcode_t::already_exist
     *          set (key1, value2, key_value_mode_t::kv_update); // kv_update, return errorcode_t::success
     */
    return_t set(const std::string& name, const TYPE& value, int mode = key_value_mode_t::kv_update) {
        return_t ret = errorcode_t::success;

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);

            auto pib = _keyvalues.insert(std::make_pair(key, value));
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
        __finally2 {}
        return ret;
    }
    /**
     * @brief   update
     * @param   const std::string&  name    [in]
     * @param   const TYPE&      value   [in]
     * @return  error code (see error.hpp)
     * @remarks
     *          set(name, value, key_value_mode_t::kv_update);
     */
    return_t update(const std::string& name, const TYPE& value) { return set(name, value, key_value_mode_t::kv_update); }
    /**
     * @brief   remove
     * @param   const std::string&  name    [IN]
     * @return  error code (see error.hpp)
     */
    return_t remove(const std::string& name) {
        return_t ret = errorcode_t::success;

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);

            auto iter = _keyvalues.find(key);
            if (_keyvalues.end() != iter) {
                _keyvalues.erase(iter);
            }

            auto reverse_order_iter = _reverse_order_map.find(key);
            _order_map.erase(reverse_order_iter->second);
            _reverse_order_map.erase(reverse_order_iter);
        }
        __finally2 {}
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
        __finally2 {}
        return ret;
    }
    /**
     * @brief   exist
     * @remarks
     *          kv.update ("key", "value");
     *          result = exist ("key"); // true
     *          result = exist ("value"); // false
     */
    bool exist(const std::string& name) const {
        bool ret_value = false;

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);
            auto iter = _keyvalues.find(key);
            if (_keyvalues.end() != iter) {
                ret_value = true;
            }
        }
        __finally2 {}
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
    TYPE operator[](const std::string& name) const {
        TYPE ret_value = TYPE();

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);
            auto iter = _keyvalues.find(key);
            if (_keyvalues.end() != iter) {
                ret_value = iter->second.c_str();
            }
        }
        __finally2 {}
        return ret_value;
    }
    /**
     * @brief   query
     * @param   const std::string&  name    [IN]
     * @param   TYPE&            value   [OUT]
     * @return  error code (see error.hpp)
     * @remarks
     *          kv.update ("key", "value");
     *          kv.query ("key", value); // "value"
     *          kv.query ("value", value); // ""
     */
    return_t query(const std::string& name, TYPE& value) const {
        return_t ret = errorcode_t::success;

        __try2 {
            std::string key(name);
            if (0 == (key_value_flag_t::key_value_case_sensitive & _flags)) {
                std::transform(key.begin(), key.end(), key.begin(), tolower);
            }

            critical_section_guard guard(_lock);
            auto iter = _keyvalues.find(key);
            if (_keyvalues.end() != iter) {
                value = iter->second;
            } else {
                ret = errorcode_t::not_found;
            }
        }
        __finally2 {}
        return ret;
    }
    TYPE get(const std::string& name) const {
        TYPE ret_value = TYPE();
        query(name, ret_value);
        return ret_value;
    }

    /**
     * @brief   copy
     * @param   t_stringkey_value& other   [IN]
     * @param   int mode  [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          kv1 [ ("key1", "value1"), ("key2", "value2") ]
     *          kv2 [ ("key2", "item2"), ("key3", "item3") ]
     *
     *          result of kv1.copy (kv2, key_value_mode_t::kv_move)   is kv1 [ ("key2", "item2"), ("key3", "item3") ]
     *          result of kv1.copy (kv2, key_value_mode_t::kv_update) is kv1 [ ("key1", "value1"), ("key2", "item2"), ("key3", "item3") ]
     *          result of kv1.copy (kv2, key_value_mode_t::kv_keep)   is kv1 [ ("key1", "value1"), ("key2", "value2"), ("key3", "item3") ]
     */
    return_t copy(t_stringkey_value& other, int mode = key_value_mode_t::kv_update) {
        return_t ret = errorcode_t::success;

        critical_section_guard guard(other._lock);
        keyvalue_map_t& source = other._keyvalues;

        ret = copyfrom(source, mode);
        return ret;
    }

    /**
     * @brief   copy
     * @return  error code (see error.hpp)
     * @sa      copy
     */
    return_t copyfrom(const std::map<std::string, TYPE>& source, int mode) {
        return_t ret = errorcode_t::success;

        critical_section_guard guard(_lock);

        if (key_value_mode_t::kv_move == mode) {
            clear();
        }

        for (const auto& pair : source) {
            set(pair.first, pair.second, mode);
        }

        return ret;
    }
    return_t copyto(std::map<std::string, TYPE>& target) {
        return_t ret = errorcode_t::success;

        critical_section_guard guard(_lock);
        target = _keyvalues;
        return ret;
    }

    /**
     * @brief   foreach
     * @param   void(const std::string&, const TYPE&, void*)
     * @param   void* param [inopt]
     */
    template <typename F>
    void foreach (F func, void* param = nullptr) const {
        critical_section_guard guard(_lock);
        for (const auto& pair : _order_map) {
            auto iter = _keyvalues.find(pair.second);
            func(iter->first, iter->second, param);
        }
    }

    t_stringkey_value& operator=(const t_stringkey_value& object) {
        _keyvalues = object._keyvalues;
        _order_map = object._order_map;
        _reverse_order_map = object._reverse_order_map;
        _flags = object._flags;
        _order = object._order;
        return *this;
    }

    /**
     * @brief   operator <<
     * @param   t_stringkey_value& other [in]
     * @return  t_stringkey_value&
     * @remarks copy with key_value_mode_t::kv_update
     */
    t_stringkey_value& operator<<(t_stringkey_value& other) {
        copy(other, key_value_mode_t::kv_update);
        return *this;
    }

    bool empty() const { return _keyvalues.size() == 0; }
    size_t size() const { return _keyvalues.size(); }

   protected:
   private:
    /* key, value */
    typedef std::map<std::string, TYPE> keyvalue_map_t;

    typedef std::map<int, std::string> key_order_map_t;
    typedef std::map<std::string, int> key_reverse_order_map_t;

    mutable critical_section _lock;
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
template <typename KEY, typename TYPE>
class t_key_value {
   public:
    typedef std::map<KEY, TYPE> keyvalue_map_t;

    enum class hook_operation_t {
        set,
        get,
        access,
        increment,
        remove,
        copy_construct,
        assign,
        copyfrom,
    };

    /**
     * @brief event emitted by the optional t_key_value hook
     * @remarks
     *          before_value and after_value are valid only for the duration
     *          of the hook callback. A null pointer means that the key did
     *          not exist on that side of the operation.
     */
    struct hook_event_t {
        hook_operation_t operation;
        const t_key_value* owner;
        const t_key_value* source;
        KEY key;
        bool before_exists;
        const TYPE* before_value;
        bool after_exists;
        const TYPE* after_value;
    };

    typedef void (*hook_handler_t)(const hook_event_t&, void*);

    t_key_value() {}

    t_key_value(const t_key_value& other) {
        hook_binding_t binding = get_hook_binding();
        keyvalue_map_t source;
        {
            critical_section_guard guard(other._lock);
            source = other._keyvalue_map;
        }
        _keyvalue_map = source;

        if (nullptr != binding.handler) {
            keyvalue_map_t empty;
            notify_replacement(binding, hook_operation_t::copy_construct, this, &other, empty, _keyvalue_map);
        }
    }

    /**
     * @brief register an instance-local hook for this key-value object
     * @remarks
     *          The callback is invoked after the key-value lock is released.
     *          It can filter event.key and use a debugger breakpoint in its
     *          own handler. Register nullptr to disable the hook.
     */
    void set_hook(hook_handler_t handler, void* parameter = nullptr) {
        std::lock_guard<std::mutex> guard(_hook_lock);
        _hook_handler = handler;
        _hook_parameter = parameter;
        _hook_enabled.store(nullptr != handler, std::memory_order_release);
    }

    void clear_hook() { set_hook(nullptr, nullptr); }

    t_key_value& set(KEY key, const TYPE& value) {
        hook_binding_t binding = get_hook_binding();
        TYPE before{};
        bool before_exists = false;

        {
            critical_section_guard guard(_lock);
            auto pib = _keyvalue_map.insert(std::make_pair(key, value));
            if (false == pib.second) {
                if (nullptr != binding.handler) {
                    before = pib.first->second;
                    before_exists = true;
                }
                pib.first->second = value;
            }
        }

        if (nullptr != binding.handler) {
            notify_hook(binding, hook_operation_t::set, this, nullptr, key, before_exists, before_exists ? &before : nullptr, true, &value);
        }
        return *this;
    }

    TYPE get(const KEY& key) const {
        hook_binding_t binding = get_hook_binding();
        TYPE value{};
        bool exists = false;

        {
            critical_section_guard guard(_lock);
            auto iter = _keyvalue_map.find(key);
            if (_keyvalue_map.end() != iter) {
                value = iter->second;
                exists = true;
            }
        }

        if (nullptr != binding.handler) {
            notify_hook(binding, hook_operation_t::get, this, nullptr, key, false, nullptr, exists, exists ? &value : nullptr);
        }
        return value;
    }

    TYPE access(const KEY& key, bool get_then_inc) {
        hook_binding_t binding = get_hook_binding();
        TYPE before{};
        TYPE result{};
        TYPE after{};
        bool before_exists = false;

        {
            critical_section_guard guard(_lock);
            auto iter = _keyvalue_map.find(key);
            before_exists = (_keyvalue_map.end() != iter);
            if (before_exists && (nullptr != binding.handler)) {
                before = iter->second;
            }

            result = _keyvalue_map[key];
            if (get_then_inc) {
                _keyvalue_map[key] = result + 1;
            }
            after = _keyvalue_map[key];
        }

        if (nullptr != binding.handler) {
            notify_hook(binding, hook_operation_t::access, this, nullptr, key, before_exists, before_exists ? &before : nullptr, true, &after);
        }
        return result;
    }

    TYPE inc(const KEY& key) {
        hook_binding_t binding = get_hook_binding();
        TYPE before{};
        TYPE after{};
        bool before_exists = false;

        {
            critical_section_guard guard(_lock);
            auto iter = _keyvalue_map.find(key);
            before_exists = (_keyvalue_map.end() != iter);
            if (before_exists && (nullptr != binding.handler)) {
                before = iter->second;
            }

            TYPE value = _keyvalue_map[key];
            _keyvalue_map[key] = ++value;
            after = _keyvalue_map[key];
        }

        if (nullptr != binding.handler) {
            notify_hook(binding, hook_operation_t::increment, this, nullptr, key, before_exists, before_exists ? &before : nullptr, true, &after);
        }
        return after;
    }

    void remove(const KEY& key) {
        hook_binding_t binding = get_hook_binding();
        TYPE before{};
        bool before_exists = false;

        {
            critical_section_guard guard(_lock);
            auto iter = _keyvalue_map.find(key);
            if (_keyvalue_map.end() != iter) {
                if (nullptr != binding.handler) {
                    before = iter->second;
                    before_exists = true;
                }
                _keyvalue_map.erase(iter);
            }
        }

        if (before_exists) {
            notify_hook(binding, hook_operation_t::remove, this, nullptr, key, true, &before, false, nullptr);
        }
    }

    t_key_value& operator=(const t_key_value& other) {
        if (this == &other) {
            return *this;
        }

        hook_binding_t binding = get_hook_binding();
        keyvalue_map_t source;
        {
            critical_section_guard guard(other._lock);
            source = other._keyvalue_map;
        }

        keyvalue_map_t before;
        keyvalue_map_t after;
        {
            critical_section_guard guard(_lock);
            if (nullptr != binding.handler) {
                before = _keyvalue_map;
            }
            _keyvalue_map = source;
            if (nullptr != binding.handler) {
                after = _keyvalue_map;
            }
        }

        if (nullptr != binding.handler) {
            notify_replacement(binding, hook_operation_t::assign, this, &other, before, after);
        }
        return *this;
    }

    return_t copyfrom(const t_key_value* other) {
        if (nullptr == other) {
            return errorcode_t::invalid_parameter;
        }
        if (this == other) {
            return errorcode_t::success;
        }

        hook_binding_t binding = get_hook_binding();
        keyvalue_map_t source;
        {
            critical_section_guard guard(other->_lock);
            source = other->_keyvalue_map;
        }

        keyvalue_map_t before;
        keyvalue_map_t after;
        {
            critical_section_guard guard(_lock);
            if (nullptr != binding.handler) {
                before = _keyvalue_map;
            }
            _keyvalue_map = source;
            if (nullptr != binding.handler) {
                after = _keyvalue_map;
            }
        }

        if (nullptr != binding.handler) {
            notify_replacement(binding, hook_operation_t::copyfrom, this, other, before, after);
        }
        return errorcode_t::success;
    }

    /*
     * @example
     *          t_key_value<uint32, uint32> frequency;
     *
     *          frequency.access(pattern_id, true);
     *
     *          _logger->writeln("pattern frequency ... statistics for rule optimization");
     *          frequency.for_each([](uint32 pid, uint32 cnt) -> void { _logger->writeln("> pattern id %u : %u", pid, cnt); });
     */
    void for_each(std::function<void(KEY, TYPE)> f) {
        critical_section_guard guard(_lock);
        for (const auto& pair : _keyvalue_map) {
            f(pair.first, pair.second);
        }
    }

   private:
    struct hook_binding_t {
        hook_handler_t handler;
        void* parameter;
    };

    hook_binding_t get_hook_binding() const {
        if (false == _hook_enabled.load(std::memory_order_acquire)) {
            hook_binding_t disabled = {nullptr, nullptr};
            return disabled;
        }

        std::lock_guard<std::mutex> guard(_hook_lock);
        hook_binding_t binding = {_hook_handler, _hook_parameter};
        return binding;
    }

    static void notify_hook(const hook_binding_t& binding, hook_operation_t operation, const t_key_value* owner, const t_key_value* source, const KEY& key,
                            bool before_exists, const TYPE* before_value, bool after_exists, const TYPE* after_value) {
        if (nullptr != binding.handler) {
            hook_event_t event = {operation, owner, source, key, before_exists, before_value, after_exists, after_value};
            binding.handler(event, binding.parameter);
        }
    }

    static void notify_replacement(const hook_binding_t& binding, hook_operation_t operation, const t_key_value* owner, const t_key_value* source,
                                   const keyvalue_map_t& before, const keyvalue_map_t& after) {
        for (const auto& pair : before) {
            auto iter = after.find(pair.first);
            bool after_exists = (after.end() != iter);
            notify_hook(binding, operation, owner, source, pair.first, true, &pair.second, after_exists, after_exists ? &iter->second : nullptr);
        }

        for (const auto& pair : after) {
            if (before.end() == before.find(pair.first)) {
                notify_hook(binding, operation, owner, source, pair.first, false, nullptr, true, &pair.second);
            }
        }
    }

    mutable critical_section _lock;
    keyvalue_map_t _keyvalue_map;

    // Hook registration is local to this t_key_value instance.
    mutable std::mutex _hook_lock;
    std::atomic<bool> _hook_enabled{false};
    hook_handler_t _hook_handler = nullptr;
    void* _hook_parameter = nullptr;
};

}  // namespace hotplace

#endif
