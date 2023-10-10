/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_KEYVALUE__
#define __HOTPLACE_SDK_IO_BASIC_KEYVALUE__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <map>

namespace hotplace {
namespace io {

/**
 * move    clear and assign
 * update  drop older data
 * key     keep older data
 */
enum key_value_mode_t { move = 0, update, keep };

/**
 * @brief key-value configuation
 * @remarks
 */
class key_value {
   public:
    key_value();
    ~key_value();

    /**
     * @brief   add, update
     * @param   const char*     name    [IN]
     * @param   const char*     value   [IN]
     * @param   uint32           flags   [INOPT] 1 overwrite, 0 keep old
     * @return  error code (see error.hpp)
     * @remarks
     *          set (key1, value1); // return errorcode_t::success
     *          set (key1, value2); // return errorcode_t::already_exist
     *          set (key1, value2, key_value::mode_update); // update, return errorcode_t::success
     */
    return_t set(const char* name, const char* value, int mode = key_value_mode_t::update);
    /**
     * @brief   update
     * @param   const char* name [in]
     * @param   const char* value [in]
     * @return  error code (see error.hpp)
     * @remarks
     *          set(name, value, key_value_mode_t::update);
     */
    return_t update(const char* name, const char* value);
    /**
     * @brief   remove
     * @param   const char*     name    [IN]
     * @return  error code (see error.hpp)
     */
    return_t remove(const char* name);
    /**
     * @brief   clear
     * @return  error code (see error.hpp)
     */
    return_t clear();
    /**
     * @brief   exist
     * @remarks
     *          kv.update ("key", "value");
     *          result = exist ("key"); // true
     *          result = exist ("value"); // false
     */
    bool exist(const char* name);
    /**
     * @brief   return value by key
     * @param   const char* name
     * @remarks
     *          kv.update ("key", "value");
     *          const char* value = kv ["key"]; // "value"
     *          const char* value = kv ["value"]; // nullptr
     */
    const char* operator[](const char* name);
    /**
     * @brief   query
     * @param   const char*     name    [IN]
     * @param   std::string&    value   [OUT]
     * @return  error code (see error.hpp)
     * @remarks
     *          kv.update ("key", "value");
     *          kv.query ("key", value); // "value"
     *          kv.query ("value", value); // ""
     */
    return_t query(const char* name, std::string& value);

    /**
     * @brief   copy
     * @param   key_value&       rhs   [IN]
     * @param   int             mode  [IN]
     * @return  error code (see error.hpp)
     * @remarks
     *          kv1 [ ("key1", "value1"), ("key2", "value2") ]
     *          kv2 [ ("key2", "item2"), ("key3", "item3") ]
     *
     *          result of kv1.copy (kv2, key_value_mode_t::move)   is kv1 [ ("key2", "item2"), ("key3", "item3") ]
     *          result of kv1.copy (kv2, key_value_mode_t::update) is kv1 [ ("key1", "value1"), ("key2", "item2"), ("key3", "item3") ]
     *          result of kv1.copy (kv2, key_value_mode_t::keep)   is kv1 [ ("key1", "value1"), ("key2", "value2"), ("key3", "item3") ]
     */
    return_t copy(key_value& rhs, int mode = key_value_mode_t::update);

    return_t copyfrom(std::map<std::string, std::string>& source, int mode);
    return_t copyto(std::map<std::string, std::string>& target);

    /**
     * @brief   operator =
     * @param   key_value& rhs [in]
     * @return  key_value&
     * @remarks copy with key_value_mode_t::update
     */
    key_value& operator=(key_value& rhs);
    /**
     * @brief   operator <<
     * @param   key_value& rhs [in]
     * @return  key_value&
     * @remarks copy with key_value_mode_t::update
     */
    key_value& operator<<(key_value& rhs);

    /* key, value */
    typedef std::map<std::string, std::string> keyvalue_map_t;
    typedef std::pair<keyvalue_map_t::iterator, bool> keyvalue_map_pib_t;

   protected:
    critical_section _lock;
    keyvalue_map_t _keyvalues;
};

}  // namespace io
}  // namespace hotplace

#endif
