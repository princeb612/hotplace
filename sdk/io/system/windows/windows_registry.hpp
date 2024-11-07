/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_REGISTRY__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_REGISTRY__

#include <sdk/base/callback.hpp>
#include <sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

#define DELTRYCOUNTMAX 5

enum registry_option_t {
    delete_sub_keys = 1,
};

typedef struct _ENUM_VALUE_CONTEXTA {
    LPSTR tszValue;
    DWORD dwValueSize;
    DWORD dwType;
    LPBYTE pData;
    DWORD dwDataSize;
} ENUM_VALUE_CONTEXTA;
typedef struct _ENUM_VALUE_CONTEXTW {
    LPWSTR tszValue;
    DWORD dwValueSize;
    DWORD dwType;
    LPBYTE pData;
    DWORD dwDataSize;
} ENUM_VALUE_CONTEXTW;

#if defined _MBCS || defined MBCS
#define ENUM_VALUE_CONTEXT ENUM_VALUE_CONTEXTA
#elif defined _UNICODE || defined UNICODE
#define ENUM_VALUE_CONTEXT ENUM_VALUE_CONTEXTW
#endif

class windows_registry {
   public:
    /**
     * @brief   constructor
     */
    windows_registry();
    /**
     * @brief   destructor
     */
    virtual ~windows_registry();

    /**
     * @brief   CreateKey
     * @param   PHKEY                   pkey        [OUT] key
     * @param   HKEY                    hrootkey    [IN] root
     * @param   LPCTSTR                 sub_key     [IN] sub
     * @param   REGSAM                  regsam      [INOPT]
     * @param   return_t                option      [INOPT]
     * @param   LPSECURITY_ATTRIBUTES   attrib      [INOPT]
     * @return
     * @sa
     * @remarks
     */
    return_t create_key(PHKEY pkey, HKEY hrootkey, const char *sub_key, REGSAM regsam = KEY_CREATE_SUB_KEY, DWORD option = REG_OPTION_NON_VOLATILE,
                        LPSECURITY_ATTRIBUTES attrib = nullptr);
    return_t create_key(PHKEY pkey, HKEY hrootkey, const wchar_t *sub_key, REGSAM regsam = KEY_CREATE_SUB_KEY, DWORD option = REG_OPTION_NON_VOLATILE,
                        LPSECURITY_ATTRIBUTES attrib = nullptr);
    /**
     * @brief   OpenKey
     * @param   PHKEY                   pkey        [OUT] key
     * @param   HKEY                    hrootkey    [IN] root
     * @param   LPCTSTR                 sub_key     [IN] sub
     * @param   REGSAM                  regsam      [INOPT]
     * @return
     * @sa
     * @remarks
     */
    return_t open_key(PHKEY pkey, HKEY hrootkey, const char *sub_key, REGSAM regsam = KEY_READ);
    return_t open_key(PHKEY pkey, HKEY hrootkey, const wchar_t *sub_key, REGSAM regsam = KEY_READ);
    /**
     * @brief   CloseKey
     * @param   HKEY                    hkey                [IN] key
     * @return
     * @sa
     * @remarks
     */
    return_t close_key(HKEY hkey);

    /**
     * @brief   enum
     * @param   HKEY                    hkey
     * @param   ENUM_CALLBACK_HANDLER   callback_handler
     * @param   void*                   param
     * @remarks
     *          return_t enum_subkeys_handler(LPCTSTR key_name, void* param, void* context)
     *          {
     *              return_t ret = errorcode_t::success;
     *              DEBUG_PRINT(_T("\t%s\n"), key_name);
     *              return ret;
     *          }
     *
     *          ret = reg.open_key(&hkey, HKEY_LOCAL_MACHINE, REGPATH_SOFTWARE, KEY_ENUMERATE_SUB_KEYS|KEY_QUERY_VALUE);
     *          reg.enumerate_subkeys(hkey, enum_subkeys_handler, nullptr);
     */
    return_t enumerate_subkeys(HKEY hkey, ENUM_CALLBACK_HANDLERA callback_handler, void *param);
    return_t enumerate_subkeys(HKEY hkey, ENUM_CALLBACK_HANDLERW callback_handler, void *param);

    /**
     * @brief   enum
     * @param   HKEY                    hkey
     * @param   ENUM_CALLBACK_HANDLER   callback_handler
     * @param   void*                   param
     * @return
     * @remarks
     *          return_t enum_values_handler(LPCTSTR name, void* param, void* context)
     *          {
     *              return_t ret = errorcode_t::success;
     *              ENUM_VALUE_CONTEXT* pContext = static_cast<ENUM_VALUE_CONTEXT*>(context);
     *              if(REG_SZ == pContext->type)
     *              {
     *                  DEBUG_PRINT(_T("\t%s = %s\n"), name, pContext->pData);
     *              }
     *              return ret;
     *          }
     *          reg.enumerate_values(hkey, enum_values_handler, nullptr);
     */
    return_t enumerate_values(HKEY hkey, ENUM_CALLBACK_HANDLERA callback_handler, void *param);
    return_t enumerate_values(HKEY hkey, ENUM_CALLBACK_HANDLERW callback_handler, void *param);

    /**
     * @brief   RegSetValueEx
     * @param   HKEY                    hkey        [IN] key
     * @param   LPCTSTR                 value       [IN] value
     * @param   LPCTSTR                 data        [IN] data
     * @return
     * @sa
     * @remarks
     */
    return_t set_string(HKEY hkey, const char *value, const char *data);
    return_t set_string(HKEY hkey, const wchar_t *value, const wchar_t *data);
    /**
     * @brief   RegSetValueEx
     * @param   HKEY                    hkey        [IN] key
     * @param   LPCTSTR                 value       [IN] value
     * @param   DWORD                   type        [IN] type
     * @param   void*                   data        [IN] data
     * @param   DWORD                   size        [IN] data size
     * @return
     * @sa
     * @remarks
     */
    return_t set_value(HKEY hkey, const char *value, DWORD type, void *data, DWORD size);
    return_t set_value(HKEY hkey, const wchar_t *value, DWORD type, void *data, DWORD size);
    /**
     * @brief   RegQueryValueEx
     * @param   HKEY                    hkey        [IN] key
     * @param   LPCTSTR                 value       [IN] value
     * @param   LPDWORD                 type_ptr    [IN] type
     * @param   void*                   data        [OUT] data
     * @param   LPDWORD                 data_ptr    [OUT] data size
     * @return
     * @sa
     * @remarks
     *          DWORD type = 0;
     *          TCHAR data[(1 << 12)];
     *          DWORD size = sizeof(data); // cb size
     *          reg.query_value(hkey, value, &type, data, &data);
     */
    return_t query_value(HKEY hkey, const char *value, LPDWORD type_ptr, void *data, LPDWORD data_ptr);
    return_t query_value(HKEY hkey, const wchar_t *value, LPDWORD type_ptr, void *data, LPDWORD data_ptr);
    /**
     * @brief   RegQueryValueEx
     * @param   HKEY                    hkey        [IN] key
     * @param   LPCTSTR                 value       [IN] value
     * @return
     * @sa
     * @remarks
     */
    return_t delete_value(HKEY hkey, const char *value);
    return_t delete_value(HKEY hkey, const wchar_t *value);
    /**
     * @brief
     * @param   HKEY                    hrootkey    [IN] root
     * @param   LPCTSTR                 sub_key     [IN] sub
     * @param   DWORD                   option      [IN] option
     *          registry_option_t::delete_sub_keys
     * @return
     * @sa
     * @remarks
     */
    return_t delete_key(HKEY hrootkey, const char *sub_key, DWORD option);
    return_t delete_key(HKEY hrootkey, const wchar_t *sub_key, DWORD option);
    /*
     * @brief   delete sub keys
     * @param   HKEY    hrootkey    [IN]
     * @param   LPCTSTR sub_key     [IN]
     * @remarks
     */
    return_t delete_sub_nodes(HKEY hrootkey, const char *sub_key);
    return_t delete_sub_nodes(HKEY hrootkey, const wchar_t *sub_key);

   protected:
};

}  // namespace io
}  // namespace hotplace

#endif
