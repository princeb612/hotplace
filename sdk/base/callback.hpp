/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_CALLBACK__
#define __HOTPLACE_SDK_BASE_CALLBACK__

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/types.hpp>

namespace hotplace {

typedef return_t (*CALLBACK_HANDLER)(void* data, void* parameter);
typedef return_t (*TYPE_CALLBACK_HANDLER)(uint32 type, void* data, void* parameter);

enum CALLBACK_CONTROL {
    CONTINUE_CONTROL,
    STOP_CONTROL,
};

typedef return_t (*TYPE_CALLBACK_HANDLEREXV)(uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* parameter);

/**
 * @brief   enumerate
 * @param   LPCTSTR    name     [IN]
 * @param   void*      parameter [IN]
 * @param   void*      context   [IN]
 */
#if defined _MBCS || defined MBCS
#define ENUM_CALLBACK_HANDLER ENUM_CALLBACK_HANDLERA
#elif defined _UNICODE || defined UNICODE
#define ENUM_CALLBACK_HANDLER ENUM_CALLBACK_HANDLERW
#endif
typedef return_t (*ENUM_CALLBACK_HANDLERA)(const char* name, void* parameter, void* context);
typedef return_t (*ENUM_CALLBACK_HANDLERW)(const wchar_t* name, void* parameter, void* context);

/**
 * @brief   enumerate by type
 * @param   LPCTSTR    name     [IN]
 * @param   intptr_t   type      [IN]
 * @param   void*      parameter [IN]
 * @param   void*      context   [IN]
 */
#if defined _MBCS || defined MBCS
#define ENUMTYPE_CALLBACK_HANDLER ENUMTYPE_CALLBACK_HANDLERA
#elif defined _UNICODE || defined UNICODE
#define ENUMTYPE_CALLBACK_HANDLER ENUMTYPE_CALLBACK_HANDLERW
#endif
typedef return_t (*ENUMTYPE_CALLBACK_HANDLERA)(const char* name, intptr_t type, void* parameter, void* context);
typedef return_t (*ENUMTYPE_CALLBACK_HANDLERW)(const wchar_t* name, intptr_t type, void* parameter, void* context);

typedef return_t (*THREAD_CALLBACK_ROUTINE)(void*);

}  // namespace hotplace

#endif
