
/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_CALLBACK__
#define __HOTPLACE_SDK_BASE_CALLBACK__

//#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <hotplace/sdk/base/error.hpp>

namespace hotplace {
namespace io {

typedef return_t (*TYPE_CALLBACK_HANDLER)(uint32 type, void* data, void* parameter);

enum CALLBACK_CONTROL {
    CONTINUE_CONTROL,
    STOP_CONTROL,
};

typedef return_t (*TYPE_CALLBACK_HANDLEREXV)(uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* parameter);

/**
 * @brief   enumerate
 * @param   LPCTSTR     tszName     [IN]
 * @param   void*      lpParameter [IN]
 * @param   void*      lpContext   [IN]
 */
#if defined _MBCS || defined MBCS
#define ENUM_CALLBACK_HANDLER ENUM_CALLBACK_HANDLERA
#elif defined _UNICODE || defined UNICODE
#define ENUM_CALLBACK_HANDLER ENUM_CALLBACK_HANDLERW
#endif
typedef return_t (* ENUM_CALLBACK_HANDLERA)(const char* tszName, void* lpParameter, void* lpContext);
typedef return_t (* ENUM_CALLBACK_HANDLERW)(const wchar_t* tszName, void* lpParameter, void* lpContext);

/**
 * @brief   enumerate by type
 * @param   LPCTSTR     tszName     [IN]
 * @param   intptr_t    dwType      [IN]
 * @param   void*      lpParameter [IN]
 * @param   void*      lpContext   [IN]
 */
#if defined _MBCS || defined MBCS
#define ENUMTYPE_CALLBACK_HANDLER ENUMTYPE_CALLBACK_HANDLERA
#elif defined _UNICODE || defined UNICODE
#define ENUMTYPE_CALLBACK_HANDLER ENUMTYPE_CALLBACK_HANDLERW
#endif
typedef return_t (* ENUMTYPE_CALLBACK_HANDLERA)(const char* tszName, intptr_t dwType, void* lpParameter, void* lpContext);
typedef return_t (* ENUMTYPE_CALLBACK_HANDLERW)(const wchar_t* tszName, intptr_t dwType, void* lpParameter, void* lpContext);

typedef return_t (*THREAD_CALLBACK_ROUTINE)(void*);

}
}  // namespace

#endif
