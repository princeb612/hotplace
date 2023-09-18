/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2002.10.24   Soo Han, Kim        codename.hush2002
 * 2007.07.01   Soo Han, Kim        asynchronous query
 * 2009.11.06   Soo Han, Kim        unicode
 * 2023.09.07   Soo Han, Kim        refactor
 */

#ifndef __HOTPLACE_SDK_ODBC_RECORD__
#define __HOTPLACE_SDK_ODBC_RECORD__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/odbc/types.hpp>

namespace hotplace {
namespace odbc {

class odbc_field;
/**
 * @brief   record (tuple)
 */
class odbc_record
{
public:
    /**
     * @brief   constructor
     */
    odbc_record ();
    /**
     * @brief   destructor
     */
    ~odbc_record ();

    /**
     * @brief   operator <<
     * @param   odbc_field* pField  [in] 추가할 필드
     * @return
     * @sa
     * @remarks
     */
    odbc_record& operator << (odbc_field* pField);
    /**
     * @brief   추가된 모든 필드를 삭제한다.
     * @param
     * @return
     * @sa
     * @remarks
     */
    return_t clear ();

    /**
     * @brief   인덱스로 필드를 구한다.
     * @param   int         nIndex  [in] 인덱스
     * @return
     * @sa
     * @remarks
     */
    odbc_field* get_field (int nIndex);
    /**
     * @brief   필드 이름으로 필드를 구한다
     * @param   LPTSTR      tszName [in] 필드 이름
     * @return
     * @sa
     * @remarks
     */
    odbc_field* get_field (LPSTR tszName);
#if defined _UNICODE || defined UNICODE
    odbc_field* get_field (LPWSTR tszName);
#endif

    /**
     * @brief   레코드에 추가된 필드의 갯수
     * @param
     * @return
     * @sa
     * @remarks
     */
    int count (void);

    int addref ();
    int release ();

protected:

    typedef std::vector<odbc_field* > odbc_field_vector_t;
    odbc_field_vector_t _odbc_columns;       ///< row
    t_shared_reference <odbc_record> _shared;
};

}
}  // namespace

#endif
