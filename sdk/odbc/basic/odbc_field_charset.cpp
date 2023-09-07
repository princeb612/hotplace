/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/basic/base16.hpp>
#include <hotplace/sdk/io/system/datetime.hpp>
#include <hotplace/sdk/odbc/basic/odbc_field.hpp>

namespace hotplace {
using namespace io;
namespace odbc {

#if defined _MBCS || defined MBCS
const char* odbc_field::as_string (ansi_string& str, UINT nCodePage)
#elif defined _UNICODE || defined UNICODE
const wchar_t* odbc_field::as_string (wide_string& str, UINT nCodePage)
#endif
{
    str = _T ("");
    TCHAR tchTemp[256];
    tchTemp[0] = 0;
    switch (_data_type) {
        case SQL_ARD_TYPE:      /* -99 */
        case SQL_LONGVARCHAR:   /* -1 */
        case SQL_VARCHAR:       /* 12 */
        case SQL_CHAR:          /* 1 */
        case -370:              /* SQL_XML */
#if defined _MBCS || defined MBCS
            if (nullptr != _field_data.p) {
                str = (LPTSTR) _field_data.p;
            } else {
                str = _T ("");
            }
#elif defined _UNICODE || defined UNICODE
            {
                ((LPSTR) _field_data.p)[_column_size] = 0;
                A2W (str, (LPSTR) _field_data.p, nCodePage);
            }
#endif
            break;
        case SQL_WLONGVARCHAR:          /* -10 */
        case SQL_WVARCHAR:              /* -9  */
        case SQL_WCHAR:                 /* -8  */
#if (ODBCVER <= 0x0300)
        case SQL_UNICODE:               /* -95 */
        case SQL_UNICODE_VARCHAR:       /* -96 */
        case SQL_UNICODE_LONGVARCHAR:   /* -97 */
#else
        case -95:
        case -96:
        case -97:
#endif
#if defined _WIN32 || defined _WIN64
#if defined _MBCS || defined MBCS
            {
                ((LPSTR) _field_data.p)[_column_size] = 0;
                W2A (str, (LPWSTR) _field_data.p, nCodePage);
            }
#elif defined _UNICODE || defined UNICODE
            UNREFERENCED_PARAMETER (nCodePage);
            if (nullptr != _field_data.p) {
                str = (LPTSTR) _field_data.p;
            } else {
                str = _T ("");
            }
#endif
#else
            //ret = ERROR_NOT_SUPPORTED;
#endif
            break;
        case SQL_BIT:       /* -7 */
        case SQL_TINYINT:   /* -6 */
        case SQL_NUMERIC:   /*  2 */
        case SQL_DECIMAL:   /*  3 */
        case SQL_INTEGER:   /*  4 */
        case SQL_SMALLINT:  /*  5 */
#if defined __linux__
            _sntprintf (tchTemp, 10, _T ("%d"), _field_data.i);
#else
#ifdef __STDC_WANT_SECURE_LIB__
            _itot_s (_field_data.i, tchTemp, RTL_NUMBER_OF (tchTemp), 10);
#else
            _itot (_field_data.i, tchTemp, 10);
#endif
#endif
            str = tchTemp;
            break;
        case SQL_FLOAT:     /*  6 */
            _sntprintf (tchTemp, RTL_NUMBER_OF (tchTemp), _T ("%f"), _field_data.f);
            str = tchTemp;
            break;
        case SQL_REAL:      /*  7 */
            _sntprintf (tchTemp, RTL_NUMBER_OF (tchTemp), _T ("%lf"), _field_data.d);
            str = tchTemp;
            break;
        case SQL_BIGINT:    /* -5 */
        case SQL_DOUBLE:    /*  8 */
            _sntprintf (tchTemp, RTL_NUMBER_OF (tchTemp), _T ("%lf"), _field_data.d);
            str = tchTemp;
            break;
        case SQL_LONGVARBINARY: /* -4 */
        case SQL_VARBINARY:     /* -3 */
        case SQL_BINARY:        /* -2 */
        {
            std::string temp;
            base16_encode (static_cast<const byte_t *>(_field_data.p), _column_size, temp);
            str = temp.c_str ();
        }
        break;
        case SQL_DATETIME:          /* 9 */
        case SQL_TIME:              /* 10 */
        case SQL_TIMESTAMP:         /* 11 */
#if (ODBCVER >= 0x0300)
        case SQL_TYPE_DATE:         /* 91 */
        case SQL_TYPE_TIME:         /* 92 */
        case SQL_TYPE_TIMESTAMP:    /* 93 */
#else
        case 91:
        case 92:
        case 93:
#endif
            {
                datetime_t dt;
                _datetime.getlocaltime (&dt);
                /* _T("%d-%02d-%02d %02d:%02d:%02d.%d") */
                TCHAR TSTRING_FORMAT_DATETIME_YMD[] = { _T ('%'), _T ('d'), _T ('-'), _T ('%'), _T ('0'), _T ('2'), _T ('d'), _T ('-'), _T ('%'), _T ('0'), _T ('2'), _T ('d'), _T (' '), _T ('%'), _T ('0'), _T ('2'), _T ('d'), _T (':'), _T ('%'), _T ('0'), _T ('2'), _T ('d'), _T (':'), _T ('%'), _T ('0'), _T ('2'), _T ('d'), _T ('.'), _T ('%'), _T ('d'), 0, };
                TCHAR tchDate [256];
                _sntprintf (tchDate, 256, TSTRING_FORMAT_DATETIME_YMD,
                            dt.year, dt.month, dt.day,
                            dt.hour, dt.minute, dt.second, dt.milliseconds / 1000000);
                str = tchDate;
            }
            break;
        default:
            if (nullptr != _field_data.p) {
                str = (LPTSTR) _field_data.p;
            } else {
                str = _T ("");
            }
            break;
    }
    return str.c_str ();
}

#if defined _MBCS || defined MBCS
const char* odbc_field::get_field_name (ansi_string& str)
#elif defined _UNICODE || defined UNICODE
const wchar_t* odbc_field::get_field_name (wide_string& str)
#endif
{
    str = _T ("");
    if (nullptr == _field_info) {
        as_string (str);
    } else {
        _field_info->as_string (str);
    }
    return str.c_str ();
}

}
}  // namespace
