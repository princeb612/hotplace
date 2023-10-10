/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/odbc/basic/odbc_field.hpp>

namespace hotplace {
namespace odbc {

//  #define SQL_UNKNOWN_TYPE        0
//  #define SQL_CHAR                1
//  #define SQL_NUMERIC             2
//  #define SQL_DECIMAL             3
//  #define SQL_INTEGER             4
//  #define SQL_SMALLINT            5
//  #define SQL_FLOAT               6
//  #define SQL_REAL                7
//  #define SQL_DOUBLE              8
//  #define SQL_DATETIME            9
//  #define SQL_TIME                10
//  #define SQL_TIMESTAMP           11
//  #define SQL_VARCHAR             12
//  #define SQL_TYPE_DATE           91
//  #define SQL_TYPE_TIME           92
//  #define SQL_TYPE_TIMESTAMP      93
//
//  #define SQL_LONGVARCHAR         (-1)
//  #define SQL_BINARY              (-2)
//  #define SQL_VARBINARY           (-3)
//  #define SQL_LONGVARBINARY       (-4)
//  #define SQL_BIGINT              (-5)
//  #define SQL_TINYINT             (-6)
//  #define SQL_BIT                 (-7)
//  #define SQL_WCHAR               (-8)
//  #define SQL_WVARCHAR            (-9)
//  #define SQL_WLONGVARCHAR        (-10)
//  #define SQL_GUID                (-11)
//  #define SQL_UNICODE             (-95)
//  #define SQL_UNICODE_VARCHAR     (-96)
//  #define SQL_UNICODE_LONGVARCHAR (-97)
//
//  #define SQL_DECFLOAT            (-360)

odbc_field::odbc_field(int index, int data_type, int column_type, int column_size, unsigned char* column_data, odbc_field* field_info)
    : _index(index), _data_type(data_type), _column_type(column_type), _column_size(column_size), _field_info(field_info) {
    _shared.make_share(this);

    _field_data.p = nullptr;

    switch (data_type) {
        case SQL_ARD_TYPE:    /* -99 */
        case SQL_LONGVARCHAR: /* -1 */
        case SQL_VARCHAR:     /* 12 */
        case SQL_CHAR:        /* 1 */
        case -370:            /* SQL_XML */
        {
            size_t size = column_size + sizeof(TCHAR);
            void* ptr = malloc(size);
            if (nullptr == ptr) {
                throw errorcode_t::out_of_memory;
            } else {
                memcpy_inline(ptr, column_size, column_data, column_size);
                memset((unsigned char*)ptr + column_size, 0, sizeof(TCHAR));
                _field_data.p = ptr;
            }
        } break;
        case SQL_WLONGVARCHAR: /* -10 */
        case SQL_WVARCHAR:     /* -9  */
        case SQL_WCHAR:        /* -8  */
#if (ODBCVER <= 0x0300)
        case SQL_UNICODE:             /* -95 */
        case SQL_UNICODE_VARCHAR:     /* -96 */
        case SQL_UNICODE_LONGVARCHAR: /* -97 */
#else
        case -95:
        case -96:
        case -97:
#endif
            if (column_size > 0) {
                size_t size = column_size + sizeof(WCHAR);  // cbSize
                void* ptr = malloc(size);
                if (nullptr == ptr) {
                    throw errorcode_t::out_of_memory;
                } else {
                    memcpy_inline(ptr, size, column_data, size);
                    memset((unsigned char*)ptr + column_size, 0, sizeof(WCHAR));
                    _field_data.p = ptr;
                }
            }
            break;
        case SQL_LONGVARBINARY: /* -4 */
        case SQL_VARBINARY:     /* -3  */
        case SQL_BINARY:        /* -2  */
        {
            size_t size = column_size;
            void* ptr = malloc(size);
            if (nullptr == ptr) {
                throw errorcode_t::out_of_memory;
            } else {
                memcpy_inline(ptr, column_size, column_data, column_size);
                _field_data.p = ptr;
            }
        } break;
        case SQL_BIT: /* -7 */
            _field_data.i = *reinterpret_cast<bool*>(column_data);
            break;
        case SQL_TINYINT:  /* -6 */
        case SQL_NUMERIC:  /*  2 */
        case SQL_DECIMAL:  /*  3 */
        case SQL_INTEGER:  /*  4 */
        case SQL_SMALLINT: /*  5 */
            _field_data.i = *reinterpret_cast<int*>(column_data);
            break;
        case SQL_FLOAT: /*  6 */
            _field_data.f = *reinterpret_cast<float*>(column_data);
            break;
        case SQL_BIGINT: /* -5 */
        case SQL_REAL:   /*  7 */
        case SQL_DOUBLE: /*  8 */
            _field_data.d = *reinterpret_cast<double*>(column_data);
            break;
        case SQL_DATETIME:  /* 9 */
        case SQL_TIME:      /* 10 */
        case SQL_TIMESTAMP: /* 11 */
#if (ODBCVER >= 0x0300)
        case SQL_TYPE_DATE:      /* 91 */
        case SQL_TYPE_TIME:      /* 92 */
        case SQL_TYPE_TIMESTAMP: /* 93 */
#else
        case 91:
        case 92:
        case 93:
#endif
            _datetime = *(datetime_t*)column_data;
            break;
        default:
            break;
    }
}

odbc_field::~odbc_field() {
    if (nullptr != _field_data.p) {
        switch (_data_type) {
            case SQL_ARD_TYPE:     /* -99 */
            case SQL_LONGVARCHAR:  /* -1 */
            case SQL_VARCHAR:      /* 12 */
            case SQL_CHAR:         /* 1 */
            case SQL_WLONGVARCHAR: /* -10 */
            case SQL_WVARCHAR:     /* -9  */
            case SQL_WCHAR:        /* -8  */
#if (ODBCVER <= 0x0300)
            case SQL_UNICODE:             /* -95 */
            case SQL_UNICODE_VARCHAR:     /* -96 */
            case SQL_UNICODE_LONGVARCHAR: /* -97 */
#else
            case -95:
            case -96:
            case -97:
#endif
            case SQL_VARBINARY: /* -3  */
            case SQL_BINARY:    /* -2  */
            case -370:          /* SQL_XML */
                free(_field_data.p);
                _field_data.p = nullptr;
                break;
            case SQL_BIT:      /* -7  */
            case SQL_TINYINT:  /* -6  */
            case SQL_INTEGER:  /*  4  */
            case SQL_SMALLINT: /*  5  */
            case SQL_DOUBLE:   /*  8  */
                /* do nothing - using m_nData */
                break;
            case SQL_TIMESTAMP: /* 11  */
                /* do nothing - using _datetime */
                break;
            default:
                break;
        }
    }
}

int odbc_field::as_integer() {
    int lRet = 0;

    switch (_data_type) {
        case SQL_BIT:      /* -7  */
        case SQL_TINYINT:  /* -6  */
        case SQL_INTEGER:  /*  4  */
        case SQL_SMALLINT: /*  5  */
            lRet = _field_data.i;
            break;
        case SQL_DOUBLE: /*  8  */
            lRet = (int)_field_data.d;
            break;
        case SQL_VARBINARY: /* -3  */
        case SQL_BINARY:    /* -2  */
        case SQL_TIMESTAMP: /* 11  */
            break;
        default:
            lRet = (int)_ttol((LPTSTR)_field_data.p);
    }
    return lRet;
}

double odbc_field::as_double() {
    double lRet = 0;

    switch (_data_type) {
        case SQL_BIT:      /* -7  */
        case SQL_TINYINT:  /* -6  */
        case SQL_INTEGER:  /*  4  */
        case SQL_SMALLINT: /*  5  */
            lRet = _field_data.i;
            break;
        case SQL_DOUBLE: /*  8  */
            lRet = _field_data.d;
            break;
        case SQL_VARBINARY: /* -3  */
        case SQL_BINARY:    /* -2  */
        case SQL_TIMESTAMP: /* 11  */
            break;
        default:
            lRet = _ttol((LPTSTR)_field_data.p);
    }
    return lRet;
}

int odbc_field::addref() { return _shared.addref(); }

int odbc_field::release() { return _shared.delref(); }

}  // namespace odbc
}  // namespace hotplace
