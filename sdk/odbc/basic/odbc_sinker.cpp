/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/stream/string.hpp>
#include <hotplace/sdk/odbc/basic/odbc_diagnose.hpp>
#include <hotplace/sdk/odbc/basic/odbc_query.hpp>

namespace hotplace {
namespace odbc {

odbc_sinker::odbc_sinker(odbc_query* dbquery, uint32 tmo_seconds) : _dbquery(dbquery), _tmo_seconds(tmo_seconds) {
    if (nullptr == dbquery) {
        throw errorcode_t::insufficiency;
    }

    time_monotonic(_timestamp);
}

odbc_sinker::~odbc_sinker() { _dbquery->release(); }

return_t odbc_sinker::ready() {
    return_t ret = errorcode_t::busy;

    sql_query_mode_t mode = _dbquery->mode();

    if (sql_query_mode_t::async_query == mode) {
        ret = _dbquery->execute_statement();
        if (errorcode_t::busy == ret) {
            struct timespec now;
            struct timespec diff;

            time_monotonic(now);
            time_diff(diff, _timestamp, now);

            if (diff.tv_sec > _tmo_seconds) {
                ret = errorcode_t::timeout;

                _dbquery->close();  // cancel
            }
        }
    } else {  // sql_query_mode_t::sync_query
        ret = errorcode_t::success;
    }

    return ret;
}

}  // namespace odbc
}  // namespace hotplace
