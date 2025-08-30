/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <math.h>

#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/qpack/qpack_encoder.hpp>

namespace hotplace {
namespace net {

return_t qpack_ric2eic(size_t capacity, size_t ric, size_t base, size_t& eic, bool& sign, size_t& deltabase) {
    return_t ret = errorcode_t::success;
    if (capacity) {
        /* RFC 9204 4.5.1.1.  Required Insert Count
         *  if (ReqInsertCount) EncInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1
         *  else EncInsertCount = 0;
         */
        if (0 == ric) {
            eic = ric;
        } else {
            size_t maxentries = ::floor(capacity / 32);
            eic = (ric % (2 * maxentries)) + 1;
        }

        /* RFC 9204 4.5.1.2.  Base
         *  A Sign bit of 1 indicates that the Base is less than the Required Insert Count
         *
         *  if (0 == Sign) DeltaBase = Base - ReqInsertCount
         *  else DeltaBase = ReqInsertCount - Base - 1
         */
        sign = (ric > base);
        if (ric > base) {
            deltabase = ric - base - 1;
        } else {
            deltabase = ric - base;
        }
    } else {
        eic = 0;
        sign = false;
        deltabase = 0;
    }

    return ret;
}

return_t qpack_eic2ric(size_t capacity, size_t tni, size_t eic, bool sign, size_t deltabase, size_t& ric, size_t& base) {
    return_t ret = errorcode_t::success;
    __try2 {
        ric = 0;
        base = 0;

        if (0 == capacity) {
            __leave2;
        }

        /**
         * RFC 9204 4.5.1.1.  Required Insert Count
         *
         * FullRange = 2 * MaxEntries
         * if EncodedInsertCount == 0:
         *    ReqInsertCount = 0
         * else:
         *    if EncodedInsertCount > FullRange:
         *       Error
         *    MaxValue = TotalNumberOfInserts + MaxEntries
         *
         *    # MaxWrapped is the largest possible value of
         *    # ReqInsertCount that is 0 mod 2 * MaxEntries
         *    MaxWrapped = floor(MaxValue / FullRange) * FullRange
         *    ReqInsertCount = MaxWrapped + EncodedInsertCount - 1
         *
         *    # If ReqInsertCount exceeds MaxValue, the Encoder's value
         *    # must have wrapped one fewer time
         *    if ReqInsertCount > MaxValue:
         *       if ReqInsertCount <= FullRange:
         *          Error
         *       ReqInsertCount -= FullRange
         *
         *    # Value of 0 must be encoded as 0.
         *    if ReqInsertCount == 0:
         *       Error
         */
        size_t maxentries = ::floor(capacity / 32);
        size_t fullrange = 2 * maxentries;
        if (0 == eic) {
            ric = 0;
        } else {
            if (eic > fullrange) {
                ret = errorcode_t::invalid_request;
                __leave2;
            }

            size_t maxvalue = tni + maxentries;
            size_t maxwrapped = ::floor(maxvalue / fullrange) * fullrange;
            ric = maxwrapped + eic - 1;

            if (ric > maxvalue) {
                if (ric <= fullrange) {
                    ret = errorcode_t::invalid_request;
                    __leave2;
                } else {
                    ric -= fullrange;
                }
            }

            if (0 == ric) {
                ret = errorcode_t::invalid_request;
                __leave2;
            }

            /* RFC 9204 4.5.1.2.  Base
             *  A Sign bit of 1 indicates that the Base is less than the Required Insert Count
             *
             *  if (0 == Sign) Base = DeltaBase + ReqInsertCount
             *  else Base = ReqInsertCount - DeltaBase - 1
             */
            if (0 == sign) {
                base = deltabase + ric;
            } else {
                base = ric - deltabase - 1;
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
