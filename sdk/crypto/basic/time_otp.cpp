/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/hmac_otp.hpp>
#include <hotplace/sdk/crypto/basic/time_otp.hpp>

namespace hotplace {
namespace crypto {

#define TOTP_CONTEXT_SIGNATURE 0x20170703
typedef struct _totp_context_t : public otp_context_t {
    uint32 _signature;
    otp_context_t* _hotp_handle;
    time_t _interval;
} totp_context_t;

time_otp::time_otp ()
{
    // do nothing
}

time_otp::~time_otp ()
{
    // do nothing
}

uint32 time_otp::open (otp_context_t** handle, unsigned int digit_length, time_t interval, hash_algorithm_t algorithm,
                       const byte_t* key_data, size_t key_size)
{
    uint32 ret = errorcode_t::success;
    totp_context_t* context = nullptr;
    hmac_otp hotp;
    otp_context_t* hotp_handle = nullptr;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = hotp.open (&hotp_handle, digit_length, algorithm, key_data, key_size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        __try_new_catch (context, new totp_context_t, ret, __leave2);

        context->_signature = TOTP_CONTEXT_SIGNATURE;
        context->_hotp_handle = hotp_handle;
        //context->_init_time = time(nullptr);
        if (0 == interval) {
            context->_interval = 1;
        } else {
            context->_interval = interval;
        }

        *handle = context;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != hotp_handle) {
                hotp.close (hotp_handle);
            }
            if (nullptr != context) {
                delete context;
            }
        }
    }
    return ret;
}

uint32 time_otp::close (otp_context_t* handle)
{
    uint32 ret = errorcode_t::success;
    totp_context_t* context = static_cast<totp_context_t*>(handle);
    hmac_otp hotp;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (TOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (nullptr != context->_hotp_handle) {
            hotp.close (context->_hotp_handle);
        }
        delete context;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

uint32 time_otp::get (otp_context_t* handle, time64_t time, uint32& code)
{
    uint32 ret = errorcode_t::success;
    totp_context_t* context = static_cast<totp_context_t*>(handle);
    hmac_otp hotp;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (TOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
        }

        uint32 c = (time / context->_interval);

        hotp.get (context->_hotp_handle, c, code);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

uint32 time_otp::verify (otp_context_t* handle, time64_t time, uint32 code)
{
    uint32 ret = errorcode_t::success;
    totp_context_t* context = static_cast<totp_context_t*>(handle);

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (TOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
        }

        uint32 result = 0;
        ret = get (handle, time, result);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (code != result) {
            ret = errorcode_t::mismatch;
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
