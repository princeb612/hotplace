/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/openssl/openssl_hash.hpp>
#include <hotplace/sdk/crypto/otp/time_otp.hpp>

namespace hotplace {
namespace crypto {

#define TOTP_CONTEXT_SIGNATURE 0x20170703
typedef struct _TOTP_CONTEXT {
    uint32 _signature;
    void* _hotp_handle;
//time_t _init_time;
    time_t _interval;
} TOTP_CONTEXT;

time_otp::time_otp ()
{
    // do nothing
}

time_otp::~time_otp ()
{
    // do nothing
}

uint32 time_otp::open (void** handle, unsigned int digit_length, time_t interval, hash_algorithm_t algorithm,
                       const byte_t* key_data, size_t key_size)
{
    uint32 ret = errorcode_t::success;
    TOTP_CONTEXT* context = nullptr;
    hmac_otp hotp;
    void* hotp_handle = nullptr;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        ret = hotp.open (&hotp_handle, digit_length, algorithm, key_data, key_size);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        __try_new_catch (context, new TOTP_CONTEXT, ret, __leave2_trace (ret));

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

uint32 time_otp::close (void* handle)
{
    uint32 ret = errorcode_t::success;
    TOTP_CONTEXT* context = static_cast<TOTP_CONTEXT*>(handle);
    hmac_otp hotp;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (TOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
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

uint32 time_otp::get (void* handle, time64_t time, uint32& code)
{
    uint32 ret = errorcode_t::success;
    TOTP_CONTEXT* context = static_cast<TOTP_CONTEXT*>(handle);
    hmac_otp hotp;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
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

uint32 time_otp::verify (void* handle, time64_t time, uint32 code)
{
    uint32 ret = errorcode_t::success;
    TOTP_CONTEXT* context = static_cast<TOTP_CONTEXT*>(handle);

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }
        if (TOTP_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
        }

        uint32 result = 0;
        ret = get (handle, time, result);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
        if (code != result) {
            ret = errorcode_t::mismatch;
            __leave2_trace (ret);
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
