/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/base/error.hpp>

namespace hotplace {

#define errordef(e, msg) \
    { errorcode_t::e, #e, msg, }

const error_description error_descriptions[] = {
    errordef(success, "success"),
    errordef(internal_error, "internal error"),
    errordef(out_of_memory, "out of memory"),
    errordef(insufficient_buffer, "insufficient buffer"),
    errordef(invalid_parameter, "invalid parameter"),
    errordef(invalid_context, "invalid context"),
    errordef(invalid_pointer, "invalid pointer"),
    errordef(not_exist, "not exist"),
    errordef(not_found, "not found"),
    errordef(already_exist, "already exist"),
    errordef(already_assigned, "already assigned"),
    errordef(not_open, "not open"),
    errordef(not_available, "not available"),
    errordef(not_ready, "not ready"),
    errordef(no_init, "not initialized"),
    errordef(no_data, "no data"),
    errordef(bad_data, "bad data"),
    errordef(bad_format, "bad format"),
    errordef(more_data, "more data"),
    errordef(empty, "empty"),
    errordef(full, "full"),
    errordef(out_of_range, "out of range"),
    errordef(mismatch, "mismatch"),
    errordef(timeout, "timeout"),
    errordef(expired, "expired"),
    errordef(canceled, "canceled"),
    errordef(invalid_request, "invalid request"),  // RFC 6749 4.1.2.1. Error Response
    errordef(response, "response"),
    errordef(unexpected, "unexpected"),
    errordef(max_reached, "max reached"),
    errordef(failed, "failed"),
    errordef(blocked, "blocked"),
    errordef(pending, "pending"),
    errordef(closed, "closed"),
    errordef(disconnect, "disconnect"),
    errordef(error_cipher, "error cipher"),
    errordef(error_digest, "error digest"),
    errordef(error_verify, "error verify"),
    errordef(busy, "busy"),
    errordef(query, "query"),
    errordef(fetch, "fetch"),
    errordef(insufficient, "insufficient"),
    errordef(reserved, "reserved"),
    errordef(suspicious, "suspicious"),
    errordef(unknown, "unknown"),
    errordef(inaccurate, "inaccurate"),
    errordef(unauthorized_client, "unauthorized client"),                               // RFC 6749 4.1.2.1. Error Response
    errordef(access_denied, "access denied"),                                           // RFC 6749 4.1.2.1. Error Response
    errordef(unsupported_response_type, "unsupported response type"),                   // RFC 6749 4.1.2.1. Error Response
    errordef(invalid_scope, "The requested scope is invalid, unknown, or malformed."),  // RFC 6749 4.1.2.1. Error Response
    errordef(server_error, "server error"),                                             // RFC 6749 4.1.2.1. Error Response
    errordef(temporarily_unavailable, "temporarily unavailable"),                       // RFC 6749 4.1.2.1. Error Response
    errordef(invalid_client, "invalid_client"),                                         // RFC 6749 5.2. Error Response
    errordef(invalid_grant, "invalid_grant"),                                           // RFC 6749 5.2. Error Response
    errordef(unsupported_grant_type, "unsupported_grant_type"),                         // RFC 6749 5.2. Error Response
    errordef(assert_failed, "assert_failed"),
    errordef(not_supported, "not supported"),
    errordef(low_security, "low security"),
    errordef(debug, "debug"),
};

error_advisor error_advisor::_instance;

error_advisor::error_advisor() { build(); }

error_advisor* error_advisor::get_instance() { return &_instance; }

void error_advisor::build() {
    for (unsigned i = 0; i < RTL_NUMBER_OF(error_descriptions); i++) {
        const error_description* item = error_descriptions + i;
        _table.insert(std::make_pair(item->error, item));
    }
}

bool error_advisor::find(return_t error, const error_description** desc) {
    bool ret = false;

    __try2 {
        if (nullptr == desc) {
            __leave2;
        }

        error_description_map_t::iterator iter = _table.find(error);
        if (_table.end() != iter) {
            *desc = iter->second;
            ret = true;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool error_advisor::error_code(return_t error, std::string& code) {
    bool ret = false;
    code.clear();

    const error_description* item = nullptr;
    find(error, &item);
    if (item) {
        code = item->error_code;
        ret = true;
    }
    return ret;
}

bool error_advisor::error_message(return_t error, std::string& message) {
    bool ret = false;
    message.clear();

    const error_description* item = nullptr;
    find(error, &item);
    if (item) {
        message = item->error_message;
        ret = true;
    }
    return ret;
}

}  // namespace hotplace
