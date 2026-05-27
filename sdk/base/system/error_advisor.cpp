/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   error_advisor.cpp
 * @author Soo Han Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.05.26   Soo Han and Gemini  refactoring
 */

#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/base/system/error.hpp>

namespace hotplace {

#define errordef(e, msg) \
    {                    \
        errorcode_t::e,  \
        #e,              \
        msg,             \
    }

// errno    strerror(errno)
// EAI_     gai_strerror(ret)

const error_description error_descriptions[] = {
#if defined __linux__
    errordef(eperm, "Operation not permitted"),
    errordef(enoent, "No such file or directory"),
    errordef(esrch, "No such process"),
    errordef(eintr, "Interrupted system call"),
    errordef(eio, "I/O error"),
    errordef(enxio, "No such device or address"),
    errordef(e2big, "Argument list too long"),
    errordef(enoexec, "Exec format error"),
    errordef(ebadf, "Bad file number"),
    errordef(echild, "No child processes"),
    errordef(eagain, "Try again"),
    errordef(enomem, "Out of memory"),
    errordef(eacces, "Permission denied"),
    errordef(efault, "Bad address"),
    errordef(enotblk, "Block device required"),
    errordef(ebusy, "Device or resource busy"),
    errordef(eexist, "File exists"),
    errordef(exdev, "Cross-device link"),
    errordef(enodev, "No such device"),
    errordef(enotdir, "Not a directory"),
    errordef(eisdir, "Is a directory"),
    errordef(einval, "Invalid argument"),
    errordef(enfile, "File table overflow"),
    errordef(emfile, "Too many open files"),
    errordef(enotty, "Not a typewriter"),
    errordef(etxtbsy, "Text file busy"),
    errordef(efbig, "File too large"),
    errordef(enospc, "No space left on device"),
    errordef(espipe, "Illegal seek"),
    errordef(erofs, "Read-only file system"),
    errordef(emlink, "Too many links"),
    errordef(epipe, "Broken pipe"),
    errordef(edom, "Math argument out of domain of func"),
    errordef(erange, "Math result not representable"),
    errordef(edeadlk, "Resource deadlock would occur"),
    errordef(enametoolong, "File name too long"),
    errordef(enolck, "No record locks available"),
    errordef(enosys, "Function not implemented"),
    errordef(enotempty, "Directory not empty"),
    errordef(eloop, "Too many symbolic links encountered"),
    errordef(ewouldblock, "errno 11 EAGAIN"),
    errordef(enomsg, "No message of desired type"),
    errordef(eidrm, "Identifier removed"),
    errordef(echrng, "Channel number out of range"),
    errordef(el2nsync, "Level 2 not synchronized"),
    errordef(el3hlt, "Level 3 halted"),
    errordef(el3rst, "Level 3 reset"),
    errordef(elnrng, "Link number out of range"),
    errordef(eunatch, "Protocol driver not attached"),
    errordef(enocsi, "No CSI structure available"),
    errordef(el2hlt, "Level 2 halted"),
    errordef(ebade, "Invalid exchange"),
    errordef(ebadr, "Invalid request descriptor"),
    errordef(exfull, "Exchange full"),
    errordef(enoano, "No anode"),
    errordef(ebadrqc, "Invalid request code"),
    errordef(ebadslt, "Invalid slot"),
    errordef(edeadlock, "errno 35 EDEADLK"),
    errordef(ebfont, "Bad font file format"),
    errordef(enostr, "Device not a stream"),
    errordef(enodata, "No data available"),
    errordef(etime, "Timer expired"),
    errordef(enosr, "Out of streams resources"),
    errordef(enonet, "Machine is not on the network"),
    errordef(enopkg, "Package not installed"),
    errordef(eremote, "Object is remote"),
    errordef(enolink, "Link has been severed"),
    errordef(eadv, "Advertise error"),
    errordef(esrmnt, "Srmount error"),
    errordef(ecomm, "Communication error on send"),
    errordef(eproto, "Protocol error "),
    errordef(emultihop, "Multihop attempted"),
    errordef(edotdot, "RFS specific error"),
    errordef(ebadmsg, "Not a data message"),
    errordef(eoverflow, "Value too large for defined data type"),
    errordef(enotuniq, "Name not unique on network"),
    errordef(ebadfd, "File descriptor in bad state"),
    errordef(eremchg, "Remote address changed"),
    errordef(elibacc, "Can not access a needed shared library"),
    errordef(elibbad, "Accessing a corrupted shared library"),
    errordef(elibscn, ".lib section in a.out corrupted"),
    errordef(elibmax, "Attempting to link in too many shared libraries"),
    errordef(elibexec, "Cannot exec a shared library directly"),
    errordef(eilseq, "Illegal byte sequence"),
    errordef(erestart, "Interrupted system call should be restarted"),
    errordef(estrpipe, "Streams pipe error"),
    errordef(eusers, "Too many users"),
    errordef(enotsock, "Socket operation on non-socket"),
    errordef(edestaddrreq, "Destination address required"),
    errordef(emsgsize, "Message too long"),
    errordef(eprototype, "Protocol wrong type for socket"),
    errordef(enoprotoopt, "Protocol not available"),
    errordef(eprotonosupport, "Protocol not supported"),
    errordef(esocktnosupport, "Socket type not supported"),
    errordef(eopnotsupp, "Operation not supported on transport endpoint"),
    errordef(epfnosupport, "Protocol family not supported"),
    errordef(eafnosupport, "Address family not supported by protocol"),
    errordef(eaddrinuse, "Address already in use"),
    errordef(eaddrnotavail, "Cannot assign requested address"),
    errordef(enetdown, "Network is down"),
    errordef(enetunreach, "Network is unreachable"),
    errordef(enetreset, "Network dropped connection because of reset"),
    errordef(econnaborted, "Software caused connection abort"),
    errordef(econnreset, "Connection reset by peer"),
    errordef(enobufs, "No buffer space available"),
    errordef(eisconn, "Transport endpoint is already connected"),
    errordef(enotconn, "Transport endpoint is not connected"),
    errordef(eshutdown, "Cannot send after transport endpoint shutdown"),
    errordef(etoomanyrefs, "Too many references: cannot splice"),
    errordef(etimedout, "Connection timed out"),
    errordef(econnrefused, "Connection refused"),
    errordef(ehostdown, "Host is down"),
    errordef(ehostunreach, "No route to host"),
    errordef(ealready, "Operation already in progress"),
    errordef(einprogress, "Operation now in progress"),
    errordef(estale, "Stale file handle"),
    errordef(euclean, "Structure needs cleaning"),
    errordef(enotnam, "Not a XENIX named type file"),
    errordef(enavail, "No XENIX semaphores available"),
    errordef(eisnam, "Is a named type file"),
    errordef(eremoteio, "Remote I/O error"),
    errordef(edquot, "Quota exceeded"),
    errordef(enomedium, "No medium found"),
    errordef(emediumtype, "Wrong medium type"),
    errordef(ecanceled, "Operation Canceled"),
    errordef(enokey, "Required key not available"),
    errordef(ekeyexpired, "Key has expired"),
    errordef(ekeyrevoked, "Key has been revoked"),
    errordef(ekeyrejected, "Key was rejected by service"),
    errordef(eownerdead, "Owner died"),
    errordef(enotrecoverable, "State not recoverable"),
    errordef(erfkill, "Operation not possible due to RF-kill"),
    errordef(ehwpoison, "Memory page has hardware error"),
    errordef(eai_badflags, "Invalid value for `ai_flags' field"),
    errordef(eai_noname, "NAME or SERVICE is unknown"),
    errordef(eai_again, "Temporary failure in name resolution"),
    errordef(eai_fail, "Non-recoverable failure in name res"),
    errordef(eai_family, "`ai_family' not supported"),
    errordef(eai_socktype, "`ai_socktype' not supported"),
    errordef(eai_service, "SERVICE not supported for `ai_socktype'"),
    errordef(eai_memory, "Memory allocation failure"),
    errordef(eai_system, "System error returned in `errno'"),
    errordef(eai_overflow, "Argument buffer overflow"),
    errordef(eai_nodata, "No address associated with NAME"),
    errordef(eai_addrfamily, "Address family for NAME not supported"),
    errordef(eai_inprogress, "Processing request in progress"),
    errordef(eai_canceled, "Request canceled"),
    errordef(eai_notcanceled, "Request not canceled"),
    errordef(eai_alldone, "All requests done"),
    errordef(eai_intr, "Interrupted by a signal"),
    errordef(eai_idn_encode, "IDN encoding failed"),
#endif
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
    errordef(exception_caught, "exception caught"),
    errordef(bad_data, "bad data"),
    errordef(bad_format, "bad format"),
    errordef(overflow, "overflow"),
    errordef(empty, "empty"),
    errordef(full, "full"),
    errordef(out_of_range, "out of range"),
    errordef(mismatch, "mismatch"),
    errordef(integrity, "integrity error"),
    errordef(expired, "expired"),
    errordef(canceled, "canceled"),
    errordef(invalid_request, "invalid request"),  // RFC 6749 4.1.2.1. Error Response
    errordef(bad_response, "bad response"),
    errordef(unexpected, "unexpected"),
    errordef(max_reached, "max reached"),
    errordef(failed, "failed"),
    errordef(blocked, "blocked"),
    errordef(duplicate, "duplicate"),
    errordef(closed, "closed"),
    errordef(disconnect, "disconnect"),
    errordef(cipher_failure, "cipher"),
    errordef(digest_failure, "digest"),
    errordef(verification_failure, "verification"),
    errordef(no_session, "no session specified"),
    errordef(query_failure, "query"),
    errordef(fetch_failure, "fetch"),
    errordef(insufficient, "insufficient"),
    errordef(confidential, "confidential"),
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
    errordef(socket_failure, "socket"),
    errordef(bind_failure, "bind"),
    errordef(handshake_failure, "handshake"),
    errordef(connect_failure, "connect"),
    errordef(send_failure, "send"),
    errordef(recv_failure, "recv"),
    errordef(abandoned, "abandoned"),
    errordef(different_type, "different type"),
    errordef(narrow_type, "narrow type"),
    errordef(narrow_type, "narrow type"),
    errordef(missing_certificate, "certificate"),
    errordef(exceed, "exceed the designed size"),
    errordef(divide_by_zero, "e.g. divide by zero"),
    errordef(not_specified, "not specfied"),
    errordef(negotiation_failure, "negotiation failed"),
    errordef(illegal_parameter, "illegal parameter"),  // ie. invalid_parameter + verify
    errordef(violation, "violation"),
    errordef(ambiguous, "ambiguous"),
    errordef(miscast_unsigned, "negative integer to unsigned type"),
    errordef(miscast_narrow, "narrow conversion"),

    errordef(not_supported, "not supported"),
    errordef(expect_failure, "expect failure (negative test)"),
    errordef(low_security, "low security"),
    errordef(debug, "debug"),
    errordef(do_nothing, "nothing to do"),
    errordef(warn_retry, "retry"),
    errordef(pending, "pending"),
    errordef(timeout, "timeout"),
    errordef(busy, "busy"),
    errordef(no_more, "no more data"),
    errordef(more_data, "more data"),
    errordef(reassemble, "reassemble"),
    errordef(no_data, "no data"),
    errordef(fragmented, "fragment detected"),
    errordef(not_implemented, "not_implemented"),
    errordef(block_segmented, "segment"),
};  // namespace hotplace

error_advisor error_advisor::_instance;

error_advisor::error_advisor() {}

error_advisor* error_advisor::get_instance() {
    _instance.build();
    return &_instance;
}

void error_advisor::build() {
    if (_table.empty()) {
        critical_section_guard guard(_lock);
        if (_table.empty()) {
            for (unsigned i = 0; i < RTL_NUMBER_OF(error_descriptions); i++) {
                const error_description* item = error_descriptions + i;
                _table.emplace(item->error, item);
            }
        }
    }
}

bool error_advisor::error_code(return_t error, std::string& code) {
    bool ret = false;
    code.clear();

    const error_description* item = nullptr;
    t_maphint_const<return_t, const error_description*> hint(_table);
    hint.find(error, &item);
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
    t_maphint_const<return_t, const error_description*> hint(_table);
    hint.find(error, &item);
    if (item) {
        message = item->error_message;
        ret = true;
    }
    return ret;
}

bool error_advisor::error_message(return_t error, std::string& code, std::string& message) {
    bool ret = false;
    message.clear();

    const error_description* item = nullptr;
    t_maphint_const<return_t, const error_description*> hint(_table);
    hint.find(error, &item);
    if (item) {
        code = item->error_code;
        message = item->error_message;
        ret = true;
    }
    return ret;
}

error_category_t error_advisor::categoryof(return_t rc) {
    const uint32 val = rc.code;

    if (0 == val) return error_category_t::error_category_success;

    if (val >= WARN_CODE_BEGIN) {
        // OS, third party library - not supporeted feature
        if (val == static_cast<uint32>(errorcode_t::not_supported)) return error_category_t::error_category_not_supported;

        // negative test
        if (val == static_cast<uint32>(errorcode_t::expect_failure)) return error_category_t::error_category_expect_failure;

        // security vulnerability policy violation
        if (val == static_cast<uint32>(errorcode_t::low_security)) return error_category_t::error_category_low_security;

        // debugging
        if (val == static_cast<uint32>(errorcode_t::do_nothing)) return error_category_t::error_category_trivial;

        // warnings (warn_retry, pending, timeout, ...)
        return error_category_t::error_category_warn;
    }

    // hotplace error space (0xEF010000 ~ 0xFF00FFFF)
    if (val >= ERROR_CODE_BEGIN) {
        return error_category_t::error_category_severe;
    }

    // native OS (Linux errno / Windows DWORD)
#if defined __linux__
    if (val <= 133 || (val >= 0x00001000 && val <= 0x000013ed)) {
        return error_category_t::error_category_severe;
    }
#endif

    return error_category_t::error_category_severe;
}

}  // namespace hotplace
