/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   error.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot (codename.hotplace)
 * 2026.05.26   Soo Han and Gemini  refactoring
 */

#ifndef __HOTPLACE_SDK_BASE_ERROR__
#define __HOTPLACE_SDK_BASE_ERROR__

#include <stdlib.h>

#include <hotplace/sdk/base/types.hpp>
#if defined __linux__
#include <errno.h>
#include <netdb.h>
#endif

namespace hotplace {
#define ERROR_CODE_BEGIN 0xef010000
#define WARN_CODE_BEGIN 0xff010000

/*
 * runtime isolation (Linux / Winodws)
 *   separation of cross-platform compilation: windows and linux builds are clearly separated at the binary level,
 *   and runtime behavior accommodates errors specific to a single OS environment only.
 */
enum class errorcode_t : uint32 {
    success = 0,

#if defined __linux__

    /* 0x00000000 0000000000 */ error_errno_base = 0x00000000,

    // asm-generic/errno-base.h
    /* 0x00000001 0000000001 EPERM          */ eperm,           /* Operation not permitted */
    /* 0x00000002 0000000002 ENOENT         */ enoent,          /* No such file or directory */
    /* 0x00000003 0000000003 ESRCH          */ esrch,           /* No such process */
    /* 0x00000004 0000000004 EINTR          */ eintr,           /* Interrupted system call */
    /* 0x00000005 0000000005 EIO            */ eio,             /* I/O error */
    /* 0x00000006 0000000006 ENXIO          */ enxio,           /* No such device or address */
    /* 0x00000007 0000000007 E2BIG          */ e2big,           /* Argument list too long */
    /* 0x00000008 0000000008 ENOEXEC        */ enoexec,         /* Exec format error */
    /* 0x00000009 0000000009 EBADF          */ ebadf,           /* Bad file number */
    /* 0x0000000a 0000000010 ECHILD         */ echild,          /* No child processes */
    /* 0x0000000b 0000000011 EAGAIN         */ eagain,          /* Try again */
    /* 0x0000000c 0000000012 ENOMEM         */ enomem,          /* Out of memory */
    /* 0x0000000d 0000000013 EACCES         */ eacces,          /* Permission denied */
    /* 0x0000000e 0000000014 EFAULT         */ efault,          /* Bad address */
    /* 0x0000000f 0000000015 ENOTBLK        */ enotblk,         /* Block device required */
    /* 0x00000010 0000000016 EBUSY          */ ebusy,           /* Device or resource busy */
    /* 0x00000011 0000000017 EEXIST         */ eexist,          /* File exists */
    /* 0x00000012 0000000018 EXDEV          */ exdev,           /* Cross-device link */
    /* 0x00000013 0000000019 ENODEV         */ enodev,          /* No such device */
    /* 0x00000014 0000000020 ENOTDIR        */ enotdir,         /* Not a directory */
    /* 0x00000015 0000000021 EISDIR         */ eisdir,          /* Is a directory */
    /* 0x00000016 0000000022 EINVAL         */ einval,          /* Invalid argument */
    /* 0x00000017 0000000023 ENFILE         */ enfile,          /* File table overflow */
    /* 0x00000018 0000000024 EMFILE         */ emfile,          /* Too many open files */
    /* 0x00000019 0000000025 ENOTTY         */ enotty,          /* Not a typewriter */
    /* 0x0000001a 0000000026 ETXTBSY        */ etxtbsy,         /* Text file busy */
    /* 0x0000001b 0000000027 EFBIG          */ efbig,           /* File too large */
    /* 0x0000001c 0000000028 ENOSPC         */ enospc,          /* No space left on device */
    /* 0x0000001d 0000000029 ESPIPE         */ espipe,          /* Illegal seek */
    /* 0x0000001e 0000000030 EROFS          */ erofs,           /* Read-only file system */
    /* 0x0000001f 0000000031 EMLINK         */ emlink,          /* Too many links */
    /* 0x00000020 0000000032 EPIPE          */ epipe,           /* Broken pipe */
    /* 0x00000021 0000000033 EDOM           */ edom,            /* Math argument out of domain of func */
    /* 0x00000022 0000000034 ERANGE         */ erange,          /* Math result not representable */
                                                                // asm-generic/errno.h
    /* 0x00000023 0000000035 EDEADLK        */ edeadlk,         /* Resource deadlock would occur */
    /* 0x00000024 0000000036 ENAMETOOLONG   */ enametoolong,    /* File name too long */
    /* 0x00000025 0000000037 ENOLCK         */ enolck,          /* No record locks available */
    /* 0x00000026 0000000038 ENOSYS         */ enosys,          /* Function not implemented */
    /* 0x00000027 0000000039 ENOTEMPTY      */ enotempty,       /* Directory not empty */
    /* 0x00000028 0000000040 ELOOP          */ eloop,           /* Too many symbolic links encountered */
    /* 0x0000000b 0000000011 EWOULDBLOCK    */ ewouldblock,     /* errno 11 EAGAIN */
    /* 0x0000002a 0000000042 ENOMSG         */ enomsg,          /* No message of desired type */
    /* 0x0000002b 0000000043 EIDRM          */ eidrm,           /* Identifier removed */
    /* 0x0000002c 0000000044 ECHRNG         */ echrng,          /* Channel number out of range */
    /* 0x0000002d 0000000045 EL2NSYNC       */ el2nsync,        /* Level 2 not synchronized */
    /* 0x0000002e 0000000046 EL3HLT         */ el3hlt,          /* Level 3 halted */
    /* 0x0000002f 0000000047 EL3RST         */ el3rst,          /* Level 3 reset */
    /* 0x00000030 0000000048 ELNRNG         */ elnrng,          /* Link number out of range */
    /* 0x00000031 0000000049 EUNATCH        */ eunatch,         /* Protocol driver not attached */
    /* 0x00000032 0000000050 ENOCSI         */ enocsi,          /* No CSI structure available */
    /* 0x00000033 0000000051 EL2HLT         */ el2hlt,          /* Level 2 halted */
    /* 0x00000034 0000000052 EBADE          */ ebade,           /* Invalid exchange */
    /* 0x00000035 0000000053 EBADR          */ ebadr,           /* Invalid request descriptor */
    /* 0x00000036 0000000054 EXFULL         */ exfull,          /* Exchange full */
    /* 0x00000037 0000000055 ENOANO         */ enoano,          /* No anode */
    /* 0x00000038 0000000056 EBADRQC        */ ebadrqc,         /* Invalid request code */
    /* 0x00000039 0000000057 EBADSLT        */ ebadslt,         /* Invalid slot */
    /* 0x00000023 0000000035 EDEADLOCK      */ edeadlock,       /* errno 35 EDEADLK */
    /* 0x0000003b 0000000059 EBFONT         */ ebfont,          /* Bad font file format */
    /* 0x0000003c 0000000060 ENOSTR         */ enostr,          /* Device not a stream */
    /* 0x0000003d 0000000061 ENODATA        */ enodata,         /* No data available */
    /* 0x0000003e 0000000062 ETIME          */ etime,           /* Timer expired */
    /* 0x0000003f 0000000063 ENOSR          */ enosr,           /* Out of streams resources */
    /* 0x00000040 0000000064 ENONET         */ enonet,          /* Machine is not on the network */
    /* 0x00000041 0000000065 ENOPKG         */ enopkg,          /* Package not installed */
    /* 0x00000042 0000000066 EREMOTE        */ eremote,         /* Object is remote */
    /* 0x00000043 0000000067 ENOLINK        */ enolink,         /* Link has been severed */
    /* 0x00000044 0000000068 EADV           */ eadv,            /* Advertise error */
    /* 0x00000045 0000000069 ESRMNT         */ esrmnt,          /* Srmount error */
    /* 0x00000046 0000000070 ECOMM          */ ecomm,           /* Communication error on send */
    /* 0x00000047 0000000071 EPROTO         */ eproto,          /* Protocol error  */
    /* 0x00000048 0000000072 EMULTIHOP      */ emultihop,       /* Multihop attempted */
    /* 0x00000049 0000000073 EDOTDOT        */ edotdot,         /* RFS specific error */
    /* 0x0000004a 0000000074 EBADMSG        */ ebadmsg,         /* Not a data message */
    /* 0x0000004b 0000000075 EOVERFLOW      */ eoverflow,       /* Value too large for defined data type */
    /* 0x0000004c 0000000076 ENOTUNIQ       */ enotuniq,        /* Name not unique on network */
    /* 0x0000004d 0000000077 EBADFD         */ ebadfd,          /* File descriptor in bad state */
    /* 0x0000004e 0000000078 EREMCHG        */ eremchg,         /* Remote address changed */
    /* 0x0000004f 0000000079 ELIBACC        */ elibacc,         /* Can not access a needed shared library */
    /* 0x00000050 0000000080 ELIBBAD        */ elibbad,         /* Accessing a corrupted shared library */
    /* 0x00000051 0000000081 ELIBSCN        */ elibscn,         /* .lib section in a.out corrupted */
    /* 0x00000052 0000000082 ELIBMAX        */ elibmax,         /* Attempting to link in too many shared libraries */
    /* 0x00000053 0000000083 ELIBEXEC       */ elibexec,        /* Cannot exec a shared library directly */
    /* 0x00000054 0000000084 EILSEQ         */ eilseq,          /* Illegal byte sequence */
    /* 0x00000055 0000000085 ERESTART       */ erestart,        /* Interrupted system call should be restarted */
    /* 0x00000056 0000000086 ESTRPIPE       */ estrpipe,        /* Streams pipe error */
    /* 0x00000057 0000000087 EUSERS         */ eusers,          /* Too many users */
    /* 0x00000058 0000000088 ENOTSOCK       */ enotsock,        /* Socket operation on non-socket */
    /* 0x00000059 0000000089 EDESTADDRREQ   */ edestaddrreq,    /* Destination address required */
    /* 0x0000005a 0000000090 EMSGSIZE       */ emsgsize,        /* Message too long */
    /* 0x0000005b 0000000091 EPROTOTYPE     */ eprototype,      /* Protocol wrong type for socket */
    /* 0x0000005c 0000000092 ENOPROTOOPT    */ enoprotoopt,     /* Protocol not available */
    /* 0x0000005d 0000000093 EPROTONOSUPPORT*/ eprotonosupport, /* Protocol not supported */
    /* 0x0000005e 0000000094 ESOCKTNOSUPPORT*/ esocktnosupport, /* Socket type not supported */
    /* 0x0000005f 0000000095 EOPNOTSUPP     */ eopnotsupp,      /* Operation not supported on transport endpoint */
    /* 0x00000060 0000000096 EPFNOSUPPORT   */ epfnosupport,    /* Protocol family not supported */
    /* 0x00000061 0000000097 EAFNOSUPPORT   */ eafnosupport,    /* Address family not supported by protocol */
    /* 0x00000062 0000000098 EADDRINUSE     */ eaddrinuse,      /* Address already in use */
    /* 0x00000063 0000000099 EADDRNOTAVAIL  */ eaddrnotavail,   /* Cannot assign requested address */
    /* 0x00000064 0000000100 ENETDOWN       */ enetdown,        /* Network is down */
    /* 0x00000065 0000000101 ENETUNREACH    */ enetunreach,     /* Network is unreachable */
    /* 0x00000066 0000000102 ENETRESET      */ enetreset,       /* Network dropped connection because of reset */
    /* 0x00000067 0000000103 ECONNABORTED   */ econnaborted,    /* Software caused connection abort */
    /* 0x00000068 0000000104 ECONNRESET     */ econnreset,      /* Connection reset by peer */
    /* 0x00000069 0000000105 ENOBUFS        */ enobufs,         /* No buffer space available */
    /* 0x0000006a 0000000106 EISCONN        */ eisconn,         /* Transport endpoint is already connected */
    /* 0x0000006b 0000000107 ENOTCONN       */ enotconn,        /* Transport endpoint is not connected */
    /* 0x0000006c 0000000108 ESHUTDOWN      */ eshutdown,       /* Cannot send after transport endpoint shutdown */
    /* 0x0000006d 0000000109 ETOOMANYREFS   */ etoomanyrefs,    /* Too many references: cannot splice */
    /* 0x0000006e 0000000110 ETIMEDOUT      */ etimedout,       /* Connection timed out */
    /* 0x0000006f 0000000111 ECONNREFUSED   */ econnrefused,    /* Connection refused */
    /* 0x00000070 0000000112 EHOSTDOWN      */ ehostdown,       /* Host is down */
    /* 0x00000071 0000000113 EHOSTUNREACH   */ ehostunreach,    /* No route to host */
    /* 0x00000072 0000000114 EALREADY       */ ealready,        /* Operation already in progress */
    /* 0x00000073 0000000115 EINPROGRESS    */ einprogress,     /* Operation now in progress */
    /* 0x00000074 0000000116 ESTALE         */ estale,          /* Stale file handle */
    /* 0x00000075 0000000117 EUCLEAN        */ euclean,         /* Structure needs cleaning */
    /* 0x00000076 0000000118 ENOTNAM        */ enotnam,         /* Not a XENIX named type file */
    /* 0x00000077 0000000119 ENAVAIL        */ enavail,         /* No XENIX semaphores available */
    /* 0x00000078 0000000120 EISNAM         */ eisnam,          /* Is a named type file */
    /* 0x00000079 0000000121 EREMOTEIO      */ eremoteio,       /* Remote I/O error */
    /* 0x0000007a 0000000122 EDQUOT         */ edquot,          /* Quota exceeded */
    /* 0x0000007b 0000000123 ENOMEDIUM      */ enomedium,       /* No medium found */
    /* 0x0000007c 0000000124 EMEDIUMTYPE    */ emediumtype,     /* Wrong medium type */
    /* 0x0000007d 0000000125 ECANCELED      */ ecanceled,       /* Operation Canceled */
    /* 0x0000007e 0000000126 ENOKEY         */ enokey,          /* Required key not available */
    /* 0x0000007f 0000000127 EKEYEXPIRED    */ ekeyexpired,     /* Key has expired */
    /* 0x00000080 0000000128 EKEYREVOKED    */ ekeyrevoked,     /* Key has been revoked */
    /* 0x00000081 0000000129 EKEYREJECTED   */ ekeyrejected,    /* Key was rejected by service */
    /* 0x00000082 0000000130 EOWNERDEAD     */ eownerdead,      /* Owner died */
    /* 0x00000083 0000000131 ENOTRECOVERABLE*/ enotrecoverable, /* State not recoverable */
    /* 0x00000084 0000000132 ERFKILL        */ erfkill,         /* Operation not possible due to RF-kill */
    /* 0x00000085 0000000133 EHWPOISON      */ ehwpoison,       /* Memory page has hardware error */

    /* Extended Addressing Information / Extended API Information */
    /* 0x00001000 0000004096 */ error_eai_base = 0x00001000,

    // netdb.h
    /* 0x00001001 0000004097 EAI_BADFLAGS    - 1   */ eai_badflags,    /* Invalid value for `ai_flags' field.  */
    /* 0x00001002 0000004098 EAI_NONAME      - 2   */ eai_noname,      /* NAME or SERVICE is unknown.  */
    /* 0x00001003 0000004099 EAI_AGAIN       - 3   */ eai_again,       /* Temporary failure in name resolution.  */
    /* 0x00001004 0000004100 EAI_FAIL        - 4   */ eai_fail,        /* Non-recoverable failure in name res.  */
    /* 0x00001006 0000004102 EAI_FAMILY      - 6   */ eai_family,      /* `ai_family' not supported.  */
    /* 0x00001007 0000004103 EAI_SOCKTYPE    - 7   */ eai_socktype,    /* `ai_socktype' not supported.  */
    /* 0x00001008 0000004104 EAI_SERVICE     - 8   */ eai_service,     /* SERVICE not supported for `ai_socktype'.  */
    /* 0x0000100a 0000004106 EAI_MEMORY      - 10  */ eai_memory,      /* Memory allocation failure.  */
    /* 0x0000100b 0000004107 EAI_SYSTEM      - 11  */ eai_system,      /* System error returned in `errno'.  */
    /* 0x0000100c 0000004108 EAI_OVERFLOW    - 12  */ eai_overflow,    /* Argument buffer overflow.  */
    /* 0x00001005 0000004101 EAI_NODATA      - 5   */ eai_nodata,      /* No address associated with NAME.  */
    /* 0x00001009 0000004105 EAI_ADDRFAMILY  - 9   */ eai_addrfamily,  /* Address family for NAME not supported.  */
    /* 0x000013e8 0000005096 EAI_INPROGRESS  - 100 */ eai_inprogress,  /* Processing request in progress.  */
    /* 0x000013e9 0000005097 EAI_CANCELED    - 101 */ eai_canceled,    /* Request canceled.  */
    /* 0x000013ea 0000005098 EAI_NOTCANCELED - 102 */ eai_notcanceled, /* Request not canceled.  */
    /* 0x000013eb 0000005099 EAI_ALLDONE     - 103 */ eai_alldone,     /* All requests done.  */
    /* 0x000013ec 0000005100 EAI_INTR        - 104 */ eai_intr,        /* Interrupted by a signal.  */
    /* 0x000013ed 0000005101 EAI_IDN_ENCODE  - 105 */ eai_idn_encode,  /* IDN encoding failed.  */

#endif

    /* -------------------------------------------------------------------------
     * General System & Internal Errors
     * Core system failures, assertions, and unclassified errors.
     * ------------------------------------------------------------------------- */
    /* 0xef010000 4009820160 */ internal_error = ERROR_CODE_BEGIN + 0x0000,
    /* 0xef010001 4009820161 */ failed,
    /* 0xef010002 4009820162 */ unexpected,
    /* 0xef010003 4009820163 */ unknown,
    /* 0xef010004 4009820164 */ exception_caught,
    /* 0xef010005 4009820165 */ assert_failed,
    /* -------------------------------------------------------------------------
     * Resource & Memory Management
     * Allocation failures, capacity limits, and buffer operations.
     * ------------------------------------------------------------------------- */
    /* 0xef011000 4009824256 */ out_of_memory = ERROR_CODE_BEGIN + 0x1000,
    /* 0xef011001 4009824257 */ insufficient_buffer,
    /* 0xef011002 4009824258 */ empty,
    /* 0xef011003 4009824259 */ full,
    /* 0xef011004 4009824260 */ max_reached,
    /* 0xef011005 4009824261 */ exceed,
    /* 0xef011006 4009824262 */ insufficient,
    /* -------------------------------------------------------------------------
     * Parameter, Data & Type Validation
     * Input validation, type conversions, format issues, and arithmetic errors.
     * ------------------------------------------------------------------------- */
    /* 0xef012000 4009828352 */ invalid_parameter = ERROR_CODE_BEGIN + 0x2000,
    /* 0xef012001 4009828353 */ illegal_parameter,
    /* 0xef012002 4009828354 */ invalid_pointer,
    /* 0xef012003 4009828355 */ invalid_handle,
    /* 0xef012004 4009828356 */ bad_data,
    /* 0xef012005 4009828357 */ bad_format,
    /* 0xef012006 4009828358 */ too_large_data,
    /* 0xef012007 4009828359 */ out_of_range,
    /* 0xef012008 4009828360 */ overflow,
    /* 0xef012009 4009828361 */ divide_by_zero,
    /* 0xef01200a 4009828362 */ mismatch,
    /* 0xef01200b 4009828363 */ different_type,
    /* 0xef01200c 4009828364 */ narrow_type,
    /* 0xef01200d 4009828365 */ miscast_unsigned,
    /* 0xef01200e 4009828366 */ miscast_narrow,
    /* 0xef01200f 4009828367 */ syntax_error,
    /* -------------------------------------------------------------------------
     * State, Lifecycle & Flow Control
     * Initialization, availability, state machine, and operation status.
     * ------------------------------------------------------------------------- */
    /* 0xef013000 4009832448 */ no_init = ERROR_CODE_BEGIN + 0x3000,
    /* 0xef013001 4009832449 */ not_ready,
    /* 0xef013002 4009832450 */ not_open,
    /* 0xef013003 4009832451 */ closed,
    /* 0xef013004 4009832452 */ not_available,
    /* 0xef013005 4009832453 */ invalid_context,
    /* 0xef013006 4009832454 */ premature_state,
    /* 0xef013007 4009832455 */ blocked,
    /* 0xef013008 4009832456 */ canceled,
    /* 0xef013009 4009832457 */ abandoned,
    /* 0xef01300a 4009832458 */ expired,
    /* 0xef01300b 4009832459 */ low_version,
    /* -------------------------------------------------------------------------
     * Security, Authentication & Integrity
     * Authorization, client/grant validation, crypto, and data integrity.
     * ------------------------------------------------------------------------- */
    /* 0xef014000 4009836544 */ missing_certificate = ERROR_CODE_BEGIN + 0x4000,
    /* 0xef014001 4009836545 */ cipher_failure,
    /* 0xef014002 4009836546 */ digest_failure,
    /* 0xef014003 4009836547 */ verification_failure,
    /* 0xef014004 4009836548 */ integrity_error,
    /* 0xef014005 4009836549 */ violation,
    /* 0xef014006 4009836550 */ confidential,
    /* 0xef014007 4009836551 */ suspicious,
    /* -------------------------------------------------------------------------
     * Network, Communication & Socket
     * Low-level socket, handshake, connection state, and transmission.
     * ------------------------------------------------------------------------- */
    /* 0xef015000 4009840640 */ socket_failure = ERROR_CODE_BEGIN + 0x5000,
    /* 0xef015001 4009840641 */ bind_failure,
    /* 0xef015002 4009840642 */ connect_failure,
    /* 0xef015003 4009840643 */ handshake_failure,
    /* 0xef015004 4009840644 */ negotiation_failure,
    /* 0xef015005 4009840645 */ send_failure,
    /* 0xef015006 4009840646 */ recv_failure,
    /* 0xef015007 4009840647 */ disconnect,
    /* 0xef015008 4009840648 */ no_session,
    /* -------------------------------------------------------------------------
     * Request, Protocol & Query Operations
     * High-level requests/responses, lookups, and data queries.
     * ------------------------------------------------------------------------- */
    /* 0xef016000 4009844736 */ not_exist = ERROR_CODE_BEGIN + 0x6000,
    /* 0xef016001 4009844737 */ not_found,
    /* 0xef016002 4009844738 */ already_exist,
    /* 0xef016003 4009844739 */ already_assigned,
    /* 0xef016004 4009844740 */ duplicate,
    /* 0xef016005 4009844741 */ conflict_detected,
    /* 0xef016006 4009844742 */ query_failure,
    /* 0xef016007 4009844743 */ fetch_failure,
    /* 0xef016008 4009844744 */ inaccurate,
    /* 0xef016009 4009844745 */ ambiguous,
    /* 0xef01600a 4009844746 */ not_specified,
    /* 0xef01600b 4009844747 */ bad_request,
    /* 0xef01600c 4009844748 */ bad_response,               //
    /* 0xef01600d 4009844749 */ invalid_request,            // Separate from bad_request (RFC 6749)
    /* 0xef01600e 4009844750 */ server_error,               // RFC 6749 server_error (Moved from Network/System)
    /* 0xef01600f 4009844751 */ access_denied,              // RFC 6749 access_denied
    /* 0xef016010 4009844752 */ unauthorized_client,        // RFC 6749 unauthorized_client
    /* 0xef016011 4009844753 */ unsupported_response_type,  // RFC 6749 unsupported_response_type
    /* 0xef016012 4009844754 */ unsupported_grant_type,     // RFC 6749 unsupported_grant_type
    /* 0xef016013 4009844755 */ temporarily_unavailable,    // RFC 6749
    /* 0xef016014 4009844756 */ invalid_scope,              // RFC 6749 invalid_scope
    /* 0xef016015 4009844757 */ invalid_grant,              // RFC 6749 invalid_grant
    /* 0xef016016 4009844758 */ invalid_client,             // RFC 6749 invalid_client

    /* -------------------------------------------------------------------------
     * debugging purpose
     * ------------------------------------------------------------------------- */
    /* 0xef017000 4009848832 */ internal_error_0 = ERROR_CODE_BEGIN + 0x7000,
    /* 0xef017001 4009848833 */ internal_error_1,
    /* 0xef017002 4009848834 */ internal_error_2,
    /* 0xef017003 4009848835 */ internal_error_3,
    /* 0xef017004 4009848836 */ internal_error_4,
    /* 0xef017005 4009848837 */ internal_error_5,
    /* 0xef017006 4009848838 */ internal_error_6,
    /* 0xef017007 4009848839 */ internal_error_7,
    /* 0xef017008 4009848840 */ internal_error_8,
    /* 0xef017009 4009848841 */ internal_error_9,
    /* 0xef01700a 4009848842 */ internal_error_10,
    /* 0xef01700b 4009848843 */ internal_error_11,
    /* 0xef01700c 4009848844 */ internal_error_12,
    /* 0xef01700d 4009848845 */ internal_error_13,
    /* 0xef01700e 4009848846 */ internal_error_14,
    /* 0xef01700f 4009848847 */ internal_error_15,
    /* -------------------------------------------------------------------------
     * third party
     * ------------------------------------------------------------------------- */
    /* 0xef018000 4009852928 */ error_openssl_inside = ERROR_CODE_BEGIN + 0x8000,

    /* -------------------------------------------------------------------------
     * warning
     * ------------------------------------------------------------------------- */
    /* 0xff010000 4278255616 */ not_supported = WARN_CODE_BEGIN + 0,
    /* 0xff010001 4278255617 */ expect_failure,
    /* 0xff010002 4278255618 */ low_security,

    /* 0xff010003 4278255619 */ debug,
    /* 0xff010004 4278255620 */ do_nothing,
    /* 0xff010005 4278255621 */ warn_retry,
    /* 0xff010006 4278255622 */ pending,
    /* 0xff010007 4278255623 */ timeout,
    /* 0xff010008 4278255624 */ busy,
    /* 0xff010009 4278255625 */ no_more,
    /* 0xff01000a 4278255626 */ more_data,
    /* 0xff01000b 4278255627 */ reassemble,
    /* 0xff01000c 4278255628 */ no_data,
    /* 0xff01000d 4278255629 */ fragmented,
    /* 0xff01000e 4278255630 */ not_implemented,
    /* 0xff01000f 4278255631 */ block_segmented,
};

/**
 * @sa error_advisor::categoryof
 */
enum class error_category_t : uint8 {
    error_category_success = 0,         // success, unittest "pass", white
    error_category_expect_failure = 1,  // success (negative test), unittest "expt", cyan
    error_category_severe = 2,          // severe error, unittest "fail", red
    error_category_not_supported = 3,   // do not support (OS, third party library - not supporeted feature), unittest "skip", cyan
    error_category_low_security = 4,    // do not support (security vulnerability policy violation), unittest "triv", yellow
    error_category_trivial = 5,         // debugging purpose, unittest "triv", yellow
    error_category_warn = 6,            // warning (general), unittest "triv", yellow
};

/**
 * universal error codes
 * case                     | type         | space    |
 * ret = errorcode_t::xxx;  | errorcode_t  | hotplace |
 * ret = errno;             | int          | linux    |
 * ret = GetLastError();    | DWORD        | windows  |
 * ret = ERROR_OUTOFMEMORY; | HRESULT/LONG | windows  |
 * ret = SQL_ERROR;         | int          | ODBC     |
 */
struct return_t {
    uint32 code;

    // constexpr, noexcept (Literal Type)
    constexpr return_t() noexcept : code(static_cast<uint32>(errorcode_t::success)) {}

    constexpr return_t(uint32 value) noexcept : code(value) {}
    constexpr return_t(int value) noexcept : code(static_cast<uint32>(value)) {}
    constexpr return_t(errorcode_t value) noexcept : code(static_cast<uint32>(value)) {}

#if defined _WIN32 || defined WIN32
    // MINGW64, MSVC
    constexpr return_t(HRESULT value) noexcept : code(static_cast<uint32>(value)) {}
#endif
#if defined _MSC_VER
    constexpr return_t(unsigned long value) noexcept : code(static_cast<uint32>(value)) {}
#endif

    std::string error_code() const;
    std::string error_message() const;
    error_category_t category() const;

    constexpr operator uint32() const noexcept { return code; }
    constexpr operator errorcode_t() const noexcept { return static_cast<errorcode_t>(code); }

    return_t& operator=(uint32 value) noexcept {
        this->code = value;
        return *this;
    }
    return_t& operator=(int value) noexcept {
        this->code = static_cast<uint32>(value);
        return *this;
    }
    return_t& operator=(errorcode_t value) noexcept {
        this->code = static_cast<uint32>(value);
        return *this;
    }
#if defined _WIN32 || defined WIN32
    return_t& operator=(HRESULT value) noexcept {
        this->code = static_cast<uint32>(value);
        return *this;
    }
#endif
#if defined _MSC_VER
    return_t& operator=(unsigned long value) noexcept {
        this->code = static_cast<uint32>(value);
        return *this;
    }
#endif

    constexpr bool operator<(const return_t& other) const noexcept { return this->code < other.code; }
    constexpr bool operator<=(const return_t& other) const noexcept { return this->code <= other.code; }
    constexpr bool operator>(const return_t& other) const noexcept { return this->code > other.code; }
    constexpr bool operator>=(const return_t& other) const noexcept { return this->code >= other.code; }

    constexpr bool operator<(errorcode_t other) const noexcept { return this->code < static_cast<uint32>(other); }
    constexpr bool operator<=(errorcode_t other) const noexcept { return this->code <= static_cast<uint32>(other); }
    constexpr bool operator>(errorcode_t other) const noexcept { return this->code > static_cast<uint32>(other); }
    constexpr bool operator>=(errorcode_t other) const noexcept { return this->code >= static_cast<uint32>(other); }

    constexpr bool operator==(const return_t& other) const noexcept { return this->code == other.code; }
    constexpr bool operator!=(const return_t& other) const noexcept { return this->code != other.code; }

    constexpr bool operator==(errorcode_t other) const noexcept { return this->code == static_cast<uint32>(other); }
    constexpr bool operator!=(errorcode_t other) const noexcept { return this->code != static_cast<uint32>(other); }

    constexpr bool operator==(uint32 other) const noexcept { return this->code == other; }
    constexpr bool operator!=(uint32 other) const noexcept { return this->code != other; }
    constexpr bool operator<(uint32 other) const noexcept { return this->code < other; }
    constexpr bool operator<=(uint32 other) const noexcept { return this->code <= other; }
    constexpr bool operator>(uint32 other) const noexcept { return this->code > other; }
    constexpr bool operator>=(uint32 other) const noexcept { return this->code >= other; }

#if defined __GNUC__
    // int (signed - SQL_ERROR ...)
    constexpr bool operator==(int other) const noexcept { return static_cast<int>(this->code) == other; }
    constexpr bool operator!=(int other) const noexcept { return false == (*this == other); }

    friend constexpr bool operator==(int lhs, const return_t& rhs) noexcept { return rhs == lhs; }
    friend constexpr bool operator!=(int lhs, const return_t& rhs) noexcept { return false == (rhs == lhs); }

    // long (signed long - Windows LONG/HRESULT/WAIT_TIMEOUT ...)
    constexpr bool operator==(long other) const noexcept { return static_cast<long>(this->code) == other; }
    constexpr bool operator!=(long other) const noexcept { return false == (*this == other); }

    friend constexpr bool operator==(long lhs, const return_t& rhs) noexcept { return rhs == lhs; }
    friend constexpr bool operator!=(long lhs, const return_t& rhs) noexcept { return false == (rhs == lhs); }
#endif
};

typedef struct _error_description {
    errorcode_t error;
    const char* error_code;
    const char* error_message;
} error_description;

/*
 * @sample
 *      errorcode_t ret = errorcode_t::success;
 *      int test = function(...);
 *      // linunx
 *      ret = get_lasterror(test);
 *      // windows
 *      ret = GetLastError();
 */
enum errorflag_t {
    wsaerror = 1,
};
return_t get_lasterror(int code, int flags = 0);

}  // namespace hotplace

#endif
