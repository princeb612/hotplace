/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot (codename.hotplace)
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

typedef uint32 return_t;
enum errorcode_t {
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

    /* 0xef010000 4009820160 */ internal_error = ERROR_CODE_BEGIN + 0,

    /* 0xef010001 4009820161 */ out_of_memory,
    /* 0xef010002 4009820162 */ insufficient_buffer,

    /* 0xef010003 4009820163 */ invalid_parameter,
    /* 0xef010004 4009820164 */ invalid_context,
    /* 0xef010005 4009820165 */ invalid_pointer,
    /* 0xef010006 4009820166 */ not_exist,
    /* 0xef010007 4009820167 */ not_found,
    /* 0xef010008 4009820168 */ already_exist,
    /* 0xef010009 4009820169 */ already_assigned,
    /* 0xef01000a 4009820170 */ not_open,
    /* 0xef01000b 4009820171 */ not_available,
    /* 0xef01000c 4009820172 */ not_ready,
    /* 0xef01000d 4009820173 */ no_init,
    /* 0xef01000e 4009820174 */ no_data,
    /* 0xef01000f 4009820175 */ bad_data,
    /* 0xef010010 4009820176 */ bad_format,
    /* 0xef010011 4009820177 */ more_data,
    /* 0xef010012 4009820178 */ empty,
    /* 0xef010013 4009820179 */ full,
    /* 0xef010014 4009820180 */ out_of_range,
    /* 0xef010015 4009820181 */ mismatch,
    /* 0xef010016 4009820182 */ timeout,
    /* 0xef010017 4009820183 */ expired,
    /* 0xef010018 4009820184 */ canceled,
    /* 0xef010019 4009820185 */ request,
    /* 0xef01001a 4009820186 */ response,
    /* 0xef01001b 4009820187 */ unexpected,
    /* 0xef01001c 4009820188 */ max_reached,
    /* 0xef01001d 4009820189 */ failed,
    /* 0xef01001e 4009820190 */ blocked,
    /* 0xef01001f 4009820191 */ pending,
    /* 0xef010020 4009820192 */ closed,
    /* 0xef010021 4009820193 */ disconnect,
    /* 0xef010022 4009820194 */ cipher,
    /* 0xef010023 4009820195 */ digest,
    /* 0xef010024 4009820196 */ verify,
    /* 0xef010025 4009820197 */ busy,
    /* 0xef010026 4009820198 */ query,
    /* 0xef010027 4009820199 */ fetch,
    /* 0xef010028 4009820200 */ insufficiency,
    /* 0xef010029 4009820201 */ reserved,
    /* 0xef01002a 4009820202 */ reserved19,
    /* 0xef01002b 4009820203 */ reserved20,
    /* 0xef01002c 4009820204 */ reserved21,

    /* 0xef010080 4009820288 */ internal_error_0 = 0xef010080,
    /* 0xef010081 4009820289 */ internal_error_1,
    /* 0xef010082 4009820290 */ internal_error_2,
    /* 0xef010083 4009820291 */ internal_error_3,
    /* 0xef010084 4009820292 */ internal_error_4,
    /* 0xef010085 4009820293 */ internal_error_5,
    /* 0xef010086 4009820294 */ internal_error_6,
    /* 0xef010087 4009820295 */ internal_error_7,
    /* 0xef010088 4009820296 */ internal_error_8,
    /* 0xef010089 4009820297 */ internal_error_9,
    /* 0xef01008a 4009820298 */ internal_error_10,
    /* 0xef01008b 4009820299 */ internal_error_11,
    /* 0xef01008c 4009820300 */ internal_error_12,
    /* 0xef01008d 4009820301 */ internal_error_13,
    /* 0xef01008e 4009820302 */ internal_error_14,
    /* 0xef01008f 4009820303 */ internal_error_15,

    /* 0xef010100 4009820416 */ not_supported = 0xef010100,
    /* 0xef010101 4009820417 */ low_security,
    /* 0xef010102 4009820418 */ debug,
};

#if defined __linux__
static inline return_t get_errno(int code) {
    return_t ret = errorcode_t::success;

    // errno.h 1~133
    if (ret < 0) {
        ret = errno;
    }
    return ret;
}

static inline return_t get_eai_error(int code) {
    return_t ret = errorcode_t::success;

    // netdb.h -1~-105 to errorcode_t
    if (ret < 0) {
        if (EAI_SYSTEM == code) {
            ret = errno;
        } else {
            ret = errorcode_t::error_eai_base + abs(code);
        }
    }
    return ret;
}
#endif

}  // namespace hotplace

#endif
