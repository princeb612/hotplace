/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2013.05.08   Soo Han, Kim        printf %I64i, %I64u (code.merlin)
 * 2018.06.15   Soo Han, Kim        printf %zi, %zu, %zd (code.grape)
 * 2020.02.06   Soo Han, Kim        printf %I128i, %1284u (code.unicorn)
 * 2021.06.29   Soo Han, Kim        printf unicode (code.unicorn)
 *
 * printf license
 *  Copyright (c) 1990 Regents of the University of California.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms are permitted
 *  provided that the above copyright notice and this paragraph are
 *  duplicated in all such forms and that any documentation,
 *  advertising materials, and other materials related to such
 *  distribution and use acknowledge that the software was developed
 *  by the University of California, Berkeley.  The name of the
 *  University may not be used to endorse or promote products derived
 *  from this software without specific prior written permission.
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include <hotplace/sdk/io/string/string.hpp>
#include <ctype.h>  // isdigit
#include <math.h>   // modf
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

namespace hotplace {
namespace io {

#define LONGINT   0x01                      /* long integer */
#define LONGDBL   0x02                      /* long double; unimplemented */
#define SHORTINT  0x04                      /* short integer */
#define ALT       0x08                      /* alternate form */
#define LADJUST   0x10                      /* left adjustment */
#define ZEROPAD   0x20                      /* zero (as opposed to blank) pad */
#define HEXPREFIX 0x40                      /* add 0x or 0X prefix */

#define BUF       (MAXEXP + MAXFRACT + 1)   /* + decimal point */
#define DEFPREC   6
/* 11-bit exponent (VAX G floating point) is 308 decimal digits */
#define MAXEXP    308
/* 128 bit fraction takes up 39 decimal digits; max reasonable precision */
#define MAXFRACT  39

#if __cplusplus >= 201703L // c++17
    #define __register
#else
    #define __register register
#endif

static inline int tochar (int c)
{
    return c + _T ('0');
}

static inline int todigit (int c)
{
    return c - _T ('0');
}

static TCHAR* exponent (__register TCHAR *p, __register int exp, int fmtch)
{
    __register TCHAR *t;
    TCHAR expbuf[MAXEXP];

    *p++ = fmtch;
    if (exp < 0) {
        exp = -exp;
        *p++ = _T ('-');
    } else {
        *p++ = _T ('+');
    }

    t = expbuf + MAXEXP;
    if (exp > 9) {
        do {
            *--t = tochar (exp % 10);
        } while ((exp /= 10) > 9);

        *--t = tochar (exp);

        for (; t < expbuf + MAXEXP; *p++ = *t++) {
            ;
        }
    } else {
        *p++ = _T ('0');
        *p++ = tochar (exp);
    }

    return p;
}

static TCHAR * round (double fract, int *exp, __register TCHAR * start, __register TCHAR * end, TCHAR ch, int *signp)
{
    double tmp;

    if (fract) {
        (void) modf (fract * 10, &tmp);
    } else {
        tmp = todigit (ch);
    }
    if (tmp > 4) {
        for (;; --end) {
            if (*end == _T ('.')) {
                --end;
            }
            if (++*end <= _T ('9')) {
                break;
            }
            *end = _T ('0');
            if (end == start) {
                if (exp) {      /* e/E; increment exponent */
                    *end = _T ('1');
                    ++*exp;
                } else {        /* f; add extra digit */
                    *--end = _T ('1');
                    --start;
                }
                break;
            }
        }
    }
    /* ``"%.3f", (double)-0.0004'' gives you a negative 0. */
    else if (*signp == _T ('-')) {
        for (;; --end) {
            if (*end == _T ('.')) {
                --end;
            }
            if (*end != _T ('0')) {
                break;
            }
            if (end == start) {
                *signp = 0;
            }
        }
    }
    return start;
}

static int __cvt_double (double number, __register int prec, int flags, int *signp, int fmtch, TCHAR * startp, TCHAR * endp)
{
    __register TCHAR *p, *t;
    __register double fract;
    int dotrim = 0, expcnt, gformat = 0;
    double integer, tmp;

    expcnt = 0;
    if (number < 0) {
        number = -number;
        *signp = _T ('-');
    } else {
        *signp = 0;
    }

    fract = modf (number, &integer);

    /* get an extra slot for rounding. */
    t = ++startp;

    /*
     * get integer portion of number; put into the end of the buffer; the
     * .01 is added for stdmodf(356.0 / 10, &integer) returning .59999999...
     */
    for (p = endp - 1; p >= startp && integer; ++expcnt) {
        tmp = modf (integer / 10, &integer);
        *p-- = (TCHAR) tochar ((int) ((tmp + .01) * 10));
    }
    switch (fmtch) {
        case _T ('f'):
        case _T ('F'):
            /* reverse integer into beginning of buffer */
            if (expcnt) {
                for (; ++p < endp; *t++ = *p) {
                    ;
                }
            } else {
                *t++ = _T ('0');
            }
            /*
             * if precision required or alternate flag Set, add in a
             * decimal point.
             */
            if (prec || flags & ALT) {
                *t++ = _T ('.');
            }
            /* if requires more precision and some fraction left */
            if (fract) {
                if (prec) {
                    do {
                        fract = modf (fract * 10, &tmp);
                        *t++ = tochar ((int) tmp);
                    } while (--prec && fract);
                }
                if (fract) {
                    startp = round (fract, (int *) nullptr, startp, t - 1, (TCHAR) 0, signp);
                }
            }
            for (; prec--; *t++ = _T ('0')) {
                ;
            }
            break;

        case _T ('e'):
        case _T ('E'):
eformat:    if (expcnt) {
                *t++ = *++p;
                if (prec || flags & ALT) {
                    *t++ = _T ('.');
                }
                /* if requires more precision and some integer left */
                for (; prec && ++p < endp; --prec) {
                    *t++ = *p;
                }
                /*
                 * if done precision and more of the integer component,
                 * stdround using it; adjust fract so we don't re-stdround
                 * later.
                 */
                if (!prec && ++p < endp) {
                    fract = 0;
                    startp = round ((double) 0, &expcnt, startp, t - 1, *p, signp);
                }
                /* adjust expcnt for digit in front of decimal */
                --expcnt;
            }
            /* until first fractional digit, decrement exponent */
            else if (fract) {
                /* adjust expcnt for digit in front of decimal */
                for (expcnt = -1;; --expcnt) {
                    fract = modf (fract * 10, &tmp);
                    if (tmp) {
                        break;
                    }
                }
                *t++ = tochar ((int) tmp);
                if (prec || flags & ALT) {
                    *t++ = _T ('.');
                }
            } else {
                *t++ = _T ('0');
                if (prec || flags & ALT) {
                    *t++ = _T ('.');
                }
            }
            /* if requires more precision and some fraction left */
            if (fract) {
                if (prec) {
                    do {
                        fract = modf (fract * 10, &tmp);
                        *t++ = tochar ((int) tmp);
                    } while (--prec && fract);
                }
                if (fract) {
                    startp = round (fract, &expcnt, startp, t - 1, (TCHAR) 0, signp);
                }
            }
            /* if requires more precision */
            for (; prec--; *t++ = _T ('0')) {
                ;
            }

            /* unless alternate flag, trim any g/G format trailing 0's */
            if (gformat && !(flags & ALT)) {
                while (t > startp && *--t == _T ('0')) {
                    ;
                }
                if (*t == _T ('.')) {
                    --t;
                }
                ++t;
            }
            t = exponent (t, expcnt, fmtch);
            break;

        case _T ('g'):
        case _T ('G'):
            /* a precision of 0 is treated as a precision of 1. */
            if (!prec) {
                ++prec;
            }
            /*
             * ``The style used depends on the value converted; style e
             * will be used only if the exponent resulting from the
             * conversion is less than -4 or greater than the precision.''
             *  -- ANSI X3J11
             */
            if (expcnt > prec || (!expcnt && fract && fract < .0001)) {
                /*
                 * g/G format counts "significant digits, not digits of
                 * precision; for the e/E format, this just causes an
                 * off-by-one problem, i.e. g/G considers the digit
                 * before the decimal point significant and e/E doesn't
                 * count it as precision.
                 */
                --prec;
                fmtch -= 2; /* G->E, g->e */
                gformat = 1;
                goto eformat;
            }
            /*
             * reverse integer into beginning of buffer,
             * note, decrement precision
             */
            if (expcnt) {
                for (; ++p < endp; *t++ = *p, --prec) {
                    ;
                }
            } else {
                *t++ = _T ('0');
            }
            /*
             * if precision required or alternate flag Set, add in a
             * decimal point.  If no digits yet, add in leading 0.
             */
            if (prec || flags & ALT) {
                dotrim = 1;
                *t++ = _T ('.');
            } else {
                dotrim = 0;
            }
            /* if requires more precision and some fraction left */
            if (fract) {
                if (prec) {
                    /* If no integer part, don't count initial * zeros as significant digits. */
                    do {
                        fract = modf (fract * 10, &tmp);
                        *t++ = tochar ((int) tmp);
                    } while (!tmp && !expcnt);

                    while (--prec && fract) {
                        fract = modf (fract * 10, &tmp);
                        *t++ = tochar ((int) tmp);
                    }
                }
                if (fract) {
                    startp = round (fract, (int *) nullptr, startp, t - 1, (TCHAR) 0, signp);
                }
            }
            /* alternate format, adds 0's for precision, else trim 0's */
            if (flags & ALT) {
                for (; prec--; *t++ = _T ('0')) {
                    ;
                }
            } else if (dotrim) {
                while (t > startp && *--t == _T ('0')) {
                    ;
                }
                if (*t != _T ('.')) {
                    ++t;
                }
            }
    }
    return (int) (t - startp);
}

#define PRINT(buf, len) runtime_printf (context, (TCHAR *) buf, len)
#define PAD_SP(howmany) { int n = howmany; while (n-- > 0) { PRINT (_T (" "), 1); \
                          } \
}
#define PAD_0(howmany)  { int n = howmany; while (n-- > 0) { PRINT (_T ("0"), 1); } }

/* int vprintf_runtime (void *context, CALLBACK_PRINTF runtime_printf, const TCHAR * fmt0, va_list ap) */
#if defined _MBCS || defined MBCS
int vprintf_runtime (void *context, CALLBACK_PRINTFA runtime_printf, const char* fmt0, va_list ap)
#elif defined _UNICODE || defined UNICODE
int vprintf_runtimew (void *context, CALLBACK_PRINTFW runtime_printf, const wchar_t* fmt0, va_list ap)
#endif
{
    __register const TCHAR *fmt = nullptr;  /* format string */
    __register int ch = 0;                  /* character from fmt */
    __register int n = 0;                   /* handy integer (short term usage) */
    __register TCHAR *cp = nullptr;         /* handy TCHAR pointer (short term usage) */
    const TCHAR *fmark = nullptr;           /* for remembering a place in fmt */
    __register int flags = 0;               /* flags as above */
    int ret = 0;                            /* return value accumulator */
    int width = 0;                          /* width from format (%8d), or 0 */
    int prec = 0;                           /* precision from format (%.3d), or -1 */
    TCHAR sign = 0;                         /* sign prefix (' ', '+', '-', or \0) */
    int softsign = 0;                       /* temporary negative sign for floats */
    double _double = 0;                     /* double precision arguments %[eEfgG] */
    int fpprec = 0;                         /* `extra' floating precision in [eEfgG] */

#if defined __SIZEOF_INT128__
    // IPv6 128bits processing (supports %I128x)
    uint128 _ulong = 0;
#else
    // 64 bits 처리를 위해 변경하였다.
    uint64 _ulong = 0; /* integer arguments %[diouxX] (including __int64) */
#endif

    // 32 bits
    //unsigned long _ulong;     /* integer arguments %[diouxX] */
    enum {
        OCT,
        DEC,
        HEX
    } base;                     /* base for [diouxX] conversion */
    int dprec;                  /* a copy of prec if [diouxX], 0 otherwise */
    int dpad;                   /* extra 0 padding needed for integers */
    int fieldsz;                /* field size expanded by sign, dpad etc */
    /* The initialization of 'size' is to suppress a warning that
       'size' might be used unitialized.  It seems gcc can't
       quite grok this spaghetti code ... */
    size_t size = 0;            /* size of converted field or string */
    TCHAR buf[BUF] = { 0, };    /* space for %c, %[diouxX], %[eEfgG] */
    TCHAR ox[2] = { 0, };       /* space for 0x hex-prefix */

    if (!runtime_printf) {
        goto error;
    }

    /*
     * BEWARE, these `goto error' on error, and PAD uses `n'.
     */

    /*
     * To extend shorts properly, we need both signed and unsigned
     * argument extraction methods.
     */

    // 64 bits patched - hush
#define SARG() \
    (flags & LONGDBL ? va_arg (ap, int64) : \
     flags&LONGINT ? (int64) va_arg (ap, long) : \
     flags & SHORTINT ? (int64) (short) va_arg (ap, int) : \
     (int64) va_arg (ap, int))
#define UARG() \
    (flags & LONGDBL ? va_arg (ap, uint64) : \
     flags & LONGINT ? (uint64) va_arg (ap, unsigned long) : \
     flags & SHORTINT ? (uint64) (unsigned short) va_arg (ap, int) : \
     (uint64) va_arg (ap, unsigned int))

    fmt = fmt0;
    ret = 0;

    /*
     * Scan the format for conversions (`%' character).
     */
    for (;; ) {
        for (fmark = fmt; (ch = *fmt) != _T ('\0') && ch != _T ('%'); fmt++) {
            /* void */;
        }
        if ((n = (int) (fmt - fmark)) != 0) {
            PRINT (fmark, n);
            ret += n;
        }
        if (ch == _T ('\0')) {
            goto done;
        }
        fmt++;      /* skip over '%' */

        flags = 0;
        dprec = 0;

        fpprec = 0;

        width = 0;
        prec = -1;
        sign = _T ('\0');

rflag:
        ch = *fmt++;
reswitch:
        switch (ch) {
            case _T (' '):
                /*
                 * ``If the space and + flags both appear, the space
                 * flag will be ignored.''
                 *  -- ANSI X3J11
                 */
                if (!sign) {
                    sign = _T (' ');
                }
                goto rflag;

            case _T ('#'):
                flags |= ALT;
                goto rflag;

            case _T ('*'):
                /*
                 * ``A negative field width argument is taken as a
                 * - flag followed by a positive field width.''
                 *  -- ANSI X3J11
                 * They don't exclude field widths read from args.
                 */
                if ((width = va_arg (ap, int)) >= 0) {
                    goto rflag;
                }
                width = -width;
            /* FALLTHROUGH */

            case _T ('-'):
                flags |= LADJUST;
                flags &= ~ZEROPAD; /* '-' disables '0' */
                goto rflag;

            case _T ('+'):
                sign = _T ('+');
                goto rflag;

            case _T ('.'):
                if ((ch = *fmt++) == _T ('*')) {
                    n = va_arg (ap, int);
                    prec = n < 0 ? -1 : n;
                    goto rflag;
                }
                n = 0;
                while (isdigit (ch)) {
                    n = 10 * n + todigit (ch);
                    ch = *fmt++;
                }
                prec = n < 0 ? -1 : n;
                goto reswitch;

            case _T ('0'):
                /*
                 * ``Note that 0 is taken as a flag, not as the
                 * beginning of a field width.''
                 *  -- ANSI X3J11
                 */
                if (!(flags & LADJUST)) {
                    flags |= ZEROPAD; /* '-' disables '0' */
                }
                goto rflag;

            case _T ('1'):
            case _T ('2'):
            case _T ('3'):
            case _T ('4'):
            case _T ('5'):
            case _T ('6'):
            case _T ('7'):
            case _T ('8'):
            case _T ('9'):
                n = 0;
                do {
                    n = 10 * n + todigit (ch);
                    ch = *fmt++;
                } while (isdigit (ch));
                width = n;
                goto reswitch;

            case _T ('L'):
                flags |= LONGDBL;
                goto rflag;

            case _T ('h'):
                flags |= SHORTINT;
                goto rflag;

            case _T ('l'):
                flags |= LONGINT;
                goto rflag;

            case _T ('c'):
                *(cp = buf) = va_arg (ap, int);
                size = 1;
                sign = _T ('\0');
                break;

            case _T ('D'):
                flags |= LONGINT;
            /*FALLTHROUGH*/
            case _T ('d'):
            case _T ('i'):
                _ulong = SARG ();
                if ((long) _ulong < 0) {
                    _ulong = -(long) _ulong;
                    sign = _T ('-');
                }
                base = DEC;
                goto number;

            case _T ('e'):
            case _T ('E'):
            case _T ('f'):
            case _T ('F'):
            case _T ('g'):
            case _T ('G'):
                _double = va_arg (ap, double);
                /*
                 * don't do unrealistic precision; just pad it with
                 * zeroes later, so buffer size stays rational.
                 */
                if (prec > MAXFRACT) {
                    if ((ch != _T ('g') && ch != _T ('G')) || (flags & ALT)) {
                        fpprec = prec - MAXFRACT;
                    }
                    prec = MAXFRACT;
                } else if (prec == -1) {
                    prec = DEFPREC;
                }
                /* __cvt_double may have to stdround up before the
                   "start" of its buffer, i.e.
                   ``intf("%.2f", (double)9.999);'';
                   if the first character is still NUL, it did.
                   softsign avoids negative 0 if _double < 0 but
                   no significant digits will be shown. */
                cp = buf;
                *cp = _T ('\0');
                size = __cvt_double (_double, prec, flags, &softsign, ch, cp, buf + sizeof (buf));
                if (softsign) {
                    sign = _T ('-');
                }
                if (*cp == _T ('\0')) {
                    cp++;
                }
                break;

            case _T ('n'):
                if (flags & LONGINT) {
                    *va_arg (ap, long *) = ret;
                } else if (flags & SHORTINT) {
                    *va_arg (ap, short *) = ret;
                } else {
                    *va_arg (ap, int *) = ret;
                }
                continue; /* no output */

            case _T ('O'):
                flags |= LONGINT;
            /*FALLTHROUGH*/
            case _T ('o'):
                _ulong = UARG ();
                base = OCT;
                goto nosign;

            case _T ('p'):
                /*
                 * ``The argument shall be a pointer to void.  The
                 * value of the pointer is converted to a sequence
                 * of printable characters, in an implementation-
                 * defined manner.''
                 *  -- ANSI X3J11
                 */
                /* NOSTRICT */
                _ulong = (uint64)
                         va_arg (ap, void *);
                base = HEX;
                flags |= HEXPREFIX;
                ch = _T ('x');
                goto nosign;

            case _T ('I'):
                /*
                 * __int64 출력을 위한 %I64i, %I64d 지원
                 *
                 * __int64 int64val = 0x0123456789abcdef;
                 * printf("%I64i", int64val);
                 */

                base = DEC;

                if (_T ('6') == *fmt && _T ('4') == *(fmt + 1)) {
                    fmt += 2;

                    _ulong = (uint64) va_arg (ap, int64);

                    if ('i' == *fmt) {
                        fmt++;
                        goto number;
                    } else if ('u' == *fmt) {
                        fmt++;
                        goto nosign;
                    } else if ('x' == *fmt) {
                        fmt++;
                        base = HEX;
                        goto number;
                    } else {
                        goto number;
                    }
                }
#if defined __SIZEOF_INT128__
                else if (_T ('1') == *fmt && _T ('2') == *(fmt + 1) && _T ('8') == *(fmt + 2)) {
                    fmt += 3;

                    _ulong = (uint128) va_arg (ap, int128);

                    if ('i' == *fmt) {
                        fmt++;
                        goto number;
                    } else if ('u' == *fmt) {
                        fmt++;
                        goto nosign;
                    } else if ('x' == *fmt) {
                        fmt++;
                        base = HEX;
                        goto number;
                    } else {
                        goto number;
                    }
                }
#endif
                else {
                    _ulong = SARG ();

                    goto number;
                }

            case _T ('z'):
                base = DEC;
                fmt++;
                _ulong = (size_t) va_arg (ap, size_t);
                if (_T ('i') == *fmt) {
                    fmt++;
                    goto number;
                } else if (_T ('u') == *fmt) {
                    fmt++;
                    goto nosign;
                } else {
                    goto number;
                }

            case _T ('s'):
                if ((cp = va_arg (ap, TCHAR *)) == nullptr) {
                    cp = (TCHAR *) _T ("(null)");
                }
                if (prec >= 0) {
                    /*
                     * can't use strlen; can only look for the
                     * NUL in the first `prec' characters, and
                     * strlen() will go further.
                     */
#if defined _MBCS || defined MBCS
                    TCHAR *p = (TCHAR *) memchr (cp, 0, prec);
#elif defined _UNICODE || defined UNICODE
                    TCHAR *p = (TCHAR *) wmemchr (cp, 0, prec);
#endif

                    if (p != nullptr) {
                        size = (int) (p - cp);
                        if ((int) size > prec) {
                            size = prec;
                        }
                    } else {
                        size = prec;
                    }
                } else {
                    size = _tcslen (cp);
                }
                sign = _T ('\0');
                break;

            case _T ('U'):
                flags |= LONGINT;
            /*FALLTHROUGH*/
            case _T ('u'):
                _ulong = UARG ();
                base = DEC;
                goto nosign;

            case _T ('X'):
            case _T ('x'):
                _ulong = UARG ();
                base = HEX;
                /* leading 0x/X only if non-zero */
                if (flags & ALT && _ulong != 0) {
                    flags |= HEXPREFIX;
                }

                /* unsigned conversions */
nosign:         sign = _T ('\0');
                /*
                 * ``... diouXx conversions ... if a precision is
                 * specified, the 0 flag will be ignored.''
                 *  -- ANSI X3J11
                 */
number:         if ((dprec = prec) >= 0) {
                    flags &= ~ZEROPAD;
                }

                /*
                 * ``The result of converting a zero value with an
                 * explicit precision of zero is no characters.''
                 *  -- ANSI X3J11
                 */
                cp = buf + BUF;
                if ((_ulong != 0) || (prec != 0)) {
                    TCHAR *xdigs = nullptr; /* digits for [xX] conversion */
                    /*
                     * unsigned mod is hard, and unsigned mod
                     * by a constant is easier than that by
                     * a variable; hence this switch.
                     */
                    switch (base) {
                        case OCT:
                            do {
                                *--cp = tochar ((int) (_ulong & 7));
                                _ulong >>= 3;
                            } while (_ulong);
                            /* handle octal leading 0 */
                            if (flags & ALT && *cp != _T ('0')) {
                                *--cp = _T ('0');
                            }
                            break;

                        case DEC:
                            /* many numbers are 1 digit */
                            while (_ulong >= 10) {
                                *--cp = tochar ((int) (_ulong % 10));
                                _ulong /= 10;
                            }
                            *--cp = tochar ((int) (_ulong));
                            break;

                        case HEX:
                            if (ch == _T ('X')) {
                                xdigs = (TCHAR *) _T ("0123456789ABCDEF");
                            } else {
                                /* ch == 'x' || ch == 'p' */
                                xdigs = (TCHAR *) _T ("0123456789abcdef");
                            }
                            do {
                                *--cp = xdigs[_ulong & 15];
                                _ulong >>= 4;
                            } while (_ulong);
                            break;

                        default:
                            cp = (TCHAR *) _T ("bad base") /*"bug in vform: bad base" */;
                            goto skipsize;
                    }
                }
                size = (int) (buf + BUF - cp);
skipsize:       break;
            default:    /* "%?" prints ?, unless ? is NUL */
                if (ch == _T ('\0')) {
                    goto done;
                }
                /* pretend it was %c with argument ch */
                cp = buf;
                *cp = ch;
                size = 1;
                sign = _T ('\0');
                break;
        }

        /*
         * All reasonable formats wind up here.  At this point,
         * `cp' points to a string which (if not flags&LADJUST)
         * should be padded out to `width' places.  If
         * flags&ZEROPAD, it should first be prefixed by any
         * sign or other prefix; otherwise, it should be blank
         * padded before the prefix is emitted.  After any
         * left-hand padding and prefixing, emit zeroes
         * required by a decimal [diouxX] precision, then print
         * the string proper, then emit zeroes required by any
         * leftover floating precision; finally, if LADJUST,
         * pad with blanks.
         */

        /*
         * compute actual size, so we know how much to pad.
         */

        fieldsz = (int) size + fpprec;

        dpad = dprec - (int) size;
        if (dpad < 0) {
            dpad = 0;
        }

        if (sign) {
            fieldsz++;
        } else if (flags & HEXPREFIX) {
            fieldsz += 2;
        }
        fieldsz += dpad;

        /* right-adjusting blank padding */
        if ((flags & (LADJUST | ZEROPAD)) == 0) {
            PAD_SP (width - fieldsz);
        }

        /* prefix */
        if (sign) {
            PRINT (&sign, 1);
        } else if (flags & HEXPREFIX) {
            ox[0] = _T ('0');
            ox[1] = ch;
            PRINT (ox, 2);
        }

        /* right-adjusting zero padding */
        if ((flags & (LADJUST | ZEROPAD)) == ZEROPAD) {
            PAD_0 (width - fieldsz);
        }

        /* leading zeroes from decimal precision */
        PAD_0 (dpad);

        /* the string or number proper */
        PRINT (cp, (int ) size);

        /* trailing f.p. zeroes */
        PAD_0 (fpprec);

        /* left-adjusting padding (always blank) */
        if (flags & LADJUST) {
            PAD_SP (width - fieldsz);
        }

        /* finally, adjust ret */
        ret += width > fieldsz ? width : fieldsz;
    }
done: return ret;
error: return EOF;
    /* NOTREACHED */
}

/* int printf_runtime (void *context, CALLBACK_PRINTF runtime_printf, const TCHAR * fmt0, ...) */
#if defined _MBCS || defined MBCS
int printf_runtime (void *context, CALLBACK_PRINTFA runtime_printf, const char * fmt0, ...)
#elif defined _UNICODE || defined UNICODE
int printf_runtimew (void *context, CALLBACK_PRINTFW runtime_printfw, const wchar_t * fmt0, ...)
#endif
{
    int nRet = EOF;
    va_list ap;

    va_start (ap, fmt0);
#if defined _MBCS || defined MBCS
    nRet = vprintf_runtime (context, runtime_printf, fmt0, ap);
#elif defined _UNICODE || defined UNICODE
    nRet = vprintf_runtimew (context, runtime_printfw, fmt0, ap);
#endif
    va_end (ap);
    return nRet;
}

}
}  // namespace
