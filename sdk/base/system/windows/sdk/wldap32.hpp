/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file wldap32.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WLDAP32__
#define __HOTPLACE_SDK_BASE_SYSTEM_WINDOWS_SDK_WLDAP32__

#include <winldap.h>

#if defined _MBCS || defined MBCS
#define DECLARE_NAMEOF_API_LDAP_BIND            DECLARE_NAMEOF_API_LDAP_BINDA
#define DECLARE_NAMEOF_API_LDAP_BIND_S          DECLARE_NAMEOF_API_LDAP_BIND_SA
#define DECLARE_NAMEOF_API_LDAP_FIRST_ATTRIBUTE DECLARE_NAMEOF_API_LDAP_FIRST_ATTRIBUTEA
#define DECLARE_NAMEOF_API_LDAP_GET_DN          DECLARE_NAMEOF_API_LDAP_GET_DNA
#define DECLARE_NAMEOF_API_LDAP_GET_VALUES      DECLARE_NAMEOF_API_LDAP_GET_VALUESA
#define DECLARE_NAMEOF_API_LDAP_INIT            DECLARE_NAMEOF_API_LDAP_INITA
#define DECLARE_NAMEOF_API_LDAP_MEMFREE         DECLARE_NAMEOF_API_LDAP_MEMFREEA
#define DECLARE_NAMEOF_API_LDAP_NEXT_ATTRIBUTE  DECLARE_NAMEOF_API_LDAP_NEXT_ATTRIBUTEA
#define DECLARE_NAMEOF_API_LDAP_SEARCH          DECLARE_NAMEOF_API_LDAP_SEARCHA
#define DECLARE_NAMEOF_API_LDAP_SEARCH_EXT      DECLARE_NAMEOF_API_LDAP_SEARCH_EXTA
#define DECLARE_NAMEOF_API_LDAP_SEARCH_EXT_S    DECLARE_NAMEOF_API_LDAP_SEARCH_EXT_SA
#define DECLARE_NAMEOF_API_LDAP_SEARCH_S        DECLARE_NAMEOF_API_LDAP_SEARCH_SA
#define DECLARE_NAMEOF_API_LDAP_SEARCH_ST       DECLARE_NAMEOF_API_LDAP_SEARCH_STA
#define DECLARE_NAMEOF_API_LDAP_SIMPLE_BIND     DECLARE_NAMEOF_API_LDAP_SIMPLE_BINDA
#define DECLARE_NAMEOF_API_LDAP_SIMPLE_BIND_S   DECLARE_NAMEOF_API_LDAP_SIMPLE_BIND_SA
#define DECLARE_NAMEOF_API_LDAP_VALUE_FREE      DECLARE_NAMEOF_API_LDAP_VALUE_FREEA
#define NAMEOF_API_LDAP_BIND                    NAMEOF_API_LDAP_BINDA
#define NAMEOF_API_LDAP_BIND_S                  NAMEOF_API_LDAP_BIND_SA
#define NAMEOF_API_LDAP_FIRST_ATTRIBUTE         NAMEOF_API_LDAP_FIRST_ATTRIBUTEA
#define NAMEOF_API_LDAP_GET_DN                  NAMEOF_API_LDAP_GET_DNA
#define NAMEOF_API_LDAP_GET_VALUES              NAMEOF_API_LDAP_GET_VALUESA
#define NAMEOF_API_LDAP_INIT                    NAMEOF_API_LDAP_INITA
#define NAMEOF_API_LDAP_MEMFREE                 NAMEOF_API_LDAP_MEMFREEA
#define NAMEOF_API_LDAP_NEXT_ATTRIBUTE          NAMEOF_API_LDAP_NEXT_ATTRIBUTEA
#define NAMEOF_API_LDAP_SEARCH                  NAMEOF_API_LDAP_SEARCHA
#define NAMEOF_API_LDAP_SEARCH_EXT              NAMEOF_API_LDAP_SEARCH_EXTA
#define NAMEOF_API_LDAP_SEARCH_EXT_S            NAMEOF_API_LDAP_SEARCH_EXT_SA
#define NAMEOF_API_LDAP_SEARCH_S                NAMEOF_API_LDAP_SEARCH_SA
#define NAMEOF_API_LDAP_SEARCH_ST               NAMEOF_API_LDAP_SEARCH_STA
#define NAMEOF_API_LDAP_SIMPLE_BIND             NAMEOF_API_LDAP_SIMPLE_BINDA
#define NAMEOF_API_LDAP_SIMPLE_BIND_S           NAMEOF_API_LDAP_SIMPLE_BIND_SA
#define NAMEOF_API_LDAP_VALUE_FREE              NAMEOF_API_LDAP_VALUE_FREEA
#define LDAP_BIND                               LDAP_BINDA
#define LDAP_BIND_S                             LDAP_BIND_SA
#define LDAP_FIRST_ATTRIBUTE                    LDAP_FIRST_ATTRIBUTEA
#define LDAP_GET_DN                             LDAP_GET_DNA
#define LDAP_GET_VALUES                         LDAP_GET_VALUESA
#define LDAP_INIT                               LDAP_INITA
#define LDAP_MEMFREE                            LDAP_MEMFREEA
#define LDAP_NEXT_ATTRIBUTE                     LDAP_NEXT_ATTRIBUTEA
#define LDAP_SEARCH                             LDAP_SEARCHA
#define LDAP_SEARCH_EXT                         LDAP_SEARCH_EXTA
#define LDAP_SEARCH_EXT_S                       LDAP_SEARCH_EXT_SA
#define LDAP_SEARCH_S                           LDAP_SEARCH_SA
#define LDAP_SEARCH_ST                          LDAP_SEARCH_STA
#define LDAP_SIMPLE_BIND                        LDAP_SIMPLE_BINDA
#define LDAP_SIMPLE_BIND_S                      LDAP_SIMPLE_BIND_SA
#define LDAP_VALUE_FREE                         LDAP_VALUE_FREEA
#elif defined _UNICODE || defined UNICODE
#define DECLARE_NAMEOF_API_LDAP_BIND            DECLARE_NAMEOF_API_LDAP_BINDW
#define DECLARE_NAMEOF_API_LDAP_BIND_S          DECLARE_NAMEOF_API_LDAP_BIND_SW
#define DECLARE_NAMEOF_API_LDAP_FIRST_ATTRIBUTE DECLARE_NAMEOF_API_LDAP_FIRST_ATTRIBUTEW
#define DECLARE_NAMEOF_API_LDAP_GET_DN          DECLARE_NAMEOF_API_LDAP_GET_DNW
#define DECLARE_NAMEOF_API_LDAP_GET_VALUES      DECLARE_NAMEOF_API_LDAP_GET_VALUESW
#define DECLARE_NAMEOF_API_LDAP_INIT            DECLARE_NAMEOF_API_LDAP_INITW
#define DECLARE_NAMEOF_API_LDAP_MEMFREE         DECLARE_NAMEOF_API_LDAP_MEMFREEW
#define DECLARE_NAMEOF_API_LDAP_NEXT_ATTRIBUTE  DECLARE_NAMEOF_API_LDAP_NEXT_ATTRIBUTEW
#define DECLARE_NAMEOF_API_LDAP_SEARCH          DECLARE_NAMEOF_API_LDAP_SEARCHW
#define DECLARE_NAMEOF_API_LDAP_SEARCH_EXT      DECLARE_NAMEOF_API_LDAP_SEARCH_EXTW
#define DECLARE_NAMEOF_API_LDAP_SEARCH_EXT_S    DECLARE_NAMEOF_API_LDAP_SEARCH_EXT_SW
#define DECLARE_NAMEOF_API_LDAP_SEARCH_S        DECLARE_NAMEOF_API_LDAP_SEARCH_SW
#define DECLARE_NAMEOF_API_LDAP_SEARCH_ST       DECLARE_NAMEOF_API_LDAP_SEARCH_STW
#define DECLARE_NAMEOF_API_LDAP_SIMPLE_BIND     DECLARE_NAMEOF_API_LDAP_SIMPLE_BINDW
#define DECLARE_NAMEOF_API_LDAP_SIMPLE_BIND_S   DECLARE_NAMEOF_API_LDAP_SIMPLE_BIND_SW
#define DECLARE_NAMEOF_API_LDAP_VALUE_FREE      DECLARE_NAMEOF_API_LDAP_VALUE_FREEW
#define NAMEOF_API_LDAP_BIND                    NAMEOF_API_LDAP_BINDW
#define NAMEOF_API_LDAP_BIND_S                  NAMEOF_API_LDAP_BIND_SW
#define NAMEOF_API_LDAP_FIRST_ATTRIBUTE         NAMEOF_API_LDAP_FIRST_ATTRIBUTEW
#define NAMEOF_API_LDAP_GET_DN                  NAMEOF_API_LDAP_GET_DNW
#define NAMEOF_API_LDAP_GET_VALUES              NAMEOF_API_LDAP_GET_VALUESW
#define NAMEOF_API_LDAP_INIT                    NAMEOF_API_LDAP_INITW
#define NAMEOF_API_LDAP_MEMFREE                 NAMEOF_API_LDAP_MEMFREEW
#define NAMEOF_API_LDAP_NEXT_ATTRIBUTE          NAMEOF_API_LDAP_NEXT_ATTRIBUTEW
#define NAMEOF_API_LDAP_SEARCH                  NAMEOF_API_LDAP_SEARCHW
#define NAMEOF_API_LDAP_SEARCH_EXT              NAMEOF_API_LDAP_SEARCH_EXTW
#define NAMEOF_API_LDAP_SEARCH_EXT_S            NAMEOF_API_LDAP_SEARCH_EXT_SW
#define NAMEOF_API_LDAP_SEARCH_S                NAMEOF_API_LDAP_SEARCH_SW
#define NAMEOF_API_LDAP_SEARCH_ST               NAMEOF_API_LDAP_SEARCH_STW
#define NAMEOF_API_LDAP_SIMPLE_BIND             NAMEOF_API_LDAP_SIMPLE_BINDW
#define NAMEOF_API_LDAP_SIMPLE_BIND_S           NAMEOF_API_LDAP_SIMPLE_BIND_SW
#define NAMEOF_API_LDAP_VALUE_FREE              NAMEOF_API_LDAP_VALUE_FREEW
#define LDAP_BIND                               LDAP_BINDW
#define LDAP_BIND_S                             LDAP_BIND_SW
#define LDAP_FIRST_ATTRIBUTE                    LDAP_FIRST_ATTRIBUTEW
#define LDAP_GET_DN                             LDAP_GET_DNW
#define LDAP_GET_VALUES                         LDAP_GET_VALUESW
#define LDAP_INIT                               LDAP_INITW
#define LDAP_MEMFREE                            LDAP_MEMFREEW
#define LDAP_NEXT_ATTRIBUTE                     LDAP_NEXT_ATTRIBUTEW
#define LDAP_SEARCH                             LDAP_SEARCHW
#define LDAP_SEARCH_EXT                         LDAP_SEARCH_EXTW
#define LDAP_SEARCH_EXT_S                       LDAP_SEARCH_EXT_SW
#define LDAP_SEARCH_S                           LDAP_SEARCH_SW
#define LDAP_SEARCH_ST                          LDAP_SEARCH_STW
#define LDAP_SIMPLE_BIND                        LDAP_SIMPLE_BINDW
#define LDAP_SIMPLE_BIND_S                      LDAP_SIMPLE_BIND_SW
#define LDAP_VALUE_FREE                         LDAP_VALUE_FREEW
#endif

/* ldap_initW */
#define DECLARE_NAMEOF_API_LDAP_INITW CHAR NAMEOF_API_LDAP_INITW[] = { 'l', 'd', 'a', 'p', '_', 'i', 'n', 'i', 't', 'W', 0, };
typedef LDAP* (*LDAP_INITW)(___in const PWCHAR HostName, ULONG PortNumber);

/* ldap_initA */
#define DECLARE_NAMEOF_API_LDAP_INITA CHAR NAMEOF_API_LDAP_INITA[] = { 'l', 'd', 'a', 'p', '_', 'i', 'n', 'i', 't', 'A', 0, };
typedef LDAP* (*LDAP_INITA)(const PCHAR HostName, ULONG PortNumber);

/* ldap_simple_bindW */
#define DECLARE_NAMEOF_API_LDAP_SIMPLE_BINDW CHAR NAMEOF_API_LDAP_SIMPLE_BINDW[] = { 'l', 'd', 'a', 'p', '_', 's', 'i', 'm', 'p', 'l', 'e', '_', 'b', 'i', 'n', 'd', 'W', 0, };
typedef ULONG (*LDAP_SIMPLE_BINDW)(LDAP *ld, __in_opt PWCHAR dn, __in_opt PWCHAR passwd);
/* ldap_simple_bindA */
#define DECLARE_NAMEOF_API_LDAP_SIMPLE_BINDA CHAR NAMEOF_API_LDAP_SIMPLE_BINDA[] = { 'l', 'd', 'a', 'p', '_', 's', 'i', 'm', 'p', 'l', 'e', '_', 'b', 'i', 'n', 'd', 'A', 0, };
typedef ULONG (*LDAP_SIMPLE_BINDA)(LDAP *ld, PCHAR dn, PCHAR passwd);

/* ldap_simple_bind_sW */
#define DECLARE_NAMEOF_API_LDAP_SIMPLE_BIND_SW CHAR NAMEOF_API_LDAP_SIMPLE_BIND_SW[] = { 'l', 'd', 'a', 'p', '_', 's', 'i', 'm', 'p', 'l', 'e', '_', 'b', 'i', 'n', 'd', '_', 's', 'W', 0, };
typedef ULONG (*LDAP_SIMPLE_BIND_SW)(LDAP *ld, __in_opt PWCHAR dn, __in_opt PWCHAR passwd);
/* ldap_simple_bind_sA */
#define DECLARE_NAMEOF_API_LDAP_SIMPLE_BIND_SA CHAR NAMEOF_API_LDAP_SIMPLE_BIND_SA[] = { 'l', 'd', 'a', 'p', '_', 's', 'i', 'm', 'p', 'l', 'e', '_', 'b', 'i', 'n', 'd', '_', 's', 'A', 0, };
typedef ULONG (*LDAP_SIMPLE_BIND_SA)(LDAP *ld, PCHAR dn, PCHAR passwd);

/* ldap_bindW */
#define DECLARE_NAMEOF_API_LDAP_BINDW CHAR NAMEOF_API_LDAP_BINDW[] = { 'l', 'd', 'a', 'p', '_', 'b', 'i', 'n', 'd', 'W', 0, };
typedef ULONG (*LDAP_BINDW)(LDAP *ld, __in_opt PWCHAR dn, __in_opt PWCHAR cred, ULONG method);
/* ldap_bindA */
#define DECLARE_NAMEOF_API_LDAP_BINDA CHAR NAMEOF_API_LDAP_BINDA[] = { 'l', 'd', 'a', 'p', '_', 'b', 'i', 'n', 'd', 'A', 0, };
typedef ULONG (*LDAP_BINDA)(LDAP *ld, PCHAR dn, PCHAR cred, ULONG method);
/* ldap_bind_sW */
#define DECLARE_NAMEOF_API_LDAP_BIND_SW CHAR NAMEOF_API_LDAP_BIND_SW[] = { 'l', 'd', 'a', 'p', '_', 'b', 'i', 'n', 'd', '_', 's', 'W', 0, };
typedef ULONG (*LDAP_BIND_SW)(LDAP *ld, __in_opt PWCHAR dn, __in_opt PWCHAR cred, ULONG method);
/* ldap_bind_sA */
#define DECLARE_NAMEOF_API_LDAP_BIND_SA CHAR NAMEOF_API_LDAP_BIND_SA[] = { 'l', 'd', 'a', 'p', '_', 'b', 'i', 'n', 'd', '_', 's', 'A', 0, };
typedef ULONG (*LDAP_BIND_SA)(LDAP *ld, PCHAR dn, PCHAR cred, ULONG method);

/* ldap_unbind */
#define DECLARE_NAMEOF_API_LDAP_UNBIND CHAR NAMEOF_API_LDAP_UNBIND[] = { 'l', 'd', 'a', 'p', '_', 'u', 'n', 'b', 'i', 'n', 'd', 0, };
typedef ULONG (*LDAP_UNBIND)(LDAP *ld);

/* ldap_searchW */
#define DECLARE_NAMEOF_API_LDAP_SEARCHW CHAR NAMEOF_API_LDAP_SEARCHW[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', 'W', 0, };
typedef ULONG (*LDAP_SEARCHW)(LDAP* ld, ___in const PWCHAR base, ULONG scope, ___in const PWCHAR filter, ___in PWCHAR attrs[], ULONG attrsonly);
/* ldap_searchA */
#define DECLARE_NAMEOF_API_LDAP_SEARCHA CHAR NAMEOF_API_LDAP_SEARCHA[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', 'A', 0, };
typedef ULONG (*LDAP_SEARCHA)(LDAP* ld, ___in const PCHAR base, ULONG scope, ___in const PCHAR filter, ___in PCHAR attrs[], ULONG attrsonly);

/* ldap_search_sW */
#define DECLARE_NAMEOF_API_LDAP_SEARCH_SW CHAR NAMEOF_API_LDAP_SEARCH_SW[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', '_', 's', 'W', 0, };
typedef ULONG (*LDAP_SEARCH_SW)(LDAP* ld, ___in const PWCHAR base, ULONG scope, ___in const PWCHAR filter, ___in PWCHAR attrs[], ULONG attrsonly, LDAPMessage **res);
/* ldap_search_sA */
#define DECLARE_NAMEOF_API_LDAP_SEARCH_SA CHAR NAMEOF_API_LDAP_SEARCH_SA[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', '_', 's', 'A', 0, };
typedef ULONG (*LDAP_SEARCH_SA)(LDAP* ld, const PCHAR base, ULONG scope, const PCHAR filter, PCHAR attrs[], ULONG attrsonly, LDAPMessage **res);

/* ldap_search_stW */
#define DECLARE_NAMEOF_API_LDAP_SEARCH_STW CHAR NAMEOF_API_LDAP_SEARCH_STW[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', '_', 's', 't', 'W', 0, };
typedef ULONG (*LDAP_SEARCH_STW)(LDAP* ld, ___in const PWCHAR base, ULONG scope, ___in const PWCHAR filter, ___in PWCHAR attrs[], ULONG attrsonly, struct l_timeval *timeout, LDAPMessage **res);
/* ldap_search_stA */
#define DECLARE_NAMEOF_API_LDAP_SEARCH_STA CHAR NAMEOF_API_LDAP_SEARCH_STA[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', '_', 's', 't', 'A', 0, };
typedef ULONG (*LDAP_SEARCH_STA)(LDAP* ld, const PCHAR base, ULONG scope, const PCHAR filter, PCHAR attrs[], ULONG attrsonly, struct l_timeval *timeout, LDAPMessage **res);

/* ldap_search_extW */
#define DECLARE_NAMEOF_API_LDAP_SEARCH_EXTW CHAR NAMEOF_API_LDAP_SEARCH_EXTW[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', '_', 'e', 'x', 't', 'W', 0, };
typedef ULONG (*LDAP_SEARCH_EXTW)(LDAP* ld, ___in const PWCHAR base, ULONG scope, ___in const PWCHAR filter, ___in PWCHAR attrs[], ULONG attrsonly, PLDAPControlW *ServerControls, PLDAPControlW *ClientControls, ULONG TimeLimit, ULONG SizeLimit, ULONG *MessageNumber);

/* ldap_search_extA */
#define DECLARE_NAMEOF_API_LDAP_SEARCH_EXTA CHAR NAMEOF_API_LDAP_SEARCH_EXTA[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', '_', 'e', 'x', 't', 'A', 0, };
typedef ULONG (*LDAP_SEARCH_EXTA)(LDAP* ld, ___in const PCHAR base, ULONG scope, ___in const PCHAR filter, ___in PCHAR attrs[], ULONG attrsonly, PLDAPControlA *ServerControls, PLDAPControlA *ClientControls, ULONG TimeLimit, ULONG SizeLimit, ULONG *MessageNumber);

/* ldap_search_ext_sW */
#define DECLARE_NAMEOF_API_LDAP_SEARCH_EXT_SW CHAR NAMEOF_API_LDAP_SEARCH_EXT_SW[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', '_', 'e', 'x', 't', '_', 's', 'W', 0, };
typedef ULONG (*LDAP_SEARCH_EXT_SW)(
    LDAP            *ld,
    ___in const PWCHAR base,
    ___in ULONG scope,
    ___in const PWCHAR filter,
    ___in PWCHAR attrs[],
    ULONG attrsonly,
    PLDAPControlW   *ServerControls,
    PLDAPControlW   *ClientControls,
    struct l_timeval  *timeout,
    ULONG SizeLimit,
    LDAPMessage     **res
    );

/* ldap_search_ext_sA */
#define DECLARE_NAMEOF_API_LDAP_SEARCH_EXT_SA CHAR NAMEOF_API_LDAP_SEARCH_EXT_SA[] = { 'l', 'd', 'a', 'p', '_', 's', 'e', 'a', 'r', 'c', 'h', '_', 'e', 'x', 't', '_', 's', 'A', 0, };
typedef ULONG (*LDAP_SEARCH_EXT_SA)(
    LDAP            *ld,
    ___in const PCHAR base,
    ULONG scope,
    ___in const PCHAR filter,
    ___in PCHAR attrs[],
    ULONG attrsonly,
    PLDAPControlA   *ServerControls,
    PLDAPControlA   *ClientControls,
    struct l_timeval  *timeout,
    ULONG SizeLimit,
    LDAPMessage     **res
    );

#define DECLARE_NAMEOF_API_LDAP_FIRST_ENTRY CHAR NAMEOF_API_LDAP_FIRST_ENTRY[] = { 'l', 'd', 'a', 'p', '_', 'f', 'i', 'r', 's', 't', '_', 'e', 'n', 't', 'r', 'y', 0, };
typedef LDAPMessage* (*LDAP_FIRST_ENTRY)( LDAP *ld, LDAPMessage *res );

#define DECLARE_NAMEOF_API_LDAP_NEXT_ENTRY CHAR NAMEOF_API_LDAP_NEXT_ENTRY[] = { 'l', 'd', 'a', 'p', '_', 'n', 'e', 'x', 't', '_', 'e', 'n', 't', 'r', 'y', 0, };
typedef LDAPMessage* (*LDAP_NEXT_ENTRY)( LDAP *ld, LDAPMessage *entry );

/* ldap_count_entries */
#define DECLARE_NAMEOF_API_LDAP_COUNT_ENTRIES CHAR NAMEOF_API_LDAP_COUNT_ENTRIES[] = { 'l', 'd', 'a', 'p', '_', 'c', 'o', 'u', 'n', 't', '_', 'e', 'n', 't', 'r', 'i', 'e', 's', 0, };
typedef ULONG (*LDAP_COUNT_ENTRIES)( LDAP *ld, LDAPMessage *res );

/* ldap_get_dnW */
#define DECLARE_NAMEOF_API_LDAP_GET_DNW CHAR NAMEOF_API_LDAP_GET_DNW[] = { 'l', 'd', 'a', 'p', '_', 'g', 'e', 't', '_', 'd', 'n', 'W', 0, };
typedef PWCHAR (*LDAP_GET_DNW)( LDAP *ld, LDAPMessage *entry );
/* ldap_get_dnA */
#define DECLARE_NAMEOF_API_LDAP_GET_DNA CHAR NAMEOF_API_LDAP_GET_DNA[] = { 'l', 'd', 'a', 'p', '_', 'g', 'e', 't', '_', 'd', 'n', 'A', 0, };
typedef PCHAR (*LDAP_GET_DNA)( LDAP *ld, LDAPMessage *entry );

/* ldap_first_attributeW */
#define DECLARE_NAMEOF_API_LDAP_FIRST_ATTRIBUTEW CHAR NAMEOF_API_LDAP_FIRST_ATTRIBUTEW[] = { 'l', 'd', 'a', 'p', '_', 'f', 'i', 'r', 's', 't', '_', 'a', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 'W', 0, };
typedef PWCHAR (*LDAP_FIRST_ATTRIBUTEW)(
    LDAP            *ld,
    LDAPMessage     *entry,
    BerElement      **ptr
    );
/* ldap_first_attributeA */
#define DECLARE_NAMEOF_API_LDAP_FIRST_ATTRIBUTEA CHAR NAMEOF_API_LDAP_FIRST_ATTRIBUTEA[] = { 'l', 'd', 'a', 'p', '_', 'f', 'i', 'r', 's', 't', '_', 'a', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 'A', 0, };
typedef PCHAR (*LDAP_FIRST_ATTRIBUTEA)(LDAP* ld, LDAPMessage *entry, BerElement **ptr);

/* ldap_next_attributeW */
#define DECLARE_NAMEOF_API_LDAP_NEXT_ATTRIBUTEW CHAR NAMEOF_API_LDAP_NEXT_ATTRIBUTEW[] = { 'l', 'd', 'a', 'p', '_', 'n', 'e', 'x', 't', '_', 'a', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 'W', 0, };
typedef PWCHAR (*LDAP_NEXT_ATTRIBUTEW)(LDAP* ld, LDAPMessage *entry, BerElement *ptr);

/* ldap_next_attributeA */
#define DECLARE_NAMEOF_API_LDAP_NEXT_ATTRIBUTEA CHAR NAMEOF_API_LDAP_NEXT_ATTRIBUTEA[] = { 'l', 'd', 'a', 'p', '_', 'n', 'e', 'x', 't', '_', 'a', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 'A', 0, };
typedef PCHAR (*LDAP_NEXT_ATTRIBUTEA)(LDAP* ld, LDAPMessage *entry, BerElement *ptr);

/* ldap_get_valuesW */
#define DECLARE_NAMEOF_API_LDAP_GET_VALUESW CHAR NAMEOF_API_LDAP_GET_VALUESW[] = { 'l', 'd', 'a', 'p', '_', 'g', 'e', 't', '_', 'v', 'a', 'l', 'u', 'e', 's', 'W', 0, };
typedef PWCHAR* (*LDAP_GET_VALUESW)(LDAP* ld, LDAPMessage *entry, ___in const PWCHAR attr);

/* ldap_get_valuesA */
#define DECLARE_NAMEOF_API_LDAP_GET_VALUESA CHAR NAMEOF_API_LDAP_GET_VALUESA[] = { 'l', 'd', 'a', 'p', '_', 'g', 'e', 't', '_', 'v', 'a', 'l', 'u', 'e', 's', 'A', 0, };
typedef PCHAR * (*LDAP_GET_VALUESA)(LDAP *ld, LDAPMessage *entry, ___in const PCHAR attr);

/* ldap_value_freeW */
#define DECLARE_NAMEOF_API_LDAP_VALUE_FREEW CHAR NAMEOF_API_LDAP_VALUE_FREEW[] = { 'l', 'd', 'a', 'p', '_', 'v', 'a', 'l', 'u', 'e', '_', 'f', 'r', 'e', 'e', 'W', 0, };
typedef ULONG (*LDAP_VALUE_FREEW)( __in_opt PWCHAR *vals );

/* ldap_value_freeA */
#define DECLARE_NAMEOF_API_LDAP_VALUE_FREEA CHAR NAMEOF_API_LDAP_VALUE_FREEA[] = { 'l', 'd', 'a', 'p', '_', 'v', 'a', 'l', 'u', 'e', '_', 'f', 'r', 'e', 'e', 'A', 0, };
typedef ULONG (*LDAP_VALUE_FREEA)( PCHAR *vals );

/* ldap_memfreeW */
#define DECLARE_NAMEOF_API_LDAP_MEMFREEW CHAR NAMEOF_API_LDAP_MEMFREEW[] = { 'l', 'd', 'a', 'p', '_', 'm', 'e', 'm', 'f', 'r', 'e', 'e', 'W', 0, };
typedef VOID (*LDAP_MEMFREEW)( ___in PWCHAR Block );
/* ldap_memfreeA */
#define DECLARE_NAMEOF_API_LDAP_MEMFREEA CHAR NAMEOF_API_LDAP_MEMFREEA[] = { 'l', 'd', 'a', 'p', '_', 'm', 'e', 'm', 'f', 'r', 'e', 'e', 'A', 0, };
typedef VOID (*LDAP_MEMFREEA)( PCHAR Block );

/* ldap_msgfree */
#define DECLARE_NAMEOF_API_LDAP_MSGFREE CHAR NAMEOF_API_LDAP_MSGFREE[] = { 'l', 'd', 'a', 'p', '_', 'm', 's', 'g', 'f', 'r', 'e', 'e', 0, };
typedef ULONG (*LDAP_MSGFREE)( LDAPMessage *res );

/* LdapGetLastError */
#define DECLARE_NAMEOF_API_LDAPGETLASTERROR CHAR NAMEOF_API_LDAPGETLASTERROR[] = { 'L', 'd', 'a', 'p', 'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', 0, };
typedef ULONG (*LDAPGETLASTERROR)( VOID );

#endif

