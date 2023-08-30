/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab textwidth=130 colorcolumn=+1: */
/**
 * @file crypt32.h
 * @author Soo Han, Kim (hush@ahnlab.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_CRYPT32__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_SDK_CRYPT32__

/* "CryptQueryObject" */
#define DECLARE_NAMEOF_API_CRYPTQUERYOBJECT CHAR NAMEOF_API_CRYPTQUERYOBJECT[] = { 'C', 'r', 'y', 'p', 't', 'Q', 'u', 'e', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', 0, };
/* "CertCreateCertificateChainEngine" */
#define DECLARE_NAMEOF_API_CERTCREATECERTIFICATECHAINENGINE CHAR NAMEOF_API_CERTCREATECERTIFICATECHAINENGINE[] = { 'C', 'e', 'r', 't', 'C', 'r', 'e', 'a', 't', 'e', 'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e', 'C', 'h', 'a', 'i', 'n', 'E', 'n', 'g', 'i', 'n', 'e', 0, };
/* "CryptMsgGetParam" */
#define DECLARE_NAMEOF_API_CRYPTMSGGETPARAM CHAR NAMEOF_API_CRYPTMSGGETPARAM[] = { 'C', 'r', 'y', 'p', 't', 'M', 's', 'g', 'G', 'e', 't', 'P', 'a', 'r', 'a', 'm', 0, };
/* "CertFindCertificateInStore" */
#define DECLARE_NAMEOF_API_CERTFINDCERTIFICATEINSTORE CHAR NAMEOF_API_CERTFINDCERTIFICATEINSTORE[] = { 'C', 'e', 'r', 't', 'F', 'i', 'n', 'd', 'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e', 'I', 'n', 'S', 't', 'o', 'r', 'e', 0, };
/* "CertGetCertificateChain" */
#define DECLARE_NAMEOF_API_CERTGETCERTIFICATECHAIN CHAR NAMEOF_API_CERTGETCERTIFICATECHAIN[] = { 'C', 'e', 'r', 't', 'G', 'e', 't', 'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e', 'C', 'h', 'a', 'i', 'n', 0, };
/* "CertFreeCertificateContext" */
#define DECLARE_NAMEOF_API_CERTFREECERTIFICATECONTEXT CHAR NAMEOF_API_CERTFREECERTIFICATECONTEXT[] = { 'C', 'e', 'r', 't', 'F', 'r', 'e', 'e', 'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e', 'C', 'o', 'n', 't', 'e', 'x', 't', 0, };
/* "CertCloseStore" */
#define DECLARE_NAMEOF_API_CERTCLOSESTORE CHAR NAMEOF_API_CERTCLOSESTORE[] = { 'C', 'e', 'r', 't', 'C', 'l', 'o', 's', 'e', 'S', 't', 'o', 'r', 'e', 0, };
/* "CryptMsgClose" */
#define DECLARE_NAMEOF_API_CRYPTMSGCLOSE CHAR NAMEOF_API_CRYPTMSGCLOSE[] = { 'C', 'r', 'y', 'p', 't', 'M', 's', 'g', 'C', 'l', 'o', 's', 'e', 0, };
/* "CertFreeCertificateChainEngine" */
#define DECLARE_NAMEOF_API_CERTFREECERTIFICATECHAINENGINE CHAR NAMEOF_API_CERTFREECERTIFICATECHAINENGINE[] = { 'C', 'e', 'r', 't', 'F', 'r', 'e', 'e', 'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e', 'C', 'h', 'a', 'i', 'n', 'E', 'n', 'g', 'i', 'n', 'e', 0, };

/* @brief
    The CryptQueryObject function retrieves information about the contents of a cryptography API object, such as a certificate, a certificate revocation list, or a certificate trust list.
    The object can either reside in a structure in memory or be contained in a file.
 */
typedef BOOL (WINAPI *CRYPTQUERYOBJECT)(
    __in DWORD dwObjectType,
    __in const void*   pvObject,
    __in DWORD dwExpectedContentTypeFlags,
    __in DWORD dwExpectedFormatTypeFlags,
    __in DWORD dwFlags,
    __out DWORD*        pdwMsgAndCertEncodingType,
    __out DWORD*        pdwContentType,
    __out DWORD*        pdwFormatType,
    __out HCERTSTORE*   phCertStore,
    __out HCRYPTMSG*    phMsg,
    __out const void**  ppvContext
    );

/* @brief
    The CertCreateCertificateChainEngine function creates a new, nondefault chain engine for an application.
    A chain engine restricts the certificates in the root store that can be used for verification, restricts the certificate stores to be searched for certificates and certificate trust lists (CTLs), sets a time-out limit for searches that involve URLs, and limits the number of certificates checked between checking for a certificate cycle.
 */
typedef BOOL (WINAPI *CERTCREATECERTIFICATECHAINENGINE)(
    __in PCERT_CHAIN_ENGINE_CONFIG pConfig,
    __out HCERTCHAINENGINE*         phChainEngine
    );

/* @brief
    The CryptMsgGetParam function acquires a message parameter after a cryptographic message has been encoded or decoded.
    This function is called after the final CryptMsgUpdate call.
 */
typedef BOOL (WINAPI *CRYPTMSGGETPARAM)(
    __in HCRYPTMSG hCryptMsg,
    __in DWORD dwParamType,
    __in DWORD dwIndex,
    __out void*     pvData,
    __inout DWORD*    pcbData
    );

/* @brief
    The CertFindCertificateInStore function finds the first or next certificate context in a certificate store that matches a search criteria established by the dwFindType and its associated pvFindPara.
    This function can be used in a loop to find all of the certificates in a certificate store that match the specified find criteria.
 */
typedef PCCERT_CONTEXT (WINAPI *CERTFINDCERTIFICATEINSTORE)(
    __in HCERTSTORE hCertStore,
    __in DWORD dwCertEncodingType,
    __in DWORD dwFindFlags,
    __in DWORD dwFindType,
    __in const void*           pvFindPara,
    __in PCCERT_CONTEXT pPrevCertContext
    );

/* @brief
    The CertGetCertificateChain function builds a certificate chain context starting from an end certificate and going back, if possible, to a trusted root certificate.
 */
typedef BOOL (WINAPI *CERTGETCERTIFICATECHAIN)(
    __in_opt HCERTCHAINENGINE hChainEngine,
    __in PCCERT_CONTEXT pCertContext,
    __in_opt LPFILETIME pTime,
    __in HCERTSTORE hAdditionalStore,
    __in PCERT_CHAIN_PARA pChainPara,
    __in DWORD dwFlags,
    __in LPVOID pvReserved,
    __out PCCERT_CHAIN_CONTEXT* ppChainContext
    );

/* @brief
    The CertFreeCertificateContext function frees a certificate context by decrementing its reference count.
    When the reference count goes to zero, CertFreeCertificateContext frees the memory used by a certificate context.
    To free a context obtained by a get, duplicate, or create function, call the appropriate free function.
    To free a context obtained by a find or enumerate function, either pass it in as the previous context parameter to a subsequent invocation of the function, or call the appropriate free function.
    For more information, see the reference topic for the function that obtains the context.
 */
typedef BOOL (WINAPI *CERTFREECERTIFICATECONTEXT)(
    __in PCCERT_CONTEXT pCertContext
    );

/* @brief
    The CertCloseStore function closes a certificate store handle and reduces the reference count on the store.
    There needs to be a corresponding call to CertCloseStore for each successful call to the CertOpenStore or CertDuplicateStore functions.
 */
typedef BOOL (WINAPI *CERTCLOSESTORE)(
    __in HCERTSTORE hCertStore,
    __in DWORD dwFlags
    );

/* @brief
    The CryptMsgClose function closes a cryptographic message handle.
    At each call to this function, the reference count on the message is reduced by one.
    When the reference count reaches zero, the message is fully released.
 */
typedef BOOL (WINAPI *CRYPTMSGCLOSE)(
    __in HCRYPTMSG hCryptMsg
    );

typedef void (WINAPI *CERTFREECERTIFICATECHAINENGINE)(
    __in HCERTCHAINENGINE hChainEngine
    );

/* @brief
    The CertFreeCertificateChainEngine function frees a certificate trust engine.
 */
typedef DWORD (WINAPI *CERTGETNAMESTRING)(
    __in PCCERT_CONTEXT pCertContext,
    __in DWORD dwType,
    __in DWORD dwFlags,
    __in void*                 pvTypePara,
    __out LPTSTR pszNameString,
    __in DWORD cchNameString
    );

#endif