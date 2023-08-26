/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_AUTHENTICODE__
#define __HOTPLACE_SDK_CRYPTO_AUTHENTICODE__

#include <hotplace/sdk/base.hpp>

namespace hotplace {
namespace crypto {

/*
 * @brief WIN_CERTIFICATE
 * @remarks
 *  begins at IMAGE_OPTIONAL_HEADER.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
 *  supports only WIN_CERT_REVISION_2_0
 */
typedef struct _WIN_CERTIFICATE {
    uint32 dwLength;
    uint16 wRevision;
    uint16 wCertificateType; // WIN_CERT_TYPE_xxx
    byte_t bCertificate[1];

} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;

#define WIN_CERT_REVISION_1_0               (0x0100)
#define WIN_CERT_REVISION_2_0               (0x0200)

#define WIN_CERT_TYPE_X509                  (0x0001)    // bCertificate contains an X.509 Certificate
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA      (0x0002)    // bCertificate contains a PKCS SignedData structure
#define WIN_CERT_TYPE_RESERVED_1            (0x0003)    // Reserved
#define WIN_CERT_TYPE_TS_STACK_SIGNED       (0x0004)    // Terminal Server Protocol Stack Certificate signing

}
}  // namespace

#endif
