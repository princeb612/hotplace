/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/authenticode/sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crl_distribution_point(X509 *cert, std::set<std::string> &crls) {
    return_t ret = errorcode_t::success;

    __try2 {
        crls.clear();

        int nid = NID_crl_distribution_points;
        STACK_OF(DIST_POINT) *dist_points = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(cert, nid, nullptr, nullptr);
        if (nullptr == dist_points) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        for (int i = 0; i < sk_DIST_POINT_num(dist_points); i++) {
            DIST_POINT *dp = sk_DIST_POINT_value(dist_points, i);
            DIST_POINT_NAME *distpoint = dp->distpoint;
            if (0 == distpoint->type) {  // fullname GENERALIZEDNAME
                for (int j = 0; j < sk_GENERAL_NAME_num(distpoint->name.fullname); j++) {
                    GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, j);
                    ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;

                    std::string crl((char *)ASN1_STRING_get0_data(asn1_str), ASN1_STRING_length(asn1_str));
                    crls.insert(crl);
                }
            } else if (1 == distpoint->type) {  // relative X509NAME
                STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
                for (int j = 0; j < sk_X509_NAME_ENTRY_num(sk_relname); j++) {
                    X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, j);
                    ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);

                    std::string crl((char *)ASN1_STRING_get0_data(d), ASN1_STRING_length(d));
                    crls.insert(crl);
                }
            }
        }
        CRL_DIST_POINTS_free(dist_points);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

/*
   Windows Authenticode Portable Executable Signature Format (Authenticode_PE.docx)

   Authenticode-Specific Structures in ContentInfo
    An Authenticode signature's ContentInfo structure contains several structures that
    in turn contain the file's hash value, page hash values (if present), the file description,
    and various optional or legacy ASN.1 fields. The root structure is SpcIndirectDataContent.

    the ASN.1 definition of SpcIndirectDataContent

    SpcIndirectDataContent ::= SEQUENCE {
        data                    SpcAttributeTypeAndOptionalValue,
        messageDigest           DigestInfo
    } --#public-

    SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
        type                    ObjectID,
        value                   [0] EXPLICIT ANY OPTIONAL
    }

    DigestInfo ::= SEQUENCE {
        digestAlgorithm     AlgorithmIdentifier,
        digest              OCTETSTRING
    }

    AlgorithmIdentifier    ::=    SEQUENCE {
        algorithm           ObjectID,
        parameters          [0] EXPLICIT ANY OPTIONAL
    }
 */

// IMPLEMENT_ASN1_FUNCTIONS(x) d2i_xxx, xxx_free
#define SPC_INDIRECT_DATA_OBJID "1.3.6.1.4.1.311.2.1.4"

typedef struct {
    ASN1_OBJECT *type;
    ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

// DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
                                                   ASN1_OPT(SpcAttributeTypeAndOptionalValue, value,
                                                            ASN1_ANY)} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

    // IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

    typedef struct {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameters;
} AlgorithmIdentifier;

// DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(AlgorithmIdentifier) = {ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
                                      ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)} ASN1_SEQUENCE_END(AlgorithmIdentifier)

    // IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)

    typedef struct {
    AlgorithmIdentifier *digestAlgorithm;
    ASN1_OCTET_STRING *digest;
} DigestInfo;

// DECLARE_ASN1_FUNCTIONS(DigestInfo)

ASN1_SEQUENCE(DigestInfo) = {ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
                             ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)} ASN1_SEQUENCE_END(DigestInfo)

    // IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)

    typedef struct {
    SpcAttributeTypeAndOptionalValue *data;
    DigestInfo *messageDigest;
} SpcIndirectDataContent;

// DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)

ASN1_SEQUENCE(SpcIndirectDataContent) = {ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
                                         ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)} ASN1_SEQUENCE_END(SpcIndirectDataContent)

    IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)

        return_t pkcs7_digest_info(PKCS7 * pkcs7, std::string &md, binary_t &digest) {
    return_t ret = errorcode_t::success;

    __try2 {
        md.clear();
        digest.resize(0);

        if (nullptr == pkcs7) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == PKCS7_type_is_signed(pkcs7)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        ASN1_OBJECT *indir_objid = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);
        int mdtype = -1;

        if (!OBJ_cmp(pkcs7->d.sign->contents->type, indir_objid) && pkcs7->d.sign->contents->d.other->type == V_ASN1_SEQUENCE) {
            ASN1_STRING *astr = pkcs7->d.sign->contents->d.other->value.sequence;
            const unsigned char *p = astr->data;
            SpcIndirectDataContent *idc = d2i_SpcIndirectDataContent(nullptr, &p, astr->length);
            if (idc) {
                if (idc->messageDigest && idc->messageDigest->digest && idc->messageDigest->digestAlgorithm) {
                    mdtype = OBJ_obj2nid(idc->messageDigest->digestAlgorithm->algorithm);
                    // const EVP_MD *evp_md = EVP_get_digestbynid (mdtype);
                    md = OBJ_nid2sn(mdtype);
                    digest.resize(idc->messageDigest->digest->length);
                    memcpy(&digest[0], idc->messageDigest->digest->data, idc->messageDigest->digest->length);
                }
                SpcIndirectDataContent_free(idc);
            }
        }
        ASN1_OBJECT_free(indir_objid);

        if (-1 == mdtype) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t X509_NAME_to_string(X509_NAME *name, std::string &data) {
    return_t ret = errorcode_t::success;
    char *s = nullptr;
    char *c = nullptr;
    char *b = nullptr;
    int l = 0;
    int i = 0;

    __try2 {
        data.clear();

        if (nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        l = 80 - 2;

        b = X509_NAME_oneline(name, nullptr, 0);
        if (nullptr == b) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        if (0 == *b) {
            __leave2;
        }

        s = b + 1; /* skip the first slash */

        c = s;
        for (;;) {
            //#ifndef CHARSET_EBCDIC
            if (((*s == '/') && ((s[1] >= 'A') && (s[1] <= 'Z') && ((s[2] == '=') || ((s[2] >= 'A') && (s[2] <= 'Z') && (s[3] == '='))))) || (*s == '\0')) {
                //#else
                // if (((*s == '/') && (isupper(s[1]) && ((s[2] == '=') || (isupper(s[2]) && (s[3] == '='))))) || (*s == '\0'))
                //#endif
                i = s - c;
                data.append(c, i);
                c = s + 1; /* skip following slash */
                if (*s != '\0') {
                    data.append(", ");
                }
                l--;
            }
            if (*s == '\0') {
                break;
            }
            s++;
            l--;
        }
    }
    __finally2 {
        if (nullptr != b) {
            OPENSSL_free(b);
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
