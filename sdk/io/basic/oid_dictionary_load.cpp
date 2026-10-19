/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   oid_dictionary_load.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/basic/oid_dictionary.hpp>

namespace hotplace {
namespace io {

/**
 * for debugging reference purposes
 * - don’t need to include every single OID.
 * - limit the scope to OIDs that appear in RFCs, certificates, or test vectors.
 */
struct oid_resources {
    oid_t oid;
    const char* name;
    const char* desc;
};

void oid_dictionary::load() {
    oid_resources table[] = {
        // http://oidref.com/1.2.840.10045.2
        {{1, 2, 840, 10045, 2}, "", "iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2)"},
        {{1, 2, 840, 10045, 2, 1}, "ecPublicKey", ""},
        {{1, 2, 840, 10045, 3, 1}, "", "iso(1) member-body(2) us(840) ansi-x962(10045) curves(3) prime(1)"},
        {{1, 2, 840, 10045, 3, 1, 1}, "prime192v1", ""},
        {{1, 2, 840, 10045, 3, 1, 2}, "prime192v2", ""},
        {{1, 2, 840, 10045, 3, 1, 3}, "prime192v3", ""},
        {{1, 2, 840, 10045, 3, 1, 4}, "prime239v1", ""},
        {{1, 2, 840, 10045, 3, 1, 5}, "prime239v2", ""},
        {{1, 2, 840, 10045, 3, 1, 6}, "prime239v3", ""},
        {{1, 2, 840, 10045, 3, 1, 7}, "prime256v1", ""},
        // http://oidref.com/1.2.840.10045.4
        {{1, 2, 840, 10045, 4}, "", "iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4)"},
        {{1, 2, 840, 10045, 4, 1}, "ecdsa-with-SHA1", ""},
        {{1, 2, 840, 10045, 4, 2}, "ecdsa-with-Recommended", ""},
        {{1, 2, 840, 10045, 4, 3}, "ecdsa-with-SHA2", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1},
         "",
         "iso(1) identified-organization(3) teletrust(36) algorithm(3) signatureAlgorithm(3) ecSign(2) ecStdCurvesAndGeneration(8) ellipticCurve(1) versionOne(1)"},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 1}, "brainpoolP160r1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 2}, "brainpoolP160t1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 3}, "brainpoolP192r1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 4}, "brainpoolP192t1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 5}, "brainpoolP224r1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 6}, "brainpoolP224t1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}, "brainpoolP256r1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 8}, "brainpoolP256t1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 9}, "brainpoolP320r1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 10}, "brainpoolP320t1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}, "brainpoolP384r1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 12}, "brainpoolP384t1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}, "brainpoolP512r1", ""},
        {{1, 3, 36, 3, 3, 2, 8, 1, 1, 14}, "brainpoolP512t1", ""},
        // http://oidref.com/1.3.101
        {{1, 3, 101}, "", "iso(1) identified-organization(3) thawte(101)"},
        {{1, 3, 101, 110}, "id-X25519", ""},
        {{1, 3, 101, 111}, "id-X448", ""},
        {{1, 3, 101, 112}, "id-Ed25519", ""},
        {{1, 3, 101, 113}, "id-Ed448", ""},
        {{1, 3, 101, 114}, "id-EdDSA25519-ph", ""},
        {{1, 3, 101, 115}, "id-EdDSA448-ph", ""},
        // http://oidref.com/1.3.132.0
        {{1, 3, 132, 0}, "", "iso(1) identified-organization(3) certicom(132) curve(0)"},
        {{1, 3, 132, 0, 1}, "sect163k1", ""},
        {{1, 3, 132, 0, 2}, "sect163r1", ""},
        {{1, 3, 132, 0, 3}, "sect239k1", ""},
        {{1, 3, 132, 0, 4}, "sect113r1", ""},
        {{1, 3, 132, 0, 5}, "sect113r2", ""},
        {{1, 3, 132, 0, 6}, "secp112r1", ""},
        {{1, 3, 132, 0, 7}, "secp112r2", ""},
        {{1, 3, 132, 0, 8}, "secp160r1", ""},
        {{1, 3, 132, 0, 9}, "secp160k1", ""},
        {{1, 3, 132, 0, 10}, "secp256k1", ""},
        {{1, 3, 132, 0, 15}, "sect163r2", ""},
        {{1, 3, 132, 0, 16}, "sect283k1", ""},
        {{1, 3, 132, 0, 17}, "sect283r1", ""},
        {{1, 3, 132, 0, 22}, "sect131r1", ""},
        {{1, 3, 132, 0, 23}, "sect131r2", ""},
        {{1, 3, 132, 0, 24}, "sect193r1", ""},
        {{1, 3, 132, 0, 25}, "sect193r2", ""},
        {{1, 3, 132, 0, 26}, "sect233k1", ""},
        {{1, 3, 132, 0, 27}, "sect233r1", ""},
        {{1, 3, 132, 0, 28}, "secp128r1", ""},
        {{1, 3, 132, 0, 29}, "secp128r2", ""},
        {{1, 3, 132, 0, 30}, "secp160r2", ""},
        {{1, 3, 132, 0, 31}, "secp192k1", ""},
        {{1, 3, 132, 0, 32}, "secp224k1", ""},
        {{1, 3, 132, 0, 33}, "secp224r1", ""},
        {{1, 3, 132, 0, 34}, "secp384r1", ""},
        {{1, 3, 132, 0, 35}, "secp521r1", ""},
        {{1, 3, 132, 0, 36}, "sect409k1", ""},
        {{1, 3, 132, 0, 37}, "sect409r1", ""},
        {{1, 3, 132, 0, 38}, "sect571k1", ""},
        {{1, 3, 132, 0, 39}, "sect571r1", ""},
        // http://oidref.com/2.5.4
        {{2, 5, 4}, "", "joint-iso-itu-t(2) ds(5) attributeType(4)"},
        {{2, 5, 4, 0}, "objectClass", ""},
        {{2, 5, 4, 1}, "aliasedEntryName", ""},
        {{2, 5, 4, 2}, "knowledgeInformation", ""},
        {{2, 5, 4, 3}, "commonName", ""},
        {{2, 5, 4, 4}, "surname", ""},
        {{2, 5, 4, 5}, "serialNumber", ""},
        {{2, 5, 4, 6}, "countryName", ""},  // RFC 2459
        {{2, 5, 4, 7}, "localityName", ""},
        {{2, 5, 4, 8}, "stateOrProvinceName", ""},
        {{2, 5, 4, 9}, "streetAddress", ""},
        {{2, 5, 4, 10}, "organizationName", ""},      // RFC 2459
        {{2, 5, 4, 11}, "organizationUnitName", ""},  // RFC 2459
        {{2, 5, 4, 12}, "title", ""},
        {{2, 5, 4, 13}, "description", ""},
        {{2, 5, 4, 14}, "searchGuide", ""},
        {{2, 5, 4, 15}, "businessCategory", ""},
        {{2, 5, 4, 16}, "postalAddress", ""},
        {{2, 5, 4, 17}, "postalCode", ""},
        {{2, 5, 4, 18}, "postOfficeBox", ""},
        // http://oidref.com/2.5.29
        {{2, 5, 29}, "", "joint-iso-itu-t(2) ds(5) certificateExtension(29)"},
        {{2, 5, 29, 1}, "authorityKeyIdentifier", ""},
        {{2, 5, 29, 2}, "keyAttributes", ""},
        {{2, 5, 29, 3}, "certificatePolicies", ""},
        {{2, 5, 29, 4}, "keyUsageRestriction", ""},
        {{2, 5, 29, 5}, "policyMapping", ""},
        {{2, 5, 29, 6}, "subtreesConstraint", ""},
        {{2, 5, 29, 7}, "subjectAltName", ""},
        {{2, 5, 29, 8}, "issuerAltName", ""},
        {{2, 5, 29, 9}, "subjectDirectoryAttributes", ""},
        {{2, 5, 29, 10}, "basicConstraints", ""},
        {{2, 5, 29, 14}, "subjectKeyIdentifier", ""},  // X.509
        {{2, 5, 29, 15}, "keyUsage", ""},              // X.509
        {{2, 5, 29, 16}, "privateKeyUsagePeriod", ""},
        {{2, 5, 29, 17}, "subjectAltName", ""},  // X.509
        {{2, 5, 29, 18}, "issuerAltName", ""},
        {{2, 5, 29, 19}, "basicConstraints", ""},  // X.509
        {{2, 5, 29, 20}, "cRLNumber", ""},
        {{2, 5, 29, 21}, "reasonCode", ""},
        {{2, 5, 29, 22}, "expirationDate", ""},
        {{2, 5, 29, 23}, "instructionCode", ""},
        {{2, 5, 29, 24}, "invalidityDate", ""},
        {{2, 5, 29, 25}, "cRLDistributionPoints", ""},
        {{2, 5, 29, 26}, "issuingDistributionPoint", ""},
        {{2, 5, 29, 27}, "deltaCRLIndicator", ""},
        {{2, 5, 29, 28}, "issuingDistributionPoint", ""},
        {{2, 5, 29, 29}, "certificateIssuer", ""},
        {{2, 5, 29, 30}, "nameConstraints", ""},
        {{2, 5, 29, 31}, "cRLDistributionPoints", ""},
        {{2, 5, 29, 32}, "certificatePolicies", ""},
        {{2, 5, 29, 33}, "policyMappings", ""},
        {{2, 5, 29, 34}, "policyConstraints", ""},
        {{2, 5, 29, 35}, "authorityKeyIdentifier", ""},  // X.509
        {{2, 5, 29, 36}, "policyConstraints", ""},
        {{2, 5, 29, 37}, "extKeyUsage", ""},  // X.509
        {{2, 5, 29, 38}, "authorityAttributeIdentifier", ""},
        {{2, 5, 29, 39}, "roleSpecCertIdentifier", ""},
        {{2, 5, 29, 40}, "cRLStreamIdentifier", ""},
        {{2, 5, 29, 41}, "basicAttConstraints", ""},
        {{2, 5, 29, 42}, "delegatedNameConstraints", ""},
        {{2, 5, 29, 43}, "timeSpecification", ""},
        {{2, 5, 29, 44}, "cRLScope", ""},
        {{2, 5, 29, 45}, "statusReferrals", ""},
        {{2, 5, 29, 46}, "freshestCRL", ""},
        {{2, 5, 29, 47}, "orderedList", ""},
        {{2, 5, 29, 48}, "attributeDescriptor", ""},
        {{2, 5, 29, 49}, "userNotice", ""},
        {{2, 5, 29, 50}, "sOAIdentifier", ""},
        {{2, 5, 29, 51}, "baseUpdateTime", ""},
        {{2, 5, 29, 52}, "acceptableCertPolicies", ""},
        {{2, 5, 29, 53}, "deltaInfo", ""},
        {{2, 5, 29, 54}, "inhibitAnyPolicy", ""},
        {{2, 5, 29, 55}, "targetInformation", ""},
        {{2, 5, 29, 56}, "noRevAvail", ""},
        {{2, 5, 29, 57}, "acceptablePrivilegePolicies", ""},
        {{2, 5, 29, 58}, "id-ce-toBeRevoked", ""},
        {{2, 5, 29, 59}, "id-ce-RevokedGroups", ""},
        {{2, 5, 29, 60}, "id-ce-expiredCertsOnCRL", ""},
        {{2, 5, 29, 61}, "indirectIssuer", ""},
        {{2, 5, 29, 62}, "id-ce-noAssertion", ""},
        {{2, 5, 29, 63}, "id-ce-aAissuingDistributionPoint", ""},
        {{2, 5, 29, 64}, "id-ce-issuedOnBehaIFOF", ""},
        {{2, 5, 29, 65}, "id-ce-singleUse", ""},
        {{2, 5, 29, 66}, "id-ce-groupAC", ""},
        {{2, 5, 29, 67}, "id-ce-allowedAttAss", ""},
        {{2, 5, 29, 68}, "id-ce-attributeMappings", ""},
        {{2, 5, 29, 69}, "id-ce-holderNameConstraints", ""},
        // http://oidref.com/2.16.840.1.101.3.4.2
        {{2, 16, 840, 1, 101, 3, 4, 2}, "", "joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2)"},
        {{2, 16, 840, 1, 101, 3, 4, 2, 1}, "SHA-256", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 2}, "SHA-384", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 3}, "SHA-512", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 4}, "SHA-224", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 5}, "SHA-512/224", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 6}, "SHA-512/256", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 7}, "SHA3-224", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 8}, "SHA3-256", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 9}, "SHA3-384", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 10}, "SHA3-512", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 11}, "SHAKE128", ""},
        {{2, 16, 840, 1, 101, 3, 4, 2, 12}, "SHAKE256", ""},
    };
    if (0 == _load) {
        critical_section_guard guard(_lock);
        if (0 == _load) {
            for (const auto& entry : table) {
                insert(entry.oid, entry.name, entry.desc);
            }
        }
    }
}

}  // namespace io
}  // namespace hotplace
