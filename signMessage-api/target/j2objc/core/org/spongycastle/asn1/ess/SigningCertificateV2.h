//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ess/SigningCertificateV2.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1EssSigningCertificateV2")
#ifdef RESTRICT_OrgSpongycastleAsn1EssSigningCertificateV2
#define INCLUDE_ALL_OrgSpongycastleAsn1EssSigningCertificateV2 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1EssSigningCertificateV2 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1EssSigningCertificateV2

#if !defined (OrgSpongycastleAsn1EssSigningCertificateV2_) && (INCLUDE_ALL_OrgSpongycastleAsn1EssSigningCertificateV2 || defined(INCLUDE_OrgSpongycastleAsn1EssSigningCertificateV2))
#define OrgSpongycastleAsn1EssSigningCertificateV2_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSObjectArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1EssESSCertIDv2;

@interface OrgSpongycastleAsn1EssSigningCertificateV2 : OrgSpongycastleAsn1ASN1Object {
 @public
  OrgSpongycastleAsn1ASN1Sequence *certs_;
  OrgSpongycastleAsn1ASN1Sequence *policies_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1EssESSCertIDv2:(OrgSpongycastleAsn1EssESSCertIDv2 *)cert;

- (instancetype)initWithOrgSpongycastleAsn1EssESSCertIDv2Array:(IOSObjectArray *)certs;

- (instancetype)initWithOrgSpongycastleAsn1EssESSCertIDv2Array:(IOSObjectArray *)certs
             withOrgSpongycastleAsn1X509PolicyInformationArray:(IOSObjectArray *)policies;

- (IOSObjectArray *)getCerts;

+ (OrgSpongycastleAsn1EssSigningCertificateV2 *)getInstanceWithId:(id)o;

- (IOSObjectArray *)getPolicies;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1EssSigningCertificateV2)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1EssSigningCertificateV2, certs_, OrgSpongycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1EssSigningCertificateV2, policies_, OrgSpongycastleAsn1ASN1Sequence *)

FOUNDATION_EXPORT OrgSpongycastleAsn1EssSigningCertificateV2 *OrgSpongycastleAsn1EssSigningCertificateV2_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2_(OrgSpongycastleAsn1EssSigningCertificateV2 *self, OrgSpongycastleAsn1EssESSCertIDv2 *cert);

FOUNDATION_EXPORT OrgSpongycastleAsn1EssSigningCertificateV2 *new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2_(OrgSpongycastleAsn1EssESSCertIDv2 *cert) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EssSigningCertificateV2 *create_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2_(OrgSpongycastleAsn1EssESSCertIDv2 *cert);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_(OrgSpongycastleAsn1EssSigningCertificateV2 *self, IOSObjectArray *certs);

FOUNDATION_EXPORT OrgSpongycastleAsn1EssSigningCertificateV2 *new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_(IOSObjectArray *certs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EssSigningCertificateV2 *create_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_(IOSObjectArray *certs);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_(OrgSpongycastleAsn1EssSigningCertificateV2 *self, IOSObjectArray *certs, IOSObjectArray *policies);

FOUNDATION_EXPORT OrgSpongycastleAsn1EssSigningCertificateV2 *new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_(IOSObjectArray *certs, IOSObjectArray *policies) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EssSigningCertificateV2 *create_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_(IOSObjectArray *certs, IOSObjectArray *policies);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1EssSigningCertificateV2)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1EssSigningCertificateV2")