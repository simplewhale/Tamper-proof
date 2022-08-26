//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/CertStatus.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpCertStatus")
#ifdef RESTRICT_OrgSpongycastleAsn1CmpCertStatus
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpCertStatus 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1CmpCertStatus 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1CmpCertStatus

#if !defined (OrgSpongycastleAsn1CmpCertStatus_) && (INCLUDE_ALL_OrgSpongycastleAsn1CmpCertStatus || defined(INCLUDE_OrgSpongycastleAsn1CmpCertStatus))
#define OrgSpongycastleAsn1CmpCertStatus_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1CmpPKIStatusInfo;

@interface OrgSpongycastleAsn1CmpCertStatus : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)certHash
           withJavaMathBigInteger:(JavaMathBigInteger *)certReqId;

- (instancetype)initWithByteArray:(IOSByteArray *)certHash
           withJavaMathBigInteger:(JavaMathBigInteger *)certReqId
withOrgSpongycastleAsn1CmpPKIStatusInfo:(OrgSpongycastleAsn1CmpPKIStatusInfo *)statusInfo;

- (OrgSpongycastleAsn1ASN1OctetString *)getCertHash;

- (OrgSpongycastleAsn1ASN1Integer *)getCertReqId;

+ (OrgSpongycastleAsn1CmpCertStatus *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1CmpPKIStatusInfo *)getStatusInfo;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1CmpCertStatus)

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_(OrgSpongycastleAsn1CmpCertStatus *self, IOSByteArray *certHash, JavaMathBigInteger *certReqId);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpCertStatus *new_OrgSpongycastleAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_(IOSByteArray *certHash, JavaMathBigInteger *certReqId) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpCertStatus *create_OrgSpongycastleAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_(IOSByteArray *certHash, JavaMathBigInteger *certReqId);

FOUNDATION_EXPORT void OrgSpongycastleAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_withOrgSpongycastleAsn1CmpPKIStatusInfo_(OrgSpongycastleAsn1CmpCertStatus *self, IOSByteArray *certHash, JavaMathBigInteger *certReqId, OrgSpongycastleAsn1CmpPKIStatusInfo *statusInfo);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpCertStatus *new_OrgSpongycastleAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_withOrgSpongycastleAsn1CmpPKIStatusInfo_(IOSByteArray *certHash, JavaMathBigInteger *certReqId, OrgSpongycastleAsn1CmpPKIStatusInfo *statusInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpCertStatus *create_OrgSpongycastleAsn1CmpCertStatus_initWithByteArray_withJavaMathBigInteger_withOrgSpongycastleAsn1CmpPKIStatusInfo_(IOSByteArray *certHash, JavaMathBigInteger *certReqId, OrgSpongycastleAsn1CmpPKIStatusInfo *statusInfo);

FOUNDATION_EXPORT OrgSpongycastleAsn1CmpCertStatus *OrgSpongycastleAsn1CmpCertStatus_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1CmpCertStatus)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1CmpCertStatus")
