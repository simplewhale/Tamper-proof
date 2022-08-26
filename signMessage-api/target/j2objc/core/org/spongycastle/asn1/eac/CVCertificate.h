//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/eac/CVCertificate.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificate")
#ifdef RESTRICT_OrgSpongycastleAsn1EacCVCertificate
#define INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificate 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificate 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1EacCVCertificate

#if !defined (OrgSpongycastleAsn1EacCVCertificate_) && (INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificate || defined(INCLUDE_OrgSpongycastleAsn1EacCVCertificate))
#define OrgSpongycastleAsn1EacCVCertificate_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1InputStream;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1EacCertificateBody;
@class OrgSpongycastleAsn1EacCertificateHolderReference;
@class OrgSpongycastleAsn1EacCertificationAuthorityReference;
@class OrgSpongycastleAsn1EacFlags;
@class OrgSpongycastleAsn1EacPackedDate;

@interface OrgSpongycastleAsn1EacCVCertificate : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1InputStream:(OrgSpongycastleAsn1ASN1InputStream *)aIS;

- (instancetype)initWithOrgSpongycastleAsn1EacCertificateBody:(OrgSpongycastleAsn1EacCertificateBody *)body
                                                withByteArray:(IOSByteArray *)signature;

- (OrgSpongycastleAsn1EacCertificationAuthorityReference *)getAuthorityReference;

- (OrgSpongycastleAsn1EacCertificateBody *)getBody;

- (jint)getCertificateType;

- (OrgSpongycastleAsn1EacPackedDate *)getEffectiveDate;

- (OrgSpongycastleAsn1EacPackedDate *)getExpirationDate;

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getHolderAuthorization;

- (OrgSpongycastleAsn1EacFlags *)getHolderAuthorizationRights;

- (jint)getHolderAuthorizationRole;

- (OrgSpongycastleAsn1EacCertificateHolderReference *)getHolderReference;

+ (OrgSpongycastleAsn1EacCVCertificate *)getInstanceWithId:(id)obj;

- (jint)getRole;

- (IOSByteArray *)getSignature;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1EacCVCertificate)

FOUNDATION_EXPORT void OrgSpongycastleAsn1EacCVCertificate_initWithOrgSpongycastleAsn1ASN1InputStream_(OrgSpongycastleAsn1EacCVCertificate *self, OrgSpongycastleAsn1ASN1InputStream *aIS);

FOUNDATION_EXPORT OrgSpongycastleAsn1EacCVCertificate *new_OrgSpongycastleAsn1EacCVCertificate_initWithOrgSpongycastleAsn1ASN1InputStream_(OrgSpongycastleAsn1ASN1InputStream *aIS) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EacCVCertificate *create_OrgSpongycastleAsn1EacCVCertificate_initWithOrgSpongycastleAsn1ASN1InputStream_(OrgSpongycastleAsn1ASN1InputStream *aIS);

FOUNDATION_EXPORT void OrgSpongycastleAsn1EacCVCertificate_initWithOrgSpongycastleAsn1EacCertificateBody_withByteArray_(OrgSpongycastleAsn1EacCVCertificate *self, OrgSpongycastleAsn1EacCertificateBody *body, IOSByteArray *signature);

FOUNDATION_EXPORT OrgSpongycastleAsn1EacCVCertificate *new_OrgSpongycastleAsn1EacCVCertificate_initWithOrgSpongycastleAsn1EacCertificateBody_withByteArray_(OrgSpongycastleAsn1EacCertificateBody *body, IOSByteArray *signature) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1EacCVCertificate *create_OrgSpongycastleAsn1EacCVCertificate_initWithOrgSpongycastleAsn1EacCertificateBody_withByteArray_(OrgSpongycastleAsn1EacCertificateBody *body, IOSByteArray *signature);

FOUNDATION_EXPORT OrgSpongycastleAsn1EacCVCertificate *OrgSpongycastleAsn1EacCVCertificate_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1EacCVCertificate)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificate")
