//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/eac/CVCertificateRequest.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificateRequest")
#ifdef RESTRICT_OrgSpongycastleAsn1EacCVCertificateRequest
#define INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificateRequest 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificateRequest 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1EacCVCertificateRequest

#if !defined (OrgSpongycastleAsn1EacCVCertificateRequest_) && (INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificateRequest || defined(INCLUDE_OrgSpongycastleAsn1EacCVCertificateRequest))
#define OrgSpongycastleAsn1EacCVCertificateRequest_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1EacCertificateBody;
@class OrgSpongycastleAsn1EacPublicKeyDataObject;

@interface OrgSpongycastleAsn1EacCVCertificateRequest : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (OrgSpongycastleAsn1EacCertificateBody *)getCertificateBody;

- (IOSByteArray *)getInnerSignature;

+ (OrgSpongycastleAsn1EacCVCertificateRequest *)getInstanceWithId:(id)obj;

- (IOSByteArray *)getOuterSignature;

- (OrgSpongycastleAsn1EacPublicKeyDataObject *)getPublicKey;

- (jboolean)hasOuterSignature;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1EacCVCertificateRequest)

FOUNDATION_EXPORT OrgSpongycastleAsn1EacCVCertificateRequest *OrgSpongycastleAsn1EacCVCertificateRequest_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1EacCVCertificateRequest)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1EacCVCertificateRequest")
