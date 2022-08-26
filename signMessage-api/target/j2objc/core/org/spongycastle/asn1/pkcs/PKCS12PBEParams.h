//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/pkcs/PKCS12PBEParams.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsPKCS12PBEParams")
#ifdef RESTRICT_OrgSpongycastleAsn1PkcsPKCS12PBEParams
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsPKCS12PBEParams 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsPKCS12PBEParams 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1PkcsPKCS12PBEParams

#if !defined (OrgSpongycastleAsn1PkcsPKCS12PBEParams_) && (INCLUDE_ALL_OrgSpongycastleAsn1PkcsPKCS12PBEParams || defined(INCLUDE_OrgSpongycastleAsn1PkcsPKCS12PBEParams))
#define OrgSpongycastleAsn1PkcsPKCS12PBEParams_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastleAsn1PkcsPKCS12PBEParams : OrgSpongycastleAsn1ASN1Object {
 @public
  OrgSpongycastleAsn1ASN1Integer *iterations_;
  OrgSpongycastleAsn1ASN1OctetString *iv_;
}

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)salt
                          withInt:(jint)iterations;

+ (OrgSpongycastleAsn1PkcsPKCS12PBEParams *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getIterations;

- (IOSByteArray *)getIV;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1PkcsPKCS12PBEParams)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsPKCS12PBEParams, iterations_, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsPKCS12PBEParams, iv_, OrgSpongycastleAsn1ASN1OctetString *)

FOUNDATION_EXPORT void OrgSpongycastleAsn1PkcsPKCS12PBEParams_initWithByteArray_withInt_(OrgSpongycastleAsn1PkcsPKCS12PBEParams *self, IOSByteArray *salt, jint iterations);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsPKCS12PBEParams *new_OrgSpongycastleAsn1PkcsPKCS12PBEParams_initWithByteArray_withInt_(IOSByteArray *salt, jint iterations) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsPKCS12PBEParams *create_OrgSpongycastleAsn1PkcsPKCS12PBEParams_initWithByteArray_withInt_(IOSByteArray *salt, jint iterations);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsPKCS12PBEParams *OrgSpongycastleAsn1PkcsPKCS12PBEParams_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1PkcsPKCS12PBEParams)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsPKCS12PBEParams")