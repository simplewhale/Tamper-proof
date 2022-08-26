//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/pkcs/PBEParameter.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsPBEParameter")
#ifdef RESTRICT_OrgSpongycastleAsn1PkcsPBEParameter
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsPBEParameter 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsPBEParameter 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1PkcsPBEParameter

#if !defined (OrgSpongycastleAsn1PkcsPBEParameter_) && (INCLUDE_ALL_OrgSpongycastleAsn1PkcsPBEParameter || defined(INCLUDE_OrgSpongycastleAsn1PkcsPBEParameter))
#define OrgSpongycastleAsn1PkcsPBEParameter_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastleAsn1PkcsPBEParameter : OrgSpongycastleAsn1ASN1Object {
 @public
  OrgSpongycastleAsn1ASN1Integer *iterations_;
  OrgSpongycastleAsn1ASN1OctetString *salt_;
}

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)salt
                          withInt:(jint)iterations;

+ (OrgSpongycastleAsn1PkcsPBEParameter *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getIterationCount;

- (IOSByteArray *)getSalt;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1PkcsPBEParameter)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsPBEParameter, iterations_, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsPBEParameter, salt_, OrgSpongycastleAsn1ASN1OctetString *)

FOUNDATION_EXPORT void OrgSpongycastleAsn1PkcsPBEParameter_initWithByteArray_withInt_(OrgSpongycastleAsn1PkcsPBEParameter *self, IOSByteArray *salt, jint iterations);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsPBEParameter *new_OrgSpongycastleAsn1PkcsPBEParameter_initWithByteArray_withInt_(IOSByteArray *salt, jint iterations) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsPBEParameter *create_OrgSpongycastleAsn1PkcsPBEParameter_initWithByteArray_withInt_(IOSByteArray *salt, jint iterations);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsPBEParameter *OrgSpongycastleAsn1PkcsPBEParameter_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1PkcsPBEParameter)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsPBEParameter")
