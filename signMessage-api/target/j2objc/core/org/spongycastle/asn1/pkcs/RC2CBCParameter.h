//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/pkcs/RC2CBCParameter.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsRC2CBCParameter")
#ifdef RESTRICT_OrgSpongycastleAsn1PkcsRC2CBCParameter
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsRC2CBCParameter 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsRC2CBCParameter 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1PkcsRC2CBCParameter

#if !defined (OrgSpongycastleAsn1PkcsRC2CBCParameter_) && (INCLUDE_ALL_OrgSpongycastleAsn1PkcsRC2CBCParameter || defined(INCLUDE_OrgSpongycastleAsn1PkcsRC2CBCParameter))
#define OrgSpongycastleAsn1PkcsRC2CBCParameter_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class OrgSpongycastleAsn1ASN1Integer;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;

@interface OrgSpongycastleAsn1PkcsRC2CBCParameter : OrgSpongycastleAsn1ASN1Object {
 @public
  OrgSpongycastleAsn1ASN1Integer *version__;
  OrgSpongycastleAsn1ASN1OctetString *iv_;
}

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)iv;

- (instancetype)initWithInt:(jint)parameterVersion
              withByteArray:(IOSByteArray *)iv;

+ (OrgSpongycastleAsn1PkcsRC2CBCParameter *)getInstanceWithId:(id)o;

- (IOSByteArray *)getIV;

- (JavaMathBigInteger *)getRC2ParameterVersion;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1PkcsRC2CBCParameter)

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsRC2CBCParameter, version__, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsRC2CBCParameter, iv_, OrgSpongycastleAsn1ASN1OctetString *)

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRC2CBCParameter *OrgSpongycastleAsn1PkcsRC2CBCParameter_getInstanceWithId_(id o);

FOUNDATION_EXPORT void OrgSpongycastleAsn1PkcsRC2CBCParameter_initWithByteArray_(OrgSpongycastleAsn1PkcsRC2CBCParameter *self, IOSByteArray *iv);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRC2CBCParameter *new_OrgSpongycastleAsn1PkcsRC2CBCParameter_initWithByteArray_(IOSByteArray *iv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRC2CBCParameter *create_OrgSpongycastleAsn1PkcsRC2CBCParameter_initWithByteArray_(IOSByteArray *iv);

FOUNDATION_EXPORT void OrgSpongycastleAsn1PkcsRC2CBCParameter_initWithInt_withByteArray_(OrgSpongycastleAsn1PkcsRC2CBCParameter *self, jint parameterVersion, IOSByteArray *iv);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRC2CBCParameter *new_OrgSpongycastleAsn1PkcsRC2CBCParameter_initWithInt_withByteArray_(jint parameterVersion, IOSByteArray *iv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRC2CBCParameter *create_OrgSpongycastleAsn1PkcsRC2CBCParameter_initWithInt_withByteArray_(jint parameterVersion, IOSByteArray *iv);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1PkcsRC2CBCParameter)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsRC2CBCParameter")
