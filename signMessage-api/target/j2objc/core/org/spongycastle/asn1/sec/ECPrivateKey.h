//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/sec/ECPrivateKey.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1SecECPrivateKey")
#ifdef RESTRICT_OrgSpongycastleAsn1SecECPrivateKey
#define INCLUDE_ALL_OrgSpongycastleAsn1SecECPrivateKey 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1SecECPrivateKey 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1SecECPrivateKey

#if !defined (OrgSpongycastleAsn1SecECPrivateKey_) && (INCLUDE_ALL_OrgSpongycastleAsn1SecECPrivateKey || defined(INCLUDE_OrgSpongycastleAsn1SecECPrivateKey))
#define OrgSpongycastleAsn1SecECPrivateKey_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class JavaMathBigInteger;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1DERBitString;
@protocol OrgSpongycastleAsn1ASN1Encodable;

@interface OrgSpongycastleAsn1SecECPrivateKey : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)key;

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)key
      withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)parameters;

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)key
       withOrgSpongycastleAsn1DERBitString:(OrgSpongycastleAsn1DERBitString *)publicKey
      withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)parameters;

- (instancetype)initWithInt:(jint)orderBitLength
     withJavaMathBigInteger:(JavaMathBigInteger *)key;

- (instancetype)initWithInt:(jint)orderBitLength
     withJavaMathBigInteger:(JavaMathBigInteger *)key
withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)parameters;

- (instancetype)initWithInt:(jint)orderBitLength
     withJavaMathBigInteger:(JavaMathBigInteger *)key
withOrgSpongycastleAsn1DERBitString:(OrgSpongycastleAsn1DERBitString *)publicKey
withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)parameters;

+ (OrgSpongycastleAsn1SecECPrivateKey *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getKey;

- (OrgSpongycastleAsn1ASN1Primitive *)getParameters;

- (OrgSpongycastleAsn1DERBitString *)getPublicKey;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1SecECPrivateKey)

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *OrgSpongycastleAsn1SecECPrivateKey_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_(OrgSpongycastleAsn1SecECPrivateKey *self, JavaMathBigInteger *key);

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *new_OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_(JavaMathBigInteger *key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *create_OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_(JavaMathBigInteger *key);

FOUNDATION_EXPORT void OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_(OrgSpongycastleAsn1SecECPrivateKey *self, jint orderBitLength, JavaMathBigInteger *key);

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *new_OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_(jint orderBitLength, JavaMathBigInteger *key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *create_OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_(jint orderBitLength, JavaMathBigInteger *key);

FOUNDATION_EXPORT void OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1SecECPrivateKey *self, JavaMathBigInteger *key, id<OrgSpongycastleAsn1ASN1Encodable> parameters);

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *new_OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_withOrgSpongycastleAsn1ASN1Encodable_(JavaMathBigInteger *key, id<OrgSpongycastleAsn1ASN1Encodable> parameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *create_OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_withOrgSpongycastleAsn1ASN1Encodable_(JavaMathBigInteger *key, id<OrgSpongycastleAsn1ASN1Encodable> parameters);

FOUNDATION_EXPORT void OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1SecECPrivateKey *self, JavaMathBigInteger *key, OrgSpongycastleAsn1DERBitString *publicKey, id<OrgSpongycastleAsn1ASN1Encodable> parameters);

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *new_OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1ASN1Encodable_(JavaMathBigInteger *key, OrgSpongycastleAsn1DERBitString *publicKey, id<OrgSpongycastleAsn1ASN1Encodable> parameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *create_OrgSpongycastleAsn1SecECPrivateKey_initWithJavaMathBigInteger_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1ASN1Encodable_(JavaMathBigInteger *key, OrgSpongycastleAsn1DERBitString *publicKey, id<OrgSpongycastleAsn1ASN1Encodable> parameters);

FOUNDATION_EXPORT void OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1SecECPrivateKey *self, jint orderBitLength, JavaMathBigInteger *key, id<OrgSpongycastleAsn1ASN1Encodable> parameters);

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *new_OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1Encodable_(jint orderBitLength, JavaMathBigInteger *key, id<OrgSpongycastleAsn1ASN1Encodable> parameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *create_OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1Encodable_(jint orderBitLength, JavaMathBigInteger *key, id<OrgSpongycastleAsn1ASN1Encodable> parameters);

FOUNDATION_EXPORT void OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1SecECPrivateKey *self, jint orderBitLength, JavaMathBigInteger *key, OrgSpongycastleAsn1DERBitString *publicKey, id<OrgSpongycastleAsn1ASN1Encodable> parameters);

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *new_OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1ASN1Encodable_(jint orderBitLength, JavaMathBigInteger *key, OrgSpongycastleAsn1DERBitString *publicKey, id<OrgSpongycastleAsn1ASN1Encodable> parameters) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1SecECPrivateKey *create_OrgSpongycastleAsn1SecECPrivateKey_initWithInt_withJavaMathBigInteger_withOrgSpongycastleAsn1DERBitString_withOrgSpongycastleAsn1ASN1Encodable_(jint orderBitLength, JavaMathBigInteger *key, OrgSpongycastleAsn1DERBitString *publicKey, id<OrgSpongycastleAsn1ASN1Encodable> parameters);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1SecECPrivateKey)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1SecECPrivateKey")
