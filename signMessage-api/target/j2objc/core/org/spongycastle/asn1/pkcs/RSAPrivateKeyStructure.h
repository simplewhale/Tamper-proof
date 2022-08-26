//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/pkcs/RSAPrivateKeyStructure.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure")
#ifdef RESTRICT_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure

#if !defined (OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_) && (INCLUDE_ALL_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure || defined(INCLUDE_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure))
#define OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class JavaMathBigInteger;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1ASN1Sequence;
@class OrgSpongycastleAsn1ASN1TaggedObject;

@interface OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)modulus
                    withJavaMathBigInteger:(JavaMathBigInteger *)publicExponent
                    withJavaMathBigInteger:(JavaMathBigInteger *)privateExponent
                    withJavaMathBigInteger:(JavaMathBigInteger *)prime1
                    withJavaMathBigInteger:(JavaMathBigInteger *)prime2
                    withJavaMathBigInteger:(JavaMathBigInteger *)exponent1
                    withJavaMathBigInteger:(JavaMathBigInteger *)exponent2
                    withJavaMathBigInteger:(JavaMathBigInteger *)coefficient;

- (JavaMathBigInteger *)getCoefficient;

- (JavaMathBigInteger *)getExponent1;

- (JavaMathBigInteger *)getExponent2;

+ (OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                          withBoolean:(jboolean)explicit_;

+ (OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getModulus;

- (JavaMathBigInteger *)getPrime1;

- (JavaMathBigInteger *)getPrime2;

- (JavaMathBigInteger *)getPrivateExponent;

- (JavaMathBigInteger *)getPublicExponent;

- (jint)getVersion;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure)

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *self, JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *prime1, JavaMathBigInteger *prime2, JavaMathBigInteger *exponent1, JavaMathBigInteger *exponent2, JavaMathBigInteger *coefficient);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *new_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *prime1, JavaMathBigInteger *prime2, JavaMathBigInteger *exponent1, JavaMathBigInteger *exponent2, JavaMathBigInteger *coefficient) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *create_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *prime1, JavaMathBigInteger *prime2, JavaMathBigInteger *exponent1, JavaMathBigInteger *exponent2, JavaMathBigInteger *coefficient);

FOUNDATION_EXPORT void OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *self, OrgSpongycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *new_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure *create_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1PkcsRSAPrivateKeyStructure")
