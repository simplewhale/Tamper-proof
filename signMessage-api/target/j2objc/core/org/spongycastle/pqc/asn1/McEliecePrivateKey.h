//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/asn1/McEliecePrivateKey.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcAsn1McEliecePrivateKey")
#ifdef RESTRICT_OrgSpongycastlePqcAsn1McEliecePrivateKey
#define INCLUDE_ALL_OrgSpongycastlePqcAsn1McEliecePrivateKey 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcAsn1McEliecePrivateKey 1
#endif
#undef RESTRICT_OrgSpongycastlePqcAsn1McEliecePrivateKey

#if !defined (OrgSpongycastlePqcAsn1McEliecePrivateKey_) && (INCLUDE_ALL_OrgSpongycastlePqcAsn1McEliecePrivateKey || defined(INCLUDE_OrgSpongycastlePqcAsn1McEliecePrivateKey))
#define OrgSpongycastlePqcAsn1McEliecePrivateKey_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastlePqcMathLinearalgebraGF2Matrix;
@class OrgSpongycastlePqcMathLinearalgebraGF2mField;
@class OrgSpongycastlePqcMathLinearalgebraPermutation;
@class OrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM;

@interface OrgSpongycastlePqcAsn1McEliecePrivateKey : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithInt:(jint)n
                    withInt:(jint)k
withOrgSpongycastlePqcMathLinearalgebraGF2mField:(OrgSpongycastlePqcMathLinearalgebraGF2mField *)field
withOrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM:(OrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM *)goppaPoly
withOrgSpongycastlePqcMathLinearalgebraPermutation:(OrgSpongycastlePqcMathLinearalgebraPermutation *)p1
withOrgSpongycastlePqcMathLinearalgebraPermutation:(OrgSpongycastlePqcMathLinearalgebraPermutation *)p2
withOrgSpongycastlePqcMathLinearalgebraGF2Matrix:(OrgSpongycastlePqcMathLinearalgebraGF2Matrix *)sInv;

- (OrgSpongycastlePqcMathLinearalgebraGF2mField *)getField;

- (OrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM *)getGoppaPoly;

+ (OrgSpongycastlePqcAsn1McEliecePrivateKey *)getInstanceWithId:(id)o;

- (jint)getK;

- (jint)getN;

- (OrgSpongycastlePqcMathLinearalgebraPermutation *)getP1;

- (OrgSpongycastlePqcMathLinearalgebraPermutation *)getP2;

- (OrgSpongycastlePqcMathLinearalgebraGF2Matrix *)getSInv;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcAsn1McEliecePrivateKey)

FOUNDATION_EXPORT void OrgSpongycastlePqcAsn1McEliecePrivateKey_initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2mField_withOrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withOrgSpongycastlePqcMathLinearalgebraPermutation_withOrgSpongycastlePqcMathLinearalgebraPermutation_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_(OrgSpongycastlePqcAsn1McEliecePrivateKey *self, jint n, jint k, OrgSpongycastlePqcMathLinearalgebraGF2mField *field, OrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM *goppaPoly, OrgSpongycastlePqcMathLinearalgebraPermutation *p1, OrgSpongycastlePqcMathLinearalgebraPermutation *p2, OrgSpongycastlePqcMathLinearalgebraGF2Matrix *sInv);

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1McEliecePrivateKey *new_OrgSpongycastlePqcAsn1McEliecePrivateKey_initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2mField_withOrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withOrgSpongycastlePqcMathLinearalgebraPermutation_withOrgSpongycastlePqcMathLinearalgebraPermutation_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_(jint n, jint k, OrgSpongycastlePqcMathLinearalgebraGF2mField *field, OrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM *goppaPoly, OrgSpongycastlePqcMathLinearalgebraPermutation *p1, OrgSpongycastlePqcMathLinearalgebraPermutation *p2, OrgSpongycastlePqcMathLinearalgebraGF2Matrix *sInv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1McEliecePrivateKey *create_OrgSpongycastlePqcAsn1McEliecePrivateKey_initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2mField_withOrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM_withOrgSpongycastlePqcMathLinearalgebraPermutation_withOrgSpongycastlePqcMathLinearalgebraPermutation_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_(jint n, jint k, OrgSpongycastlePqcMathLinearalgebraGF2mField *field, OrgSpongycastlePqcMathLinearalgebraPolynomialGF2mSmallM *goppaPoly, OrgSpongycastlePqcMathLinearalgebraPermutation *p1, OrgSpongycastlePqcMathLinearalgebraPermutation *p2, OrgSpongycastlePqcMathLinearalgebraGF2Matrix *sInv);

FOUNDATION_EXPORT OrgSpongycastlePqcAsn1McEliecePrivateKey *OrgSpongycastlePqcAsn1McEliecePrivateKey_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcAsn1McEliecePrivateKey)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcAsn1McEliecePrivateKey")