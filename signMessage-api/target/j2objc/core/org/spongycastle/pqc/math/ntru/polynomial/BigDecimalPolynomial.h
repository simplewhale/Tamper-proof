//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/ntru/polynomial/BigDecimalPolynomial.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial")
#ifdef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial

#if !defined (OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_) && (INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial || defined(INCLUDE_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial))
#define OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_

@class IOSObjectArray;
@class OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial;

@interface OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial : NSObject {
 @public
  IOSObjectArray *coeffs_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)p;

- (void)addWithOrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *)b;

- (id)java_clone;

- (IOSObjectArray *)getCoeffs;

- (void)halve;

- (OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *)poly2;

- (OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)poly2;

- (OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)round;

#pragma mark Package-Private

- (instancetype)initWithJavaMathBigDecimalArray:(IOSObjectArray *)coeffs;

- (instancetype)initWithInt:(jint)N;

- (void)subWithOrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *)b;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial)

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial, coeffs_, IOSObjectArray *)

FOUNDATION_EXPORT void OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, jint N);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(jint N) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(jint N);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, IOSObjectArray *coeffs);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(IOSObjectArray *coeffs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(IOSObjectArray *coeffs);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial_(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *p);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial_(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *p) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial_(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *p);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial")
