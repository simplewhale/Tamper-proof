//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/ntru/polynomial/DenseTernaryPolynomial.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial")
#ifdef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial

#if !defined (OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_) && (INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial || defined(INCLUDE_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial))
#define OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_

#define RESTRICT_OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial 1
#define INCLUDE_OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial 1
#include "org/spongycastle/pqc/math/ntru/polynomial/IntegerPolynomial.h"

#define RESTRICT_OrgSpongycastlePqcMathNtruPolynomialTernaryPolynomial 1
#define INCLUDE_OrgSpongycastlePqcMathNtruPolynomialTernaryPolynomial 1
#include "org/spongycastle/pqc/math/ntru/polynomial/TernaryPolynomial.h"

@class IOSIntArray;
@class JavaSecuritySecureRandom;
@class OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial;

@interface OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial : OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial < OrgSpongycastlePqcMathNtruPolynomialTernaryPolynomial >

#pragma mark Public

- (instancetype)initWithIntArray:(IOSIntArray *)coeffs;

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)intPoly;

+ (OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *)generateRandomWithInt:(jint)N
                                                                              withInt:(jint)numOnes
                                                                              withInt:(jint)numNegOnes
                                                         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *)generateRandomWithInt:(jint)N
                                                         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (IOSIntArray *)getNegOnes;

- (IOSIntArray *)getOnes;

- (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)poly2
                                                                                                                 withInt:(jint)modulus;

- (jint)size;

#pragma mark Package-Private

- (instancetype)initWithInt:(jint)N;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial)

FOUNDATION_EXPORT void OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithInt_(OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *self, jint N);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *new_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithInt_(jint N) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *create_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithInt_(jint N);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_(OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *self, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *intPoly);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *new_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *intPoly) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *create_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *intPoly);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithIntArray_(OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *self, IOSIntArray *coeffs);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *new_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithIntArray_(IOSIntArray *coeffs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *create_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithIntArray_(IOSIntArray *coeffs);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(jint N, jint numOnes, jint numNegOnes, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial *OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_generateRandomWithInt_withJavaSecuritySecureRandom_(jint N, JavaSecuritySecureRandom *random);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial")
