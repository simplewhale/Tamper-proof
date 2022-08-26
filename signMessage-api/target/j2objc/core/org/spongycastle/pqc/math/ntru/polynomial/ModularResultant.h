//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/ntru/polynomial/ModularResultant.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialModularResultant")
#ifdef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialModularResultant
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialModularResultant 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialModularResultant 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialModularResultant

#if !defined (OrgSpongycastlePqcMathNtruPolynomialModularResultant_) && (INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialModularResultant || defined(INCLUDE_OrgSpongycastlePqcMathNtruPolynomialModularResultant))
#define OrgSpongycastlePqcMathNtruPolynomialModularResultant_

#define RESTRICT_OrgSpongycastlePqcMathNtruPolynomialResultant 1
#define INCLUDE_OrgSpongycastlePqcMathNtruPolynomialResultant 1
#include "org/spongycastle/pqc/math/ntru/polynomial/Resultant.h"

@class JavaMathBigInteger;
@class OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial;

@interface OrgSpongycastlePqcMathNtruPolynomialModularResultant : OrgSpongycastlePqcMathNtruPolynomialResultant {
 @public
  JavaMathBigInteger *modulus_;
}

#pragma mark Package-Private

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)rho
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)res
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)modulus;

+ (OrgSpongycastlePqcMathNtruPolynomialModularResultant *)combineRhoWithOrgSpongycastlePqcMathNtruPolynomialModularResultant:(OrgSpongycastlePqcMathNtruPolynomialModularResultant *)modRes1
                                                                    withOrgSpongycastlePqcMathNtruPolynomialModularResultant:(OrgSpongycastlePqcMathNtruPolynomialModularResultant *)modRes2;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)arg0
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathNtruPolynomialModularResultant)

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcMathNtruPolynomialModularResultant, modulus_, JavaMathBigInteger *)

FOUNDATION_EXPORT void OrgSpongycastlePqcMathNtruPolynomialModularResultant_initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastlePqcMathNtruPolynomialModularResultant *self, OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res, JavaMathBigInteger *modulus);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialModularResultant *new_OrgSpongycastlePqcMathNtruPolynomialModularResultant_initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res, JavaMathBigInteger *modulus) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialModularResultant *create_OrgSpongycastlePqcMathNtruPolynomialModularResultant_initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *rho, JavaMathBigInteger *res, JavaMathBigInteger *modulus);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialModularResultant *OrgSpongycastlePqcMathNtruPolynomialModularResultant_combineRhoWithOrgSpongycastlePqcMathNtruPolynomialModularResultant_withOrgSpongycastlePqcMathNtruPolynomialModularResultant_(OrgSpongycastlePqcMathNtruPolynomialModularResultant *modRes1, OrgSpongycastlePqcMathNtruPolynomialModularResultant *modRes2);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathNtruPolynomialModularResultant)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialModularResultant")
