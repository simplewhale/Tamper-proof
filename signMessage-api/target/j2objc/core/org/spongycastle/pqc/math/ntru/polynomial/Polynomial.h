//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/ntru/polynomial/Polynomial.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialPolynomial")
#ifdef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialPolynomial
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialPolynomial 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialPolynomial 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialPolynomial

#if !defined (OrgSpongycastlePqcMathNtruPolynomialPolynomial_) && (INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialPolynomial || defined(INCLUDE_OrgSpongycastlePqcMathNtruPolynomialPolynomial))
#define OrgSpongycastlePqcMathNtruPolynomialPolynomial_

@class OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial;
@class OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;

@protocol OrgSpongycastlePqcMathNtruPolynomialPolynomial < JavaObject >

- (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)poly2;

- (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)poly2
                                                                                                                 withInt:(jint)modulus;

- (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)toIntegerPolynomial;

- (OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:(OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *)poly2;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathNtruPolynomialPolynomial)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathNtruPolynomialPolynomial)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialPolynomial")
