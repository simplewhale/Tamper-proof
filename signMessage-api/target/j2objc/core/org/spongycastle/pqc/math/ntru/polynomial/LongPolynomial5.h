//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/ntru/polynomial/LongPolynomial5.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5")
#ifdef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5

#if !defined (OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5_) && (INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5 || defined(INCLUDE_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5))
#define OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5_

@class OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;
@protocol OrgSpongycastlePqcMathNtruPolynomialTernaryPolynomial;

@interface OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5 : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)p;

- (OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5 *)multWithOrgSpongycastlePqcMathNtruPolynomialTernaryPolynomial:(id<OrgSpongycastlePqcMathNtruPolynomialTernaryPolynomial>)poly2;

- (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)toIntegerPolynomial;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5)

FOUNDATION_EXPORT void OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_(OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5 *self, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *p);

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5 *new_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *p) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5 *create_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *p);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruPolynomialLongPolynomial5")
