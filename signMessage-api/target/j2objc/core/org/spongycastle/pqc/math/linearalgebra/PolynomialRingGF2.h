//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/linearalgebra/PolynomialRingGF2.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2")
#ifdef RESTRICT_OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2

#if !defined (OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_) && (INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2 || defined(INCLUDE_OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2))
#define OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_

@interface OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2 : NSObject

#pragma mark Public

+ (jint)addWithInt:(jint)p
           withInt:(jint)q;

+ (jint)degreeWithInt:(jint)p;

+ (jint)degreeWithLong:(jlong)p;

+ (jint)gcdWithInt:(jint)p
           withInt:(jint)q;

+ (jint)getIrreduciblePolynomialWithInt:(jint)deg;

+ (jboolean)isIrreducibleWithInt:(jint)p;

+ (jint)modMultiplyWithInt:(jint)a
                   withInt:(jint)b
                   withInt:(jint)r;

+ (jlong)multiplyWithInt:(jint)p
                 withInt:(jint)q;

+ (jint)remainderWithInt:(jint)p
                 withInt:(jint)q;

+ (jint)restWithLong:(jlong)p
             withInt:(jint)q;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2)

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_addWithInt_withInt_(jint p, jint q);

FOUNDATION_EXPORT jlong OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_multiplyWithInt_withInt_(jint p, jint q);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_modMultiplyWithInt_withInt_withInt_(jint a, jint b, jint r);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_degreeWithInt_(jint p);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_degreeWithLong_(jlong p);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_remainderWithInt_withInt_(jint p, jint q);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_restWithLong_withInt_(jlong p, jint q);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_gcdWithInt_withInt_(jint p, jint q);

FOUNDATION_EXPORT jboolean OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_isIrreducibleWithInt_(jint p);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2_getIrreduciblePolynomialWithInt_(jint deg);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPolynomialRingGF2")