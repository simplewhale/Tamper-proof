//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/linearalgebra/IntegerFunctions.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraIntegerFunctions")
#ifdef RESTRICT_OrgSpongycastlePqcMathLinearalgebraIntegerFunctions
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraIntegerFunctions 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraIntegerFunctions 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathLinearalgebraIntegerFunctions

#if !defined (OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_) && (INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraIntegerFunctions || defined(INCLUDE_OrgSpongycastlePqcMathLinearalgebraIntegerFunctions))
#define OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_

@class IOSByteArray;
@class IOSIntArray;
@class IOSObjectArray;
@class JavaMathBigInteger;
@class JavaSecuritySecureRandom;

@interface OrgSpongycastlePqcMathLinearalgebraIntegerFunctions : NSObject

#pragma mark Public

+ (JavaMathBigInteger *)binomialWithInt:(jint)n
                                withInt:(jint)t;

+ (jint)bitCountWithInt:(jint)a;

+ (jint)ceilLogWithJavaMathBigInteger:(JavaMathBigInteger *)a;

+ (jint)ceilLogWithInt:(jint)a;

+ (jint)ceilLog256WithInt:(jint)n;

+ (jint)ceilLog256WithLong:(jlong)n;

+ (JavaMathBigInteger *)divideAndRoundWithJavaMathBigInteger:(JavaMathBigInteger *)a
                                      withJavaMathBigInteger:(JavaMathBigInteger *)b;

+ (IOSObjectArray *)divideAndRoundWithJavaMathBigIntegerArray:(IOSObjectArray *)a
                                       withJavaMathBigInteger:(JavaMathBigInteger *)b;

+ (IOSIntArray *)extGCDWithInt:(jint)a
                       withInt:(jint)b;

+ (IOSObjectArray *)extgcdWithJavaMathBigInteger:(JavaMathBigInteger *)a
                          withJavaMathBigInteger:(JavaMathBigInteger *)b;

+ (jfloat)floatPowWithFloat:(jfloat)f
                    withInt:(jint)i;

+ (jint)floorLogWithJavaMathBigInteger:(JavaMathBigInteger *)a;

+ (jint)floorLogWithInt:(jint)a;

+ (jint)gcdWithInt:(jint)u
           withInt:(jint)v;

+ (IOSByteArray *)integerToOctetsWithJavaMathBigInteger:(JavaMathBigInteger *)val;

+ (jfloat)intRootWithInt:(jint)base
                 withInt:(jint)root;

+ (jboolean)isIncreasingWithIntArray:(IOSIntArray *)a;

+ (jint)isPowerWithInt:(jint)a
               withInt:(jint)p;

+ (jboolean)isPrimeWithInt:(jint)n;

+ (jint)jacobiWithJavaMathBigInteger:(JavaMathBigInteger *)A
              withJavaMathBigInteger:(JavaMathBigInteger *)B;

+ (JavaMathBigInteger *)leastCommonMultipleWithJavaMathBigIntegerArray:(IOSObjectArray *)numbers;

+ (jint)leastDivWithInt:(jint)a;

+ (jdouble)logWithDouble:(jdouble)x;

+ (jdouble)logWithLong:(jlong)x;

+ (jint)maxPowerWithInt:(jint)a;

+ (jlong)modWithLong:(jlong)a
            withLong:(jlong)m;

+ (jint)modInverseWithInt:(jint)a
                  withInt:(jint)mod;

+ (jlong)modInverseWithLong:(jlong)a
                   withLong:(jlong)mod;

+ (jint)modPowWithInt:(jint)a
              withInt:(jint)e
              withInt:(jint)n;

+ (JavaMathBigInteger *)nextPrimeWithLong:(jlong)n;

+ (JavaMathBigInteger *)nextProbablePrimeWithJavaMathBigInteger:(JavaMathBigInteger *)n;

+ (JavaMathBigInteger *)nextProbablePrimeWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                                        withInt:(jint)certainty;

+ (jint)nextSmallerPrimeWithInt:(jint)n;

+ (JavaMathBigInteger *)octetsToIntegerWithByteArray:(IOSByteArray *)data;

+ (JavaMathBigInteger *)octetsToIntegerWithByteArray:(IOSByteArray *)data
                                             withInt:(jint)offset
                                             withInt:(jint)length;

+ (jint)orderWithInt:(jint)g
             withInt:(jint)p;

+ (jboolean)passesSmallPrimeTestWithJavaMathBigInteger:(JavaMathBigInteger *)candidate;

+ (jint)powWithInt:(jint)a
           withInt:(jint)e;

+ (jlong)powWithLong:(jlong)a
             withInt:(jint)e;

+ (JavaMathBigInteger *)randomizeWithJavaMathBigInteger:(JavaMathBigInteger *)upperBound;

+ (JavaMathBigInteger *)randomizeWithJavaMathBigInteger:(JavaMathBigInteger *)upperBound
                           withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)prng;

+ (JavaMathBigInteger *)reduceIntoWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                  withJavaMathBigInteger:(JavaMathBigInteger *)begin
                                  withJavaMathBigInteger:(JavaMathBigInteger *)end;

+ (JavaMathBigInteger *)ressolWithJavaMathBigInteger:(JavaMathBigInteger *)a
                              withJavaMathBigInteger:(JavaMathBigInteger *)p;

+ (JavaMathBigInteger *)squareRootWithJavaMathBigInteger:(JavaMathBigInteger *)a;

@end

J2OBJC_STATIC_INIT(OrgSpongycastlePqcMathLinearalgebraIntegerFunctions)

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_jacobiWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *A, JavaMathBigInteger *B);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_ressolWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *a, JavaMathBigInteger *p);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_gcdWithInt_withInt_(jint u, jint v);

FOUNDATION_EXPORT IOSIntArray *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_extGCDWithInt_withInt_(jint a, jint b);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_divideAndRoundWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT IOSObjectArray *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_divideAndRoundWithJavaMathBigIntegerArray_withJavaMathBigInteger_(IOSObjectArray *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_ceilLogWithJavaMathBigInteger_(JavaMathBigInteger *a);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_ceilLogWithInt_(jint a);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_ceilLog256WithInt_(jint n);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_ceilLog256WithLong_(jlong n);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_floorLogWithJavaMathBigInteger_(JavaMathBigInteger *a);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_floorLogWithInt_(jint a);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_maxPowerWithInt_(jint a);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_bitCountWithInt_(jint a);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_orderWithInt_withInt_(jint g, jint p);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_reduceIntoWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *n, JavaMathBigInteger *begin, JavaMathBigInteger *end);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_powWithInt_withInt_(jint a, jint e);

FOUNDATION_EXPORT jlong OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_powWithLong_withInt_(jlong a, jint e);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_modPowWithInt_withInt_withInt_(jint a, jint e, jint n);

FOUNDATION_EXPORT IOSObjectArray *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_extgcdWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *a, JavaMathBigInteger *b);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_leastCommonMultipleWithJavaMathBigIntegerArray_(IOSObjectArray *numbers);

FOUNDATION_EXPORT jlong OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_modWithLong_withLong_(jlong a, jlong m);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_modInverseWithInt_withInt_(jint a, jint mod);

FOUNDATION_EXPORT jlong OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_modInverseWithLong_withLong_(jlong a, jlong mod);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_isPowerWithInt_withInt_(jint a, jint p);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_leastDivWithInt_(jint a);

FOUNDATION_EXPORT jboolean OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_isPrimeWithInt_(jint n);

FOUNDATION_EXPORT jboolean OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_passesSmallPrimeTestWithJavaMathBigInteger_(JavaMathBigInteger *candidate);

FOUNDATION_EXPORT jint OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_nextSmallerPrimeWithInt_(jint n);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_nextProbablePrimeWithJavaMathBigInteger_withInt_(JavaMathBigInteger *n, jint certainty);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_nextProbablePrimeWithJavaMathBigInteger_(JavaMathBigInteger *n);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_nextPrimeWithLong_(jlong n);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_binomialWithInt_withInt_(jint n, jint t);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_randomizeWithJavaMathBigInteger_(JavaMathBigInteger *upperBound);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_randomizeWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *upperBound, JavaSecuritySecureRandom *prng);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_squareRootWithJavaMathBigInteger_(JavaMathBigInteger *a);

FOUNDATION_EXPORT jfloat OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_intRootWithInt_withInt_(jint base, jint root);

FOUNDATION_EXPORT jfloat OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_floatPowWithFloat_withInt_(jfloat f, jint i);

FOUNDATION_EXPORT jdouble OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_logWithDouble_(jdouble x);

FOUNDATION_EXPORT jdouble OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_logWithLong_(jlong x);

FOUNDATION_EXPORT jboolean OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_isIncreasingWithIntArray_(IOSIntArray *a);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_integerToOctetsWithJavaMathBigInteger_(JavaMathBigInteger *val);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_octetsToIntegerWithByteArray_withInt_withInt_(IOSByteArray *data, jint offset, jint length);

FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_octetsToIntegerWithByteArray_(IOSByteArray *data);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathLinearalgebraIntegerFunctions)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraIntegerFunctions")
