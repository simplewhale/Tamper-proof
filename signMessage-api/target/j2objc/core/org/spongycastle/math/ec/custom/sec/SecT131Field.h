//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecT131Field.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT131Field")
#ifdef RESTRICT_OrgSpongycastleMathEcCustomSecSecT131Field
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT131Field 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT131Field 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcCustomSecSecT131Field

#if !defined (OrgSpongycastleMathEcCustomSecSecT131Field_) && (INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT131Field || defined(INCLUDE_OrgSpongycastleMathEcCustomSecSecT131Field))
#define OrgSpongycastleMathEcCustomSecSecT131Field_

@class IOSLongArray;
@class JavaMathBigInteger;

@interface OrgSpongycastleMathEcCustomSecSecT131Field : NSObject

#pragma mark Public

- (instancetype)init;

+ (void)addWithLongArray:(IOSLongArray *)x
           withLongArray:(IOSLongArray *)y
           withLongArray:(IOSLongArray *)z;

+ (void)addExtWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)yy
              withLongArray:(IOSLongArray *)zz;

+ (void)addOneWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z;

+ (IOSLongArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (void)invertWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z;

+ (void)multiplyWithLongArray:(IOSLongArray *)x
                withLongArray:(IOSLongArray *)y
                withLongArray:(IOSLongArray *)z;

+ (void)multiplyAddToExtWithLongArray:(IOSLongArray *)x
                        withLongArray:(IOSLongArray *)y
                        withLongArray:(IOSLongArray *)zz;

+ (void)reduceWithLongArray:(IOSLongArray *)xx
              withLongArray:(IOSLongArray *)z;

+ (void)reduce61WithLongArray:(IOSLongArray *)z
                      withInt:(jint)zOff;

+ (void)sqrtWithLongArray:(IOSLongArray *)x
            withLongArray:(IOSLongArray *)z;

+ (void)squareWithLongArray:(IOSLongArray *)x
              withLongArray:(IOSLongArray *)z;

+ (void)squareAddToExtWithLongArray:(IOSLongArray *)x
                      withLongArray:(IOSLongArray *)zz;

+ (void)squareNWithLongArray:(IOSLongArray *)x
                     withInt:(jint)n
               withLongArray:(IOSLongArray *)z;

+ (jint)traceWithLongArray:(IOSLongArray *)x;

#pragma mark Protected

+ (void)implCompactExtWithLongArray:(IOSLongArray *)zz;

+ (void)implMultiplyWithLongArray:(IOSLongArray *)x
                    withLongArray:(IOSLongArray *)y
                    withLongArray:(IOSLongArray *)zz;

+ (void)implMulwWithLong:(jlong)x
                withLong:(jlong)y
           withLongArray:(IOSLongArray *)z
                 withInt:(jint)zOff;

+ (void)implSquareWithLongArray:(IOSLongArray *)x
                  withLongArray:(IOSLongArray *)zz;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleMathEcCustomSecSecT131Field)

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_init(OrgSpongycastleMathEcCustomSecSecT131Field *self);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT131Field *new_OrgSpongycastleMathEcCustomSecSecT131Field_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT131Field *create_OrgSpongycastleMathEcCustomSecSecT131Field_init(void);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_addWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_addExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *yy, IOSLongArray *zz);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_addOneWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT IOSLongArray *OrgSpongycastleMathEcCustomSecSecT131Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_invertWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_multiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_reduceWithLongArray_withLongArray_(IOSLongArray *xx, IOSLongArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_reduce61WithLongArray_withInt_(IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_sqrtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_squareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_squareAddToExtWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_squareNWithLongArray_withInt_withLongArray_(IOSLongArray *x, jint n, IOSLongArray *z);

FOUNDATION_EXPORT jint OrgSpongycastleMathEcCustomSecSecT131Field_traceWithLongArray_(IOSLongArray *x);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_implCompactExtWithLongArray_(IOSLongArray *zz);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_implMultiplyWithLongArray_withLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *y, IOSLongArray *zz);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_implMulwWithLong_withLong_withLongArray_withInt_(jlong x, jlong y, IOSLongArray *z, jint zOff);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT131Field_implSquareWithLongArray_withLongArray_(IOSLongArray *x, IOSLongArray *zz);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcCustomSecSecT131Field)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT131Field")
