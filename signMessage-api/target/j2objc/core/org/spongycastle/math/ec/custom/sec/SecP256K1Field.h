//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecP256K1Field.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP256K1Field")
#ifdef RESTRICT_OrgSpongycastleMathEcCustomSecSecP256K1Field
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP256K1Field 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP256K1Field 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcCustomSecSecP256K1Field

#if !defined (OrgSpongycastleMathEcCustomSecSecP256K1Field_) && (INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP256K1Field || defined(INCLUDE_OrgSpongycastleMathEcCustomSecSecP256K1Field))
#define OrgSpongycastleMathEcCustomSecSecP256K1Field_

@class IOSIntArray;
@class JavaMathBigInteger;

@interface OrgSpongycastleMathEcCustomSecSecP256K1Field : NSObject

#pragma mark Public

- (instancetype)init;

+ (void)addWithIntArray:(IOSIntArray *)x
           withIntArray:(IOSIntArray *)y
           withIntArray:(IOSIntArray *)z;

+ (void)addExtWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)yy
              withIntArray:(IOSIntArray *)zz;

+ (void)addOneWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z;

+ (IOSIntArray *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

+ (void)halfWithIntArray:(IOSIntArray *)x
            withIntArray:(IOSIntArray *)z;

+ (void)multiplyWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z;

+ (void)multiplyAddToExtWithIntArray:(IOSIntArray *)x
                        withIntArray:(IOSIntArray *)y
                        withIntArray:(IOSIntArray *)zz;

+ (void)negateWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z;

+ (void)reduceWithIntArray:(IOSIntArray *)xx
              withIntArray:(IOSIntArray *)z;

+ (void)reduce32WithInt:(jint)x
           withIntArray:(IOSIntArray *)z;

+ (void)squareWithIntArray:(IOSIntArray *)x
              withIntArray:(IOSIntArray *)z;

+ (void)squareNWithIntArray:(IOSIntArray *)x
                    withInt:(jint)n
               withIntArray:(IOSIntArray *)z;

+ (void)subtractWithIntArray:(IOSIntArray *)x
                withIntArray:(IOSIntArray *)y
                withIntArray:(IOSIntArray *)z;

+ (void)subtractExtWithIntArray:(IOSIntArray *)xx
                   withIntArray:(IOSIntArray *)yy
                   withIntArray:(IOSIntArray *)zz;

+ (void)twiceWithIntArray:(IOSIntArray *)x
             withIntArray:(IOSIntArray *)z;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleMathEcCustomSecSecP256K1Field)

inline IOSIntArray *OrgSpongycastleMathEcCustomSecSecP256K1Field_get_P(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSIntArray *OrgSpongycastleMathEcCustomSecSecP256K1Field_P;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleMathEcCustomSecSecP256K1Field, P, IOSIntArray *)

inline IOSIntArray *OrgSpongycastleMathEcCustomSecSecP256K1Field_get_PExt(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSIntArray *OrgSpongycastleMathEcCustomSecSecP256K1Field_PExt;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleMathEcCustomSecSecP256K1Field, PExt, IOSIntArray *)

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_init(OrgSpongycastleMathEcCustomSecSecP256K1Field *self);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecP256K1Field *new_OrgSpongycastleMathEcCustomSecSecP256K1Field_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecP256K1Field *create_OrgSpongycastleMathEcCustomSecSecP256K1Field_init(void);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_addWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_addExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_addOneWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT IOSIntArray *OrgSpongycastleMathEcCustomSecSecP256K1Field_fromBigIntegerWithJavaMathBigInteger_(JavaMathBigInteger *x);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_halfWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_multiplyWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *zz);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_negateWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_reduceWithIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_reduce32WithInt_withIntArray_(jint x, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_squareWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_squareNWithIntArray_withInt_withIntArray_(IOSIntArray *x, jint n, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_subtractWithIntArray_withIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *y, IOSIntArray *z);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_subtractExtWithIntArray_withIntArray_withIntArray_(IOSIntArray *xx, IOSIntArray *yy, IOSIntArray *zz);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP256K1Field_twiceWithIntArray_withIntArray_(IOSIntArray *x, IOSIntArray *z);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcCustomSecSecP256K1Field)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP256K1Field")
