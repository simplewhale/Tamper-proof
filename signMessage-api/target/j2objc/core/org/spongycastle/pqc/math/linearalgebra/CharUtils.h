//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/linearalgebra/CharUtils.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraCharUtils")
#ifdef RESTRICT_OrgSpongycastlePqcMathLinearalgebraCharUtils
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraCharUtils 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraCharUtils 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathLinearalgebraCharUtils

#if !defined (OrgSpongycastlePqcMathLinearalgebraCharUtils_) && (INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraCharUtils || defined(INCLUDE_OrgSpongycastlePqcMathLinearalgebraCharUtils))
#define OrgSpongycastlePqcMathLinearalgebraCharUtils_

@class IOSByteArray;
@class IOSCharArray;

@interface OrgSpongycastlePqcMathLinearalgebraCharUtils : NSObject

#pragma mark Public

+ (IOSCharArray *)cloneWithCharArray:(IOSCharArray *)array;

+ (jboolean)equalsWithCharArray:(IOSCharArray *)left
                  withCharArray:(IOSCharArray *)right;

+ (IOSByteArray *)toByteArrayWithCharArray:(IOSCharArray *)chars;

+ (IOSByteArray *)toByteArrayForPBEWithCharArray:(IOSCharArray *)chars;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathLinearalgebraCharUtils)

FOUNDATION_EXPORT IOSCharArray *OrgSpongycastlePqcMathLinearalgebraCharUtils_cloneWithCharArray_(IOSCharArray *array);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastlePqcMathLinearalgebraCharUtils_toByteArrayWithCharArray_(IOSCharArray *chars);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastlePqcMathLinearalgebraCharUtils_toByteArrayForPBEWithCharArray_(IOSCharArray *chars);

FOUNDATION_EXPORT jboolean OrgSpongycastlePqcMathLinearalgebraCharUtils_equalsWithCharArray_withCharArray_(IOSCharArray *left, IOSCharArray *right);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathLinearalgebraCharUtils)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraCharUtils")
