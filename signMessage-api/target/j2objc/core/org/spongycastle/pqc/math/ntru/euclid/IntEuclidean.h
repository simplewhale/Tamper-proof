//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/ntru/euclid/IntEuclidean.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruEuclidIntEuclidean")
#ifdef RESTRICT_OrgSpongycastlePqcMathNtruEuclidIntEuclidean
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruEuclidIntEuclidean 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathNtruEuclidIntEuclidean 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathNtruEuclidIntEuclidean

#if !defined (OrgSpongycastlePqcMathNtruEuclidIntEuclidean_) && (INCLUDE_ALL_OrgSpongycastlePqcMathNtruEuclidIntEuclidean || defined(INCLUDE_OrgSpongycastlePqcMathNtruEuclidIntEuclidean))
#define OrgSpongycastlePqcMathNtruEuclidIntEuclidean_

@interface OrgSpongycastlePqcMathNtruEuclidIntEuclidean : NSObject {
 @public
  jint x_;
  jint y_;
  jint gcd_;
}

#pragma mark Public

+ (OrgSpongycastlePqcMathNtruEuclidIntEuclidean *)calculateWithInt:(jint)a
                                                           withInt:(jint)b;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathNtruEuclidIntEuclidean)

FOUNDATION_EXPORT OrgSpongycastlePqcMathNtruEuclidIntEuclidean *OrgSpongycastlePqcMathNtruEuclidIntEuclidean_calculateWithInt_withInt_(jint a, jint b);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathNtruEuclidIntEuclidean)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathNtruEuclidIntEuclidean")
