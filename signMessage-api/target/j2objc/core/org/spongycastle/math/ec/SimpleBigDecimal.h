//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/SimpleBigDecimal.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcSimpleBigDecimal")
#ifdef RESTRICT_OrgSpongycastleMathEcSimpleBigDecimal
#define INCLUDE_ALL_OrgSpongycastleMathEcSimpleBigDecimal 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcSimpleBigDecimal 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcSimpleBigDecimal

#if !defined (OrgSpongycastleMathEcSimpleBigDecimal_) && (INCLUDE_ALL_OrgSpongycastleMathEcSimpleBigDecimal || defined(INCLUDE_OrgSpongycastleMathEcSimpleBigDecimal))
#define OrgSpongycastleMathEcSimpleBigDecimal_

@class JavaMathBigInteger;

@interface OrgSpongycastleMathEcSimpleBigDecimal : NSObject

#pragma mark Public

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)bigInt
                                   withInt:(jint)scale_;

- (OrgSpongycastleMathEcSimpleBigDecimal *)addWithJavaMathBigInteger:(JavaMathBigInteger *)b;

- (OrgSpongycastleMathEcSimpleBigDecimal *)addWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b;

- (OrgSpongycastleMathEcSimpleBigDecimal *)adjustScaleWithInt:(jint)newScale;

- (jint)compareToWithJavaMathBigInteger:(JavaMathBigInteger *)val;

- (jint)compareToWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)val;

- (OrgSpongycastleMathEcSimpleBigDecimal *)divideWithJavaMathBigInteger:(JavaMathBigInteger *)b;

- (OrgSpongycastleMathEcSimpleBigDecimal *)divideWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b;

- (jboolean)isEqual:(id)o;

- (JavaMathBigInteger *)floor;

+ (OrgSpongycastleMathEcSimpleBigDecimal *)getInstanceWithJavaMathBigInteger:(JavaMathBigInteger *)value
                                                                     withInt:(jint)scale_;

- (jint)getScale;

- (NSUInteger)hash;

- (jint)intValue;

- (jlong)longValue;

- (OrgSpongycastleMathEcSimpleBigDecimal *)multiplyWithJavaMathBigInteger:(JavaMathBigInteger *)b;

- (OrgSpongycastleMathEcSimpleBigDecimal *)multiplyWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b;

- (OrgSpongycastleMathEcSimpleBigDecimal *)negate;

- (JavaMathBigInteger *)round;

- (OrgSpongycastleMathEcSimpleBigDecimal *)shiftLeftWithInt:(jint)n;

- (OrgSpongycastleMathEcSimpleBigDecimal *)subtractWithJavaMathBigInteger:(JavaMathBigInteger *)b;

- (OrgSpongycastleMathEcSimpleBigDecimal *)subtractWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcSimpleBigDecimal)

FOUNDATION_EXPORT OrgSpongycastleMathEcSimpleBigDecimal *OrgSpongycastleMathEcSimpleBigDecimal_getInstanceWithJavaMathBigInteger_withInt_(JavaMathBigInteger *value, jint scale_);

FOUNDATION_EXPORT void OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(OrgSpongycastleMathEcSimpleBigDecimal *self, JavaMathBigInteger *bigInt, jint scale_);

FOUNDATION_EXPORT OrgSpongycastleMathEcSimpleBigDecimal *new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(JavaMathBigInteger *bigInt, jint scale_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcSimpleBigDecimal *create_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(JavaMathBigInteger *bigInt, jint scale_);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcSimpleBigDecimal)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcSimpleBigDecimal")
