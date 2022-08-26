//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/linearalgebra/Permutation.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPermutation")
#ifdef RESTRICT_OrgSpongycastlePqcMathLinearalgebraPermutation
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPermutation 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPermutation 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathLinearalgebraPermutation

#if !defined (OrgSpongycastlePqcMathLinearalgebraPermutation_) && (INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPermutation || defined(INCLUDE_OrgSpongycastlePqcMathLinearalgebraPermutation))
#define OrgSpongycastlePqcMathLinearalgebraPermutation_

@class IOSByteArray;
@class IOSIntArray;
@class JavaSecuritySecureRandom;

@interface OrgSpongycastlePqcMathLinearalgebraPermutation : NSObject

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)enc;

- (instancetype)initWithInt:(jint)n;

- (instancetype)initWithInt:(jint)n
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr;

- (instancetype)initWithIntArray:(IOSIntArray *)perm;

- (OrgSpongycastlePqcMathLinearalgebraPermutation *)computeInverse;

- (jboolean)isEqual:(id)other;

- (IOSByteArray *)getEncoded;

- (IOSIntArray *)getVector;

- (NSUInteger)hash;

- (OrgSpongycastlePqcMathLinearalgebraPermutation *)rightMultiplyWithOrgSpongycastlePqcMathLinearalgebraPermutation:(OrgSpongycastlePqcMathLinearalgebraPermutation *)p;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathLinearalgebraPermutation)

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraPermutation_initWithInt_(OrgSpongycastlePqcMathLinearalgebraPermutation *self, jint n);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraPermutation *new_OrgSpongycastlePqcMathLinearalgebraPermutation_initWithInt_(jint n) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraPermutation *create_OrgSpongycastlePqcMathLinearalgebraPermutation_initWithInt_(jint n);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraPermutation_initWithIntArray_(OrgSpongycastlePqcMathLinearalgebraPermutation *self, IOSIntArray *perm);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraPermutation *new_OrgSpongycastlePqcMathLinearalgebraPermutation_initWithIntArray_(IOSIntArray *perm) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraPermutation *create_OrgSpongycastlePqcMathLinearalgebraPermutation_initWithIntArray_(IOSIntArray *perm);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraPermutation_initWithByteArray_(OrgSpongycastlePqcMathLinearalgebraPermutation *self, IOSByteArray *enc);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraPermutation *new_OrgSpongycastlePqcMathLinearalgebraPermutation_initWithByteArray_(IOSByteArray *enc) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraPermutation *create_OrgSpongycastlePqcMathLinearalgebraPermutation_initWithByteArray_(IOSByteArray *enc);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(OrgSpongycastlePqcMathLinearalgebraPermutation *self, jint n, JavaSecuritySecureRandom *sr);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraPermutation *new_OrgSpongycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(jint n, JavaSecuritySecureRandom *sr) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraPermutation *create_OrgSpongycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(jint n, JavaSecuritySecureRandom *sr);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathLinearalgebraPermutation)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraPermutation")