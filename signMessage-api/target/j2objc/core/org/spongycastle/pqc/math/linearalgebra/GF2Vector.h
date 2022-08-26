//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/linearalgebra/GF2Vector.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2Vector")
#ifdef RESTRICT_OrgSpongycastlePqcMathLinearalgebraGF2Vector
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2Vector 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2Vector 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathLinearalgebraGF2Vector

#if !defined (OrgSpongycastlePqcMathLinearalgebraGF2Vector_) && (INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2Vector || defined(INCLUDE_OrgSpongycastlePqcMathLinearalgebraGF2Vector))
#define OrgSpongycastlePqcMathLinearalgebraGF2Vector_

#define RESTRICT_OrgSpongycastlePqcMathLinearalgebraVector 1
#define INCLUDE_OrgSpongycastlePqcMathLinearalgebraVector 1
#include "org/spongycastle/pqc/math/linearalgebra/Vector.h"

@class IOSByteArray;
@class IOSIntArray;
@class JavaSecuritySecureRandom;
@class OrgSpongycastlePqcMathLinearalgebraGF2mField;
@class OrgSpongycastlePqcMathLinearalgebraGF2mVector;
@class OrgSpongycastlePqcMathLinearalgebraPermutation;

@interface OrgSpongycastlePqcMathLinearalgebraGF2Vector : OrgSpongycastlePqcMathLinearalgebraVector

#pragma mark Public

- (instancetype)initWithOrgSpongycastlePqcMathLinearalgebraGF2Vector:(OrgSpongycastlePqcMathLinearalgebraGF2Vector *)other;

- (instancetype)initWithInt:(jint)length;

- (instancetype)initWithInt:(jint)length
                    withInt:(jint)t
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr;

- (instancetype)initWithInt:(jint)length
               withIntArray:(IOSIntArray *)v;

- (instancetype)initWithInt:(jint)length
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr;

- (OrgSpongycastlePqcMathLinearalgebraVector *)addWithOrgSpongycastlePqcMathLinearalgebraVector:(OrgSpongycastlePqcMathLinearalgebraVector *)other;

- (jboolean)isEqual:(id)other;

- (OrgSpongycastlePqcMathLinearalgebraGF2Vector *)extractLeftVectorWithInt:(jint)k;

- (OrgSpongycastlePqcMathLinearalgebraGF2Vector *)extractRightVectorWithInt:(jint)k;

- (OrgSpongycastlePqcMathLinearalgebraGF2Vector *)extractVectorWithIntArray:(IOSIntArray *)setJ;

- (jint)getBitWithInt:(jint)index;

- (IOSByteArray *)getEncoded;

- (jint)getHammingWeight;

- (IOSIntArray *)getVecArray;

- (NSUInteger)hash;

- (jboolean)isZero;

- (OrgSpongycastlePqcMathLinearalgebraVector *)multiplyWithOrgSpongycastlePqcMathLinearalgebraPermutation:(OrgSpongycastlePqcMathLinearalgebraPermutation *)p;

+ (OrgSpongycastlePqcMathLinearalgebraGF2Vector *)OS2VPWithInt:(jint)length
                                                 withByteArray:(IOSByteArray *)encVec;

- (void)setBitWithInt:(jint)index;

- (OrgSpongycastlePqcMathLinearalgebraGF2mVector *)toExtensionFieldVectorWithOrgSpongycastlePqcMathLinearalgebraGF2mField:(OrgSpongycastlePqcMathLinearalgebraGF2mField *)field;

- (NSString *)description;

#pragma mark Protected

- (instancetype)initWithIntArray:(IOSIntArray *)v
                         withInt:(jint)length;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathLinearalgebraGF2Vector)

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_(OrgSpongycastlePqcMathLinearalgebraGF2Vector *self, jint length);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *new_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_(jint length) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *create_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_(jint length);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withJavaSecuritySecureRandom_(OrgSpongycastlePqcMathLinearalgebraGF2Vector *self, jint length, JavaSecuritySecureRandom *sr);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *new_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withJavaSecuritySecureRandom_(jint length, JavaSecuritySecureRandom *sr) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *create_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withJavaSecuritySecureRandom_(jint length, JavaSecuritySecureRandom *sr);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withInt_withJavaSecuritySecureRandom_(OrgSpongycastlePqcMathLinearalgebraGF2Vector *self, jint length, jint t, JavaSecuritySecureRandom *sr);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *new_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withInt_withJavaSecuritySecureRandom_(jint length, jint t, JavaSecuritySecureRandom *sr) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *create_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withInt_withJavaSecuritySecureRandom_(jint length, jint t, JavaSecuritySecureRandom *sr);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withIntArray_(OrgSpongycastlePqcMathLinearalgebraGF2Vector *self, jint length, IOSIntArray *v);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *new_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withIntArray_(jint length, IOSIntArray *v) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *create_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithInt_withIntArray_(jint length, IOSIntArray *v);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithOrgSpongycastlePqcMathLinearalgebraGF2Vector_(OrgSpongycastlePqcMathLinearalgebraGF2Vector *self, OrgSpongycastlePqcMathLinearalgebraGF2Vector *other);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *new_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithOrgSpongycastlePqcMathLinearalgebraGF2Vector_(OrgSpongycastlePqcMathLinearalgebraGF2Vector *other) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *create_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithOrgSpongycastlePqcMathLinearalgebraGF2Vector_(OrgSpongycastlePqcMathLinearalgebraGF2Vector *other);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithIntArray_withInt_(OrgSpongycastlePqcMathLinearalgebraGF2Vector *self, IOSIntArray *v, jint length);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *new_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithIntArray_withInt_(IOSIntArray *v, jint length) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *create_OrgSpongycastlePqcMathLinearalgebraGF2Vector_initWithIntArray_withInt_(IOSIntArray *v, jint length);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2Vector *OrgSpongycastlePqcMathLinearalgebraGF2Vector_OS2VPWithInt_withByteArray_(jint length, IOSByteArray *encVec);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathLinearalgebraGF2Vector)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2Vector")
