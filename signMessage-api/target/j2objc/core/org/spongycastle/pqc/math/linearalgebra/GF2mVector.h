//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/linearalgebra/GF2mVector.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2mVector")
#ifdef RESTRICT_OrgSpongycastlePqcMathLinearalgebraGF2mVector
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2mVector 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2mVector 1
#endif
#undef RESTRICT_OrgSpongycastlePqcMathLinearalgebraGF2mVector

#if !defined (OrgSpongycastlePqcMathLinearalgebraGF2mVector_) && (INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2mVector || defined(INCLUDE_OrgSpongycastlePqcMathLinearalgebraGF2mVector))
#define OrgSpongycastlePqcMathLinearalgebraGF2mVector_

#define RESTRICT_OrgSpongycastlePqcMathLinearalgebraVector 1
#define INCLUDE_OrgSpongycastlePqcMathLinearalgebraVector 1
#include "org/spongycastle/pqc/math/linearalgebra/Vector.h"

@class IOSByteArray;
@class IOSIntArray;
@class OrgSpongycastlePqcMathLinearalgebraGF2mField;
@class OrgSpongycastlePqcMathLinearalgebraPermutation;

@interface OrgSpongycastlePqcMathLinearalgebraGF2mVector : OrgSpongycastlePqcMathLinearalgebraVector

#pragma mark Public

- (instancetype)initWithOrgSpongycastlePqcMathLinearalgebraGF2mField:(OrgSpongycastlePqcMathLinearalgebraGF2mField *)field
                                                       withByteArray:(IOSByteArray *)v;

- (instancetype)initWithOrgSpongycastlePqcMathLinearalgebraGF2mField:(OrgSpongycastlePqcMathLinearalgebraGF2mField *)field
                                                        withIntArray:(IOSIntArray *)vector;

- (instancetype)initWithOrgSpongycastlePqcMathLinearalgebraGF2mVector:(OrgSpongycastlePqcMathLinearalgebraGF2mVector *)other;

- (OrgSpongycastlePqcMathLinearalgebraVector *)addWithOrgSpongycastlePqcMathLinearalgebraVector:(OrgSpongycastlePqcMathLinearalgebraVector *)addend;

- (jboolean)isEqual:(id)other;

- (IOSByteArray *)getEncoded;

- (OrgSpongycastlePqcMathLinearalgebraGF2mField *)getField;

- (IOSIntArray *)getIntArrayForm;

- (NSUInteger)hash;

- (jboolean)isZero;

- (OrgSpongycastlePqcMathLinearalgebraVector *)multiplyWithOrgSpongycastlePqcMathLinearalgebraPermutation:(OrgSpongycastlePqcMathLinearalgebraPermutation *)p;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcMathLinearalgebraGF2mVector)

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mField_withByteArray_(OrgSpongycastlePqcMathLinearalgebraGF2mVector *self, OrgSpongycastlePqcMathLinearalgebraGF2mField *field, IOSByteArray *v);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2mVector *new_OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mField_withByteArray_(OrgSpongycastlePqcMathLinearalgebraGF2mField *field, IOSByteArray *v) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2mVector *create_OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mField_withByteArray_(OrgSpongycastlePqcMathLinearalgebraGF2mField *field, IOSByteArray *v);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mField_withIntArray_(OrgSpongycastlePqcMathLinearalgebraGF2mVector *self, OrgSpongycastlePqcMathLinearalgebraGF2mField *field, IOSIntArray *vector);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2mVector *new_OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mField_withIntArray_(OrgSpongycastlePqcMathLinearalgebraGF2mField *field, IOSIntArray *vector) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2mVector *create_OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mField_withIntArray_(OrgSpongycastlePqcMathLinearalgebraGF2mField *field, IOSIntArray *vector);

FOUNDATION_EXPORT void OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mVector_(OrgSpongycastlePqcMathLinearalgebraGF2mVector *self, OrgSpongycastlePqcMathLinearalgebraGF2mVector *other);

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2mVector *new_OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mVector_(OrgSpongycastlePqcMathLinearalgebraGF2mVector *other) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcMathLinearalgebraGF2mVector *create_OrgSpongycastlePqcMathLinearalgebraGF2mVector_initWithOrgSpongycastlePqcMathLinearalgebraGF2mVector_(OrgSpongycastlePqcMathLinearalgebraGF2mVector *other);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcMathLinearalgebraGF2mVector)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcMathLinearalgebraGF2mVector")
