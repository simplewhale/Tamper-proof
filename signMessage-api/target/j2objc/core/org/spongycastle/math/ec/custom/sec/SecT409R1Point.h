//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecT409R1Point.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT409R1Point")
#ifdef RESTRICT_OrgSpongycastleMathEcCustomSecSecT409R1Point
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT409R1Point 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT409R1Point 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcCustomSecSecT409R1Point

#if !defined (OrgSpongycastleMathEcCustomSecSecT409R1Point_) && (INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT409R1Point || defined(INCLUDE_OrgSpongycastleMathEcCustomSecSecT409R1Point))
#define OrgSpongycastleMathEcCustomSecSecT409R1Point_

#define RESTRICT_OrgSpongycastleMathEcECPoint 1
#define INCLUDE_OrgSpongycastleMathEcECPoint_AbstractF2m 1
#include "org/spongycastle/math/ec/ECPoint.h"

@class IOSObjectArray;
@class OrgSpongycastleMathEcECCurve;
@class OrgSpongycastleMathEcECFieldElement;
@class OrgSpongycastleMathEcECPoint;

@interface OrgSpongycastleMathEcCustomSecSecT409R1Point : OrgSpongycastleMathEcECPoint_AbstractF2m

#pragma mark Public

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                         withBoolean:(jboolean)withCompression;

- (OrgSpongycastleMathEcECPoint *)addWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)b;

- (OrgSpongycastleMathEcECFieldElement *)getYCoord;

- (OrgSpongycastleMathEcECPoint *)negate;

- (OrgSpongycastleMathEcECPoint *)twice;

- (OrgSpongycastleMathEcECPoint *)twicePlusWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)b;

#pragma mark Protected

- (OrgSpongycastleMathEcECPoint *)detach;

- (jboolean)getCompressionYTilde;

#pragma mark Package-Private

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
        withOrgSpongycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                         withBoolean:(jboolean)withCompression;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)arg0
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)arg1
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)arg2
        withOrgSpongycastleMathEcECFieldElementArray:(IOSObjectArray *)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcCustomSecSecT409R1Point)

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcCustomSecSecT409R1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT409R1Point *new_OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT409R1Point *create_OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcCustomSecSecT409R1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT409R1Point *new_OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT409R1Point *create_OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcCustomSecSecT409R1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT409R1Point *new_OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT409R1Point *create_OrgSpongycastleMathEcCustomSecSecT409R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcCustomSecSecT409R1Point)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT409R1Point")
