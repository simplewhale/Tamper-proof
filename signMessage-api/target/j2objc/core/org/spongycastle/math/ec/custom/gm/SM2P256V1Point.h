//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/gm/SM2P256V1Point.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomGmSM2P256V1Point")
#ifdef RESTRICT_OrgSpongycastleMathEcCustomGmSM2P256V1Point
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomGmSM2P256V1Point 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomGmSM2P256V1Point 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcCustomGmSM2P256V1Point

#if !defined (OrgSpongycastleMathEcCustomGmSM2P256V1Point_) && (INCLUDE_ALL_OrgSpongycastleMathEcCustomGmSM2P256V1Point || defined(INCLUDE_OrgSpongycastleMathEcCustomGmSM2P256V1Point))
#define OrgSpongycastleMathEcCustomGmSM2P256V1Point_

#define RESTRICT_OrgSpongycastleMathEcECPoint 1
#define INCLUDE_OrgSpongycastleMathEcECPoint_AbstractFp 1
#include "org/spongycastle/math/ec/ECPoint.h"

@class IOSObjectArray;
@class OrgSpongycastleMathEcECCurve;
@class OrgSpongycastleMathEcECFieldElement;
@class OrgSpongycastleMathEcECPoint;

@interface OrgSpongycastleMathEcCustomGmSM2P256V1Point : OrgSpongycastleMathEcECPoint_AbstractFp

#pragma mark Public

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y;

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                         withBoolean:(jboolean)withCompression;

- (OrgSpongycastleMathEcECPoint *)addWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)b;

- (OrgSpongycastleMathEcECPoint *)negate;

- (OrgSpongycastleMathEcECPoint *)threeTimes;

- (OrgSpongycastleMathEcECPoint *)twice;

- (OrgSpongycastleMathEcECPoint *)twicePlusWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)b;

#pragma mark Protected

- (OrgSpongycastleMathEcECPoint *)detach;

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

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcCustomGmSM2P256V1Point)

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcCustomGmSM2P256V1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomGmSM2P256V1Point *new_OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomGmSM2P256V1Point *create_OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcCustomGmSM2P256V1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomGmSM2P256V1Point *new_OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomGmSM2P256V1Point *create_OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression);

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcCustomGmSM2P256V1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomGmSM2P256V1Point *new_OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomGmSM2P256V1Point *create_OrgSpongycastleMathEcCustomGmSM2P256V1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcCustomGmSM2P256V1Point)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomGmSM2P256V1Point")
