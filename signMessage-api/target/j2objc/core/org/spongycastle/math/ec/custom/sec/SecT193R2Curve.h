//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecT193R2Curve.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193R2Curve")
#ifdef RESTRICT_OrgSpongycastleMathEcCustomSecSecT193R2Curve
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193R2Curve 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193R2Curve 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcCustomSecSecT193R2Curve

#if !defined (OrgSpongycastleMathEcCustomSecSecT193R2Curve_) && (INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193R2Curve || defined(INCLUDE_OrgSpongycastleMathEcCustomSecSecT193R2Curve))
#define OrgSpongycastleMathEcCustomSecSecT193R2Curve_

#define RESTRICT_OrgSpongycastleMathEcECCurve 1
#define INCLUDE_OrgSpongycastleMathEcECCurve_AbstractF2m 1
#include "org/spongycastle/math/ec/ECCurve.h"

@class IOSObjectArray;
@class JavaMathBigInteger;
@class OrgSpongycastleMathEcCustomSecSecT193R2Point;
@class OrgSpongycastleMathEcECCurve;
@class OrgSpongycastleMathEcECFieldElement;
@class OrgSpongycastleMathEcECPoint;

@interface OrgSpongycastleMathEcCustomSecSecT193R2Curve : OrgSpongycastleMathEcECCurve_AbstractF2m {
 @public
  OrgSpongycastleMathEcCustomSecSecT193R2Point *infinity_;
}

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (jint)getFieldSize;

- (OrgSpongycastleMathEcECPoint *)getInfinity;

- (jint)getK1;

- (jint)getK2;

- (jint)getK3;

- (jint)getM;

- (jboolean)isKoblitz;

- (jboolean)isTrinomial;

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord;

#pragma mark Protected

- (OrgSpongycastleMathEcECCurve *)cloneCurve;

- (OrgSpongycastleMathEcECPoint *)createRawPointWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                                                            withBoolean:(jboolean)withCompression;

- (OrgSpongycastleMathEcECPoint *)createRawPointWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                           withOrgSpongycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                            withBoolean:(jboolean)withCompression;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithInt:(jint)arg0
                    withInt:(jint)arg1
                    withInt:(jint)arg2
                    withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcCustomSecSecT193R2Curve)

J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcCustomSecSecT193R2Curve, infinity_, OrgSpongycastleMathEcCustomSecSecT193R2Point *)

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT193R2Curve_init(OrgSpongycastleMathEcCustomSecSecT193R2Curve *self);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT193R2Curve *new_OrgSpongycastleMathEcCustomSecSecT193R2Curve_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT193R2Curve *create_OrgSpongycastleMathEcCustomSecSecT193R2Curve_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcCustomSecSecT193R2Curve)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT193R2Curve")
