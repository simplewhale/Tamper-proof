//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecT163R1Curve.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT163R1Curve")
#ifdef RESTRICT_OrgSpongycastleMathEcCustomSecSecT163R1Curve
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT163R1Curve 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT163R1Curve 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcCustomSecSecT163R1Curve

#if !defined (OrgSpongycastleMathEcCustomSecSecT163R1Curve_) && (INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT163R1Curve || defined(INCLUDE_OrgSpongycastleMathEcCustomSecSecT163R1Curve))
#define OrgSpongycastleMathEcCustomSecSecT163R1Curve_

#define RESTRICT_OrgSpongycastleMathEcECCurve 1
#define INCLUDE_OrgSpongycastleMathEcECCurve_AbstractF2m 1
#include "org/spongycastle/math/ec/ECCurve.h"

@class IOSObjectArray;
@class JavaMathBigInteger;
@class OrgSpongycastleMathEcCustomSecSecT163R1Point;
@class OrgSpongycastleMathEcECCurve;
@class OrgSpongycastleMathEcECFieldElement;
@class OrgSpongycastleMathEcECPoint;

@interface OrgSpongycastleMathEcCustomSecSecT163R1Curve : OrgSpongycastleMathEcECCurve_AbstractF2m {
 @public
  OrgSpongycastleMathEcCustomSecSecT163R1Point *infinity_;
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

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleMathEcCustomSecSecT163R1Curve)

J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcCustomSecSecT163R1Curve, infinity_, OrgSpongycastleMathEcCustomSecSecT163R1Point *)

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecT163R1Curve_init(OrgSpongycastleMathEcCustomSecSecT163R1Curve *self);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT163R1Curve *new_OrgSpongycastleMathEcCustomSecSecT163R1Curve_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecT163R1Curve *create_OrgSpongycastleMathEcCustomSecSecT163R1Curve_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcCustomSecSecT163R1Curve)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecT163R1Curve")
