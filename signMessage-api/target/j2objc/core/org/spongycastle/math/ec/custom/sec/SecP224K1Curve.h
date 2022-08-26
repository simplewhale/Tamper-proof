//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecP224K1Curve.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP224K1Curve")
#ifdef RESTRICT_OrgSpongycastleMathEcCustomSecSecP224K1Curve
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP224K1Curve 0
#else
#define INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP224K1Curve 1
#endif
#undef RESTRICT_OrgSpongycastleMathEcCustomSecSecP224K1Curve

#if !defined (OrgSpongycastleMathEcCustomSecSecP224K1Curve_) && (INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP224K1Curve || defined(INCLUDE_OrgSpongycastleMathEcCustomSecSecP224K1Curve))
#define OrgSpongycastleMathEcCustomSecSecP224K1Curve_

#define RESTRICT_OrgSpongycastleMathEcECCurve 1
#define INCLUDE_OrgSpongycastleMathEcECCurve_AbstractFp 1
#include "org/spongycastle/math/ec/ECCurve.h"

@class IOSObjectArray;
@class JavaMathBigInteger;
@class OrgSpongycastleMathEcCustomSecSecP224K1Point;
@class OrgSpongycastleMathEcECCurve;
@class OrgSpongycastleMathEcECFieldElement;
@class OrgSpongycastleMathEcECPoint;

@interface OrgSpongycastleMathEcCustomSecSecP224K1Curve : OrgSpongycastleMathEcECCurve_AbstractFp {
 @public
  OrgSpongycastleMathEcCustomSecSecP224K1Point *infinity_;
}

#pragma mark Public

- (instancetype)init;

- (OrgSpongycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (jint)getFieldSize;

- (OrgSpongycastleMathEcECPoint *)getInfinity;

- (JavaMathBigInteger *)getQ;

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

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleMathEcCustomSecSecP224K1Curve)

J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcCustomSecSecP224K1Curve, infinity_, OrgSpongycastleMathEcCustomSecSecP224K1Point *)

inline JavaMathBigInteger *OrgSpongycastleMathEcCustomSecSecP224K1Curve_get_q(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaMathBigInteger *OrgSpongycastleMathEcCustomSecSecP224K1Curve_q;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleMathEcCustomSecSecP224K1Curve, q, JavaMathBigInteger *)

FOUNDATION_EXPORT void OrgSpongycastleMathEcCustomSecSecP224K1Curve_init(OrgSpongycastleMathEcCustomSecSecP224K1Curve *self);

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecP224K1Curve *new_OrgSpongycastleMathEcCustomSecSecP224K1Curve_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleMathEcCustomSecSecP224K1Curve *create_OrgSpongycastleMathEcCustomSecSecP224K1Curve_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleMathEcCustomSecSecP224K1Curve)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleMathEcCustomSecSecP224K1Curve")
