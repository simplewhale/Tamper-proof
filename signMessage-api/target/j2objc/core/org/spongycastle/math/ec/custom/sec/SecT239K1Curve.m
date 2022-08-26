//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecT239K1Curve.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/ECMultiplier.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/WTauNafMultiplier.h"
#include "org/spongycastle/math/ec/custom/sec/SecT239FieldElement.h"
#include "org/spongycastle/math/ec/custom/sec/SecT239K1Curve.h"
#include "org/spongycastle/math/ec/custom/sec/SecT239K1Point.h"
#include "org/spongycastle/util/encoders/Hex.h"

inline jint OrgSpongycastleMathEcCustomSecSecT239K1Curve_get_SecT239K1_DEFAULT_COORDS(void);
#define OrgSpongycastleMathEcCustomSecSecT239K1Curve_SecT239K1_DEFAULT_COORDS 6
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcCustomSecSecT239K1Curve, SecT239K1_DEFAULT_COORDS, jint)

@implementation OrgSpongycastleMathEcCustomSecSecT239K1Curve

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcCustomSecSecT239K1Curve_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (OrgSpongycastleMathEcECCurve *)cloneCurve {
  return new_OrgSpongycastleMathEcCustomSecSecT239K1Curve_init();
}

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord {
  switch (coord) {
    case OrgSpongycastleMathEcECCurve_COORD_LAMBDA_PROJECTIVE:
    return true;
    default:
    return false;
  }
}

- (id<OrgSpongycastleMathEcECMultiplier>)createDefaultMultiplier {
  return new_OrgSpongycastleMathEcWTauNafMultiplier_init();
}

- (jint)getFieldSize {
  return 239;
}

- (OrgSpongycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return new_OrgSpongycastleMathEcCustomSecSecT239FieldElement_initWithJavaMathBigInteger_(x);
}

- (OrgSpongycastleMathEcECPoint *)createRawPointWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                                                            withBoolean:(jboolean)withCompression {
  return new_OrgSpongycastleMathEcCustomSecSecT239K1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(self, x, y, withCompression);
}

- (OrgSpongycastleMathEcECPoint *)createRawPointWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                           withOrgSpongycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                            withBoolean:(jboolean)withCompression {
  return new_OrgSpongycastleMathEcCustomSecSecT239K1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(self, x, y, zs, withCompression);
}

- (OrgSpongycastleMathEcECPoint *)getInfinity {
  return infinity_;
}

- (jboolean)isKoblitz {
  return true;
}

- (jint)getM {
  return 239;
}

- (jboolean)isTrinomial {
  return true;
}

- (jint)getK1 {
  return 158;
}

- (jint)getK2 {
  return 0;
}

- (jint)getK3 {
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECCurve;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECMultiplier;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x4, 4, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(cloneCurve);
  methods[2].selector = @selector(supportsCoordinateSystemWithInt:);
  methods[3].selector = @selector(createDefaultMultiplier);
  methods[4].selector = @selector(getFieldSize);
  methods[5].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[6].selector = @selector(createRawPointWithOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withBoolean:);
  methods[7].selector = @selector(createRawPointWithOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElementArray:withBoolean:);
  methods[8].selector = @selector(getInfinity);
  methods[9].selector = @selector(isKoblitz);
  methods[10].selector = @selector(getM);
  methods[11].selector = @selector(isTrinomial);
  methods[12].selector = @selector(getK1);
  methods[13].selector = @selector(getK2);
  methods[14].selector = @selector(getK3);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SecT239K1_DEFAULT_COORDS", "I", .constantValue.asInt = OrgSpongycastleMathEcCustomSecSecT239K1Curve_SecT239K1_DEFAULT_COORDS, 0x1a, -1, -1, -1, -1 },
    { "infinity_", "LOrgSpongycastleMathEcCustomSecSecT239K1Point;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "supportsCoordinateSystem", "I", "fromBigInteger", "LJavaMathBigInteger;", "createRawPoint", "LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;Z", "LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;[LOrgSpongycastleMathEcECFieldElement;Z" };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecT239K1Curve = { "SecT239K1Curve", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 15, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecT239K1Curve;
}

@end

void OrgSpongycastleMathEcCustomSecSecT239K1Curve_init(OrgSpongycastleMathEcCustomSecSecT239K1Curve *self) {
  OrgSpongycastleMathEcECCurve_AbstractF2m_initWithInt_withInt_withInt_withInt_(self, 239, 158, 0, 0);
  self->infinity_ = new_OrgSpongycastleMathEcCustomSecSecT239K1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(self, nil, nil);
  self->a_ = [self fromBigIntegerWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(0)];
  self->b_ = [self fromBigIntegerWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(1)];
  self->order_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5"));
  self->cofactor_ = JavaMathBigInteger_valueOfWithLong_(4);
  self->coord_ = OrgSpongycastleMathEcCustomSecSecT239K1Curve_SecT239K1_DEFAULT_COORDS;
}

OrgSpongycastleMathEcCustomSecSecT239K1Curve *new_OrgSpongycastleMathEcCustomSecSecT239K1Curve_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecT239K1Curve, init)
}

OrgSpongycastleMathEcCustomSecSecT239K1Curve *create_OrgSpongycastleMathEcCustomSecSecT239K1Curve_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecT239K1Curve, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecT239K1Curve)
