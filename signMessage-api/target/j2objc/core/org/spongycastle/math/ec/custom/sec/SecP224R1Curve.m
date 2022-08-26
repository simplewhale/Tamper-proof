//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecP224R1Curve.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/custom/sec/SecP224R1Curve.h"
#include "org/spongycastle/math/ec/custom/sec/SecP224R1FieldElement.h"
#include "org/spongycastle/math/ec/custom/sec/SecP224R1Point.h"
#include "org/spongycastle/util/encoders/Hex.h"

inline jint OrgSpongycastleMathEcCustomSecSecP224R1Curve_get_SecP224R1_DEFAULT_COORDS(void);
#define OrgSpongycastleMathEcCustomSecSecP224R1Curve_SecP224R1_DEFAULT_COORDS 2
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcCustomSecSecP224R1Curve, SecP224R1_DEFAULT_COORDS, jint)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleMathEcCustomSecSecP224R1Curve)

JavaMathBigInteger *OrgSpongycastleMathEcCustomSecSecP224R1Curve_q;

@implementation OrgSpongycastleMathEcCustomSecSecP224R1Curve

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcCustomSecSecP224R1Curve_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (OrgSpongycastleMathEcECCurve *)cloneCurve {
  return new_OrgSpongycastleMathEcCustomSecSecP224R1Curve_init();
}

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord {
  switch (coord) {
    case OrgSpongycastleMathEcECCurve_COORD_JACOBIAN:
    return true;
    default:
    return false;
  }
}

- (JavaMathBigInteger *)getQ {
  return OrgSpongycastleMathEcCustomSecSecP224R1Curve_q;
}

- (jint)getFieldSize {
  return [((JavaMathBigInteger *) nil_chk(OrgSpongycastleMathEcCustomSecSecP224R1Curve_q)) bitLength];
}

- (OrgSpongycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return new_OrgSpongycastleMathEcCustomSecSecP224R1FieldElement_initWithJavaMathBigInteger_(x);
}

- (OrgSpongycastleMathEcECPoint *)createRawPointWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                                                            withBoolean:(jboolean)withCompression {
  return new_OrgSpongycastleMathEcCustomSecSecP224R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(self, x, y, withCompression);
}

- (OrgSpongycastleMathEcECPoint *)createRawPointWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                           withOrgSpongycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                            withBoolean:(jboolean)withCompression {
  return new_OrgSpongycastleMathEcCustomSecSecP224R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(self, x, y, zs, withCompression);
}

- (OrgSpongycastleMathEcECPoint *)getInfinity {
  return infinity_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECCurve;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x4, 4, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(cloneCurve);
  methods[2].selector = @selector(supportsCoordinateSystemWithInt:);
  methods[3].selector = @selector(getQ);
  methods[4].selector = @selector(getFieldSize);
  methods[5].selector = @selector(fromBigIntegerWithJavaMathBigInteger:);
  methods[6].selector = @selector(createRawPointWithOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withBoolean:);
  methods[7].selector = @selector(createRawPointWithOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElementArray:withBoolean:);
  methods[8].selector = @selector(getInfinity);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "q", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x19, -1, 7, -1, -1 },
    { "SecP224R1_DEFAULT_COORDS", "I", .constantValue.asInt = OrgSpongycastleMathEcCustomSecSecP224R1Curve_SecP224R1_DEFAULT_COORDS, 0x1a, -1, -1, -1, -1 },
    { "infinity_", "LOrgSpongycastleMathEcCustomSecSecP224R1Point;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "supportsCoordinateSystem", "I", "fromBigInteger", "LJavaMathBigInteger;", "createRawPoint", "LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;Z", "LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;[LOrgSpongycastleMathEcECFieldElement;Z", &OrgSpongycastleMathEcCustomSecSecP224R1Curve_q };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecP224R1Curve = { "SecP224R1Curve", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecP224R1Curve;
}

+ (void)initialize {
  if (self == [OrgSpongycastleMathEcCustomSecSecP224R1Curve class]) {
    OrgSpongycastleMathEcCustomSecSecP224R1Curve_q = new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"));
    J2OBJC_SET_INITIALIZED(OrgSpongycastleMathEcCustomSecSecP224R1Curve)
  }
}

@end

void OrgSpongycastleMathEcCustomSecSecP224R1Curve_init(OrgSpongycastleMathEcCustomSecSecP224R1Curve *self) {
  OrgSpongycastleMathEcECCurve_AbstractFp_initWithJavaMathBigInteger_(self, OrgSpongycastleMathEcCustomSecSecP224R1Curve_q);
  self->infinity_ = new_OrgSpongycastleMathEcCustomSecSecP224R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(self, nil, nil);
  self->a_ = [self fromBigIntegerWithJavaMathBigInteger:new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"))];
  self->b_ = [self fromBigIntegerWithJavaMathBigInteger:new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4"))];
  self->order_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"));
  self->cofactor_ = JavaMathBigInteger_valueOfWithLong_(1);
  self->coord_ = OrgSpongycastleMathEcCustomSecSecP224R1Curve_SecP224R1_DEFAULT_COORDS;
}

OrgSpongycastleMathEcCustomSecSecP224R1Curve *new_OrgSpongycastleMathEcCustomSecSecP224R1Curve_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP224R1Curve, init)
}

OrgSpongycastleMathEcCustomSecSecP224R1Curve *create_OrgSpongycastleMathEcCustomSecSecP224R1Curve_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP224R1Curve, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecP224R1Curve)