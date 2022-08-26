//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecP256R1Curve.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/custom/sec/SecP256R1Curve.h"
#include "org/spongycastle/math/ec/custom/sec/SecP256R1FieldElement.h"
#include "org/spongycastle/math/ec/custom/sec/SecP256R1Point.h"
#include "org/spongycastle/util/encoders/Hex.h"

inline jint OrgSpongycastleMathEcCustomSecSecP256R1Curve_get_SecP256R1_DEFAULT_COORDS(void);
#define OrgSpongycastleMathEcCustomSecSecP256R1Curve_SecP256R1_DEFAULT_COORDS 2
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcCustomSecSecP256R1Curve, SecP256R1_DEFAULT_COORDS, jint)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleMathEcCustomSecSecP256R1Curve)

JavaMathBigInteger *OrgSpongycastleMathEcCustomSecSecP256R1Curve_q;

@implementation OrgSpongycastleMathEcCustomSecSecP256R1Curve

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcCustomSecSecP256R1Curve_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (OrgSpongycastleMathEcECCurve *)cloneCurve {
  return new_OrgSpongycastleMathEcCustomSecSecP256R1Curve_init();
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
  return OrgSpongycastleMathEcCustomSecSecP256R1Curve_q;
}

- (jint)getFieldSize {
  return [((JavaMathBigInteger *) nil_chk(OrgSpongycastleMathEcCustomSecSecP256R1Curve_q)) bitLength];
}

- (OrgSpongycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithJavaMathBigInteger_(x);
}

- (OrgSpongycastleMathEcECPoint *)createRawPointWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                                                            withBoolean:(jboolean)withCompression {
  return new_OrgSpongycastleMathEcCustomSecSecP256R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(self, x, y, withCompression);
}

- (OrgSpongycastleMathEcECPoint *)createRawPointWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                           withOrgSpongycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                            withBoolean:(jboolean)withCompression {
  return new_OrgSpongycastleMathEcCustomSecSecP256R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(self, x, y, zs, withCompression);
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
    { "SecP256R1_DEFAULT_COORDS", "I", .constantValue.asInt = OrgSpongycastleMathEcCustomSecSecP256R1Curve_SecP256R1_DEFAULT_COORDS, 0x1a, -1, -1, -1, -1 },
    { "infinity_", "LOrgSpongycastleMathEcCustomSecSecP256R1Point;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "supportsCoordinateSystem", "I", "fromBigInteger", "LJavaMathBigInteger;", "createRawPoint", "LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;Z", "LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;[LOrgSpongycastleMathEcECFieldElement;Z", &OrgSpongycastleMathEcCustomSecSecP256R1Curve_q };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecP256R1Curve = { "SecP256R1Curve", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecP256R1Curve;
}

+ (void)initialize {
  if (self == [OrgSpongycastleMathEcCustomSecSecP256R1Curve class]) {
    OrgSpongycastleMathEcCustomSecSecP256R1Curve_q = new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));
    J2OBJC_SET_INITIALIZED(OrgSpongycastleMathEcCustomSecSecP256R1Curve)
  }
}

@end

void OrgSpongycastleMathEcCustomSecSecP256R1Curve_init(OrgSpongycastleMathEcCustomSecSecP256R1Curve *self) {
  OrgSpongycastleMathEcECCurve_AbstractFp_initWithJavaMathBigInteger_(self, OrgSpongycastleMathEcCustomSecSecP256R1Curve_q);
  self->infinity_ = new_OrgSpongycastleMathEcCustomSecSecP256R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(self, nil, nil);
  self->a_ = [self fromBigIntegerWithJavaMathBigInteger:new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"))];
  self->b_ = [self fromBigIntegerWithJavaMathBigInteger:new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"))];
  self->order_ = new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleUtilEncodersHex_decodeWithNSString_(@"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));
  self->cofactor_ = JavaMathBigInteger_valueOfWithLong_(1);
  self->coord_ = OrgSpongycastleMathEcCustomSecSecP256R1Curve_SecP256R1_DEFAULT_COORDS;
}

OrgSpongycastleMathEcCustomSecSecP256R1Curve *new_OrgSpongycastleMathEcCustomSecSecP256R1Curve_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP256R1Curve, init)
}

OrgSpongycastleMathEcCustomSecSecP256R1Curve *create_OrgSpongycastleMathEcCustomSecSecP256R1Curve_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP256R1Curve, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecP256R1Curve)
