//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecT571FieldElement.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/custom/sec/SecT571Field.h"
#include "org/spongycastle/math/ec/custom/sec/SecT571FieldElement.h"
#include "org/spongycastle/math/raw/Nat576.h"
#include "org/spongycastle/util/Arrays.h"

@implementation OrgSpongycastleMathEcCustomSecSecT571FieldElement

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithJavaMathBigInteger_(self, x);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcCustomSecSecT571FieldElement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLongArray:(IOSLongArray *)x {
  OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(self, x);
  return self;
}

- (jboolean)isOne {
  return OrgSpongycastleMathRawNat576_isOne64WithLongArray_(x_);
}

- (jboolean)isZero {
  return OrgSpongycastleMathRawNat576_isZero64WithLongArray_(x_);
}

- (jboolean)testBitZero {
  return (IOSLongArray_Get(nil_chk(x_), 0) & 1LL) != 0LL;
}

- (JavaMathBigInteger *)toBigInteger {
  return OrgSpongycastleMathRawNat576_toBigInteger64WithLongArray_(x_);
}

- (NSString *)getFieldName {
  return @"SecT571Field";
}

- (jint)getFieldSize {
  return 571;
}

- (OrgSpongycastleMathEcECFieldElement *)addWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_addWithLongArray_withLongArray_withLongArray_(x_, ((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecT571FieldElement class]))))->x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)addOne {
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_addOneWithLongArray_withLongArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)subtractWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  return [self addWithOrgSpongycastleMathEcECFieldElement:b];
}

- (OrgSpongycastleMathEcECFieldElement *)multiplyWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_multiplyWithLongArray_withLongArray_withLongArray_(x_, ((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecT571FieldElement class]))))->x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)multiplyMinusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b
                                                             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y {
  return [self multiplyPlusProductWithOrgSpongycastleMathEcECFieldElement:b withOrgSpongycastleMathEcECFieldElement:x withOrgSpongycastleMathEcECFieldElement:y];
}

- (OrgSpongycastleMathEcECFieldElement *)multiplyPlusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b
                                                            withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                            withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y {
  IOSLongArray *ax = self->x_;
  IOSLongArray *bx = ((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecT571FieldElement class]))))->x_;
  IOSLongArray *xx = ((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) cast_chk(x, [OrgSpongycastleMathEcCustomSecSecT571FieldElement class]))))->x_;
  IOSLongArray *yx = ((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) cast_chk(y, [OrgSpongycastleMathEcCustomSecSecT571FieldElement class]))))->x_;
  IOSLongArray *tt = OrgSpongycastleMathRawNat576_createExt64();
  OrgSpongycastleMathEcCustomSecSecT571Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(ax, bx, tt);
  OrgSpongycastleMathEcCustomSecSecT571Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(xx, yx, tt);
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_reduceWithLongArray_withLongArray_(tt, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)divideWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  return [self multiplyWithOrgSpongycastleMathEcECFieldElement:[((OrgSpongycastleMathEcECFieldElement *) nil_chk(b)) invert]];
}

- (OrgSpongycastleMathEcECFieldElement *)negate {
  return self;
}

- (OrgSpongycastleMathEcECFieldElement *)square {
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_squareWithLongArray_withLongArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)squareMinusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                           withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y {
  return [self squarePlusProductWithOrgSpongycastleMathEcECFieldElement:x withOrgSpongycastleMathEcECFieldElement:y];
}

- (OrgSpongycastleMathEcECFieldElement *)squarePlusProductWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
                                                          withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y {
  IOSLongArray *ax = self->x_;
  IOSLongArray *xx = ((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) cast_chk(x, [OrgSpongycastleMathEcCustomSecSecT571FieldElement class]))))->x_;
  IOSLongArray *yx = ((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) cast_chk(y, [OrgSpongycastleMathEcCustomSecSecT571FieldElement class]))))->x_;
  IOSLongArray *tt = OrgSpongycastleMathRawNat576_createExt64();
  OrgSpongycastleMathEcCustomSecSecT571Field_squareAddToExtWithLongArray_withLongArray_(ax, tt);
  OrgSpongycastleMathEcCustomSecSecT571Field_multiplyAddToExtWithLongArray_withLongArray_withLongArray_(xx, yx, tt);
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_reduceWithLongArray_withLongArray_(tt, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)squarePowWithInt:(jint)pow {
  if (pow < 1) {
    return self;
  }
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_squareNWithLongArray_withInt_withLongArray_(x_, pow, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)invert {
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_invertWithLongArray_withLongArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)sqrt {
  IOSLongArray *z = OrgSpongycastleMathRawNat576_create64();
  OrgSpongycastleMathEcCustomSecSecT571Field_sqrtWithLongArray_withLongArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(z);
}

- (jint)getRepresentation {
  return OrgSpongycastleMathEcECFieldElement_F2m_PPB;
}

- (jint)getM {
  return 571;
}

- (jint)getK1 {
  return 2;
}

- (jint)getK2 {
  return 5;
}

- (jint)getK3 {
  return 10;
}

- (jboolean)isEqual:(id)other {
  if (other == self) {
    return true;
  }
  if (!([other isKindOfClass:[OrgSpongycastleMathEcCustomSecSecT571FieldElement class]])) {
    return false;
  }
  OrgSpongycastleMathEcCustomSecSecT571FieldElement *o = (OrgSpongycastleMathEcCustomSecSecT571FieldElement *) cast_chk(other, [OrgSpongycastleMathEcCustomSecSecT571FieldElement class]);
  return OrgSpongycastleMathRawNat576_eq64WithLongArray_withLongArray_(x_, ((OrgSpongycastleMathEcCustomSecSecT571FieldElement *) nil_chk(o))->x_);
}

- (NSUInteger)hash {
  return 5711052 ^ OrgSpongycastleUtilArrays_hashCodeWithLongArray_withInt_withInt_(x_, 0, 9);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 4, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 5, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 8, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 9, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 12, 11, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 13, 14, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 15, 16, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 17, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(initWithLongArray:);
  methods[3].selector = @selector(isOne);
  methods[4].selector = @selector(isZero);
  methods[5].selector = @selector(testBitZero);
  methods[6].selector = @selector(toBigInteger);
  methods[7].selector = @selector(getFieldName);
  methods[8].selector = @selector(getFieldSize);
  methods[9].selector = @selector(addWithOrgSpongycastleMathEcECFieldElement:);
  methods[10].selector = @selector(addOne);
  methods[11].selector = @selector(subtractWithOrgSpongycastleMathEcECFieldElement:);
  methods[12].selector = @selector(multiplyWithOrgSpongycastleMathEcECFieldElement:);
  methods[13].selector = @selector(multiplyMinusProductWithOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:);
  methods[14].selector = @selector(multiplyPlusProductWithOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:);
  methods[15].selector = @selector(divideWithOrgSpongycastleMathEcECFieldElement:);
  methods[16].selector = @selector(negate);
  methods[17].selector = @selector(square);
  methods[18].selector = @selector(squareMinusProductWithOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:);
  methods[19].selector = @selector(squarePlusProductWithOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:);
  methods[20].selector = @selector(squarePowWithInt:);
  methods[21].selector = @selector(invert);
  methods[22].selector = @selector(sqrt);
  methods[23].selector = @selector(getRepresentation);
  methods[24].selector = @selector(getM);
  methods[25].selector = @selector(getK1);
  methods[26].selector = @selector(getK2);
  methods[27].selector = @selector(getK3);
  methods[28].selector = @selector(isEqual:);
  methods[29].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "x_", "[J", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;", "[J", "add", "LOrgSpongycastleMathEcECFieldElement;", "subtract", "multiply", "multiplyMinusProduct", "LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;", "multiplyPlusProduct", "divide", "squareMinusProduct", "LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;", "squarePlusProduct", "squarePow", "I", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecT571FieldElement = { "SecT571FieldElement", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 30, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecT571FieldElement;
}

@end

void OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithJavaMathBigInteger_(OrgSpongycastleMathEcCustomSecSecT571FieldElement *self, JavaMathBigInteger *x) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  if (x == nil || [x signum] < 0 || [x bitLength] > 571) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"x value invalid for SecT571FieldElement");
  }
  self->x_ = OrgSpongycastleMathEcCustomSecSecT571Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

OrgSpongycastleMathEcCustomSecSecT571FieldElement *new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecT571FieldElement, initWithJavaMathBigInteger_, x)
}

OrgSpongycastleMathEcCustomSecSecT571FieldElement *create_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecT571FieldElement, initWithJavaMathBigInteger_, x)
}

void OrgSpongycastleMathEcCustomSecSecT571FieldElement_init(OrgSpongycastleMathEcCustomSecSecT571FieldElement *self) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  self->x_ = OrgSpongycastleMathRawNat576_create64();
}

OrgSpongycastleMathEcCustomSecSecT571FieldElement *new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecT571FieldElement, init)
}

OrgSpongycastleMathEcCustomSecSecT571FieldElement *create_OrgSpongycastleMathEcCustomSecSecT571FieldElement_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecT571FieldElement, init)
}

void OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(OrgSpongycastleMathEcCustomSecSecT571FieldElement *self, IOSLongArray *x) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  self->x_ = x;
}

OrgSpongycastleMathEcCustomSecSecT571FieldElement *new_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(IOSLongArray *x) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecT571FieldElement, initWithLongArray_, x)
}

OrgSpongycastleMathEcCustomSecSecT571FieldElement *create_OrgSpongycastleMathEcCustomSecSecT571FieldElement_initWithLongArray_(IOSLongArray *x) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecT571FieldElement, initWithLongArray_, x)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecT571FieldElement)
