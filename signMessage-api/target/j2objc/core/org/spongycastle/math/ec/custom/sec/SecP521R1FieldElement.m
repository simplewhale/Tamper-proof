//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecP521R1FieldElement.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/custom/sec/SecP521R1Curve.h"
#include "org/spongycastle/math/ec/custom/sec/SecP521R1Field.h"
#include "org/spongycastle/math/ec/custom/sec/SecP521R1FieldElement.h"
#include "org/spongycastle/math/raw/Mod.h"
#include "org/spongycastle/math/raw/Nat.h"
#include "org/spongycastle/util/Arrays.h"

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement)

JavaMathBigInteger *OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_Q;

@implementation OrgSpongycastleMathEcCustomSecSecP521R1FieldElement

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithJavaMathBigInteger_(self, x);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithIntArray:(IOSIntArray *)x {
  OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(self, x);
  return self;
}

- (jboolean)isZero {
  return OrgSpongycastleMathRawNat_isZeroWithInt_withIntArray_(17, x_);
}

- (jboolean)isOne {
  return OrgSpongycastleMathRawNat_isOneWithInt_withIntArray_(17, x_);
}

- (jboolean)testBitZero {
  return OrgSpongycastleMathRawNat_getBitWithIntArray_withInt_(x_, 0) == 1;
}

- (JavaMathBigInteger *)toBigInteger {
  return OrgSpongycastleMathRawNat_toBigIntegerWithInt_withIntArray_(17, x_);
}

- (NSString *)getFieldName {
  return @"SecP521R1Field";
}

- (jint)getFieldSize {
  return [((JavaMathBigInteger *) nil_chk(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_Q)) bitLength];
}

- (OrgSpongycastleMathEcECFieldElement *)addWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSIntArray *z = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_addWithIntArray_withIntArray_withIntArray_(x_, ((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecP521R1FieldElement class]))))->x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)addOne {
  IOSIntArray *z = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_addOneWithIntArray_withIntArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)subtractWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSIntArray *z = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_subtractWithIntArray_withIntArray_withIntArray_(x_, ((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecP521R1FieldElement class]))))->x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)multiplyWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSIntArray *z = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_multiplyWithIntArray_withIntArray_withIntArray_(x_, ((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecP521R1FieldElement class]))))->x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)divideWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSIntArray *z = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathRawMod_invertWithIntArray_withIntArray_withIntArray_(JreLoadStatic(OrgSpongycastleMathEcCustomSecSecP521R1Field, P), ((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecP521R1FieldElement class]))))->x_, z);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_multiplyWithIntArray_withIntArray_withIntArray_(z, x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)negate {
  IOSIntArray *z = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_negateWithIntArray_withIntArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)square {
  IOSIntArray *z = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_squareWithIntArray_withIntArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)invert {
  IOSIntArray *z = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathRawMod_invertWithIntArray_withIntArray_withIntArray_(JreLoadStatic(OrgSpongycastleMathEcCustomSecSecP521R1Field, P), x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)sqrt {
  IOSIntArray *x1 = self->x_;
  if (OrgSpongycastleMathRawNat_isZeroWithInt_withIntArray_(17, x1) || OrgSpongycastleMathRawNat_isOneWithInt_withIntArray_(17, x1)) {
    return self;
  }
  IOSIntArray *t1 = OrgSpongycastleMathRawNat_createWithInt_(17);
  IOSIntArray *t2 = OrgSpongycastleMathRawNat_createWithInt_(17);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_squareNWithIntArray_withInt_withIntArray_(x1, 519, t1);
  OrgSpongycastleMathEcCustomSecSecP521R1Field_squareWithIntArray_withIntArray_(t1, t2);
  return OrgSpongycastleMathRawNat_eqWithInt_withIntArray_withIntArray_(17, x1, t2) ? new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(t1) : nil;
}

- (jboolean)isEqual:(id)other {
  if (other == self) {
    return true;
  }
  if (!([other isKindOfClass:[OrgSpongycastleMathEcCustomSecSecP521R1FieldElement class]])) {
    return false;
  }
  OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *o = (OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) cast_chk(other, [OrgSpongycastleMathEcCustomSecSecP521R1FieldElement class]);
  return OrgSpongycastleMathRawNat_eqWithInt_withIntArray_withIntArray_(17, x_, ((OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *) nil_chk(o))->x_);
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_Q)) hash]) ^ OrgSpongycastleUtilArrays_hashCodeWithIntArray_withInt_withInt_(x_, 0, 17);
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
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 6, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 9, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(initWithIntArray:);
  methods[3].selector = @selector(isZero);
  methods[4].selector = @selector(isOne);
  methods[5].selector = @selector(testBitZero);
  methods[6].selector = @selector(toBigInteger);
  methods[7].selector = @selector(getFieldName);
  methods[8].selector = @selector(getFieldSize);
  methods[9].selector = @selector(addWithOrgSpongycastleMathEcECFieldElement:);
  methods[10].selector = @selector(addOne);
  methods[11].selector = @selector(subtractWithOrgSpongycastleMathEcECFieldElement:);
  methods[12].selector = @selector(multiplyWithOrgSpongycastleMathEcECFieldElement:);
  methods[13].selector = @selector(divideWithOrgSpongycastleMathEcECFieldElement:);
  methods[14].selector = @selector(negate);
  methods[15].selector = @selector(square);
  methods[16].selector = @selector(invert);
  methods[17].selector = @selector(sqrt);
  methods[18].selector = @selector(isEqual:);
  methods[19].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "Q", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x19, -1, 10, -1, -1 },
    { "x_", "[I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;", "[I", "add", "LOrgSpongycastleMathEcECFieldElement;", "subtract", "multiply", "divide", "equals", "LNSObject;", "hashCode", &OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_Q };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecP521R1FieldElement = { "SecP521R1FieldElement", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 20, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement;
}

+ (void)initialize {
  if (self == [OrgSpongycastleMathEcCustomSecSecP521R1FieldElement class]) {
    OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_Q = JreLoadStatic(OrgSpongycastleMathEcCustomSecSecP521R1Curve, q);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement)
  }
}

@end

void OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithJavaMathBigInteger_(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *self, JavaMathBigInteger *x) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  if (x == nil || [x signum] < 0 || [x compareToWithId:OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_Q] >= 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"x value invalid for SecP521R1FieldElement");
  }
  self->x_ = OrgSpongycastleMathEcCustomSecSecP521R1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement, initWithJavaMathBigInteger_, x)
}

OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *create_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement, initWithJavaMathBigInteger_, x)
}

void OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_init(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *self) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  self->x_ = OrgSpongycastleMathRawNat_createWithInt_(17);
}

OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement, init)
}

OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *create_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement, init)
}

void OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *self, IOSIntArray *x) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  self->x_ = x;
}

OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *new_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(IOSIntArray *x) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement, initWithIntArray_, x)
}

OrgSpongycastleMathEcCustomSecSecP521R1FieldElement *create_OrgSpongycastleMathEcCustomSecSecP521R1FieldElement_initWithIntArray_(IOSIntArray *x) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement, initWithIntArray_, x)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecP521R1FieldElement)
