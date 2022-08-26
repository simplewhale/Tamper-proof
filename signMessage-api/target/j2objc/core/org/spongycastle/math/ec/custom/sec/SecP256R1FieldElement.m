//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecP256R1FieldElement.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/custom/sec/SecP256R1Curve.h"
#include "org/spongycastle/math/ec/custom/sec/SecP256R1Field.h"
#include "org/spongycastle/math/ec/custom/sec/SecP256R1FieldElement.h"
#include "org/spongycastle/math/raw/Mod.h"
#include "org/spongycastle/math/raw/Nat256.h"
#include "org/spongycastle/util/Arrays.h"

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement)

JavaMathBigInteger *OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_Q;

@implementation OrgSpongycastleMathEcCustomSecSecP256R1FieldElement

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x {
  OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithJavaMathBigInteger_(self, x);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithIntArray:(IOSIntArray *)x {
  OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(self, x);
  return self;
}

- (jboolean)isZero {
  return OrgSpongycastleMathRawNat256_isZeroWithIntArray_(x_);
}

- (jboolean)isOne {
  return OrgSpongycastleMathRawNat256_isOneWithIntArray_(x_);
}

- (jboolean)testBitZero {
  return OrgSpongycastleMathRawNat256_getBitWithIntArray_withInt_(x_, 0) == 1;
}

- (JavaMathBigInteger *)toBigInteger {
  return OrgSpongycastleMathRawNat256_toBigIntegerWithIntArray_(x_);
}

- (NSString *)getFieldName {
  return @"SecP256R1Field";
}

- (jint)getFieldSize {
  return [((JavaMathBigInteger *) nil_chk(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_Q)) bitLength];
}

- (OrgSpongycastleMathEcECFieldElement *)addWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSIntArray *z = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomSecSecP256R1Field_addWithIntArray_withIntArray_withIntArray_(x_, ((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecP256R1FieldElement class]))))->x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)addOne {
  IOSIntArray *z = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomSecSecP256R1Field_addOneWithIntArray_withIntArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)subtractWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSIntArray *z = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomSecSecP256R1Field_subtractWithIntArray_withIntArray_withIntArray_(x_, ((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecP256R1FieldElement class]))))->x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)multiplyWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSIntArray *z = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(x_, ((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecP256R1FieldElement class]))))->x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)divideWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)b {
  IOSIntArray *z = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathRawMod_invertWithIntArray_withIntArray_withIntArray_(JreLoadStatic(OrgSpongycastleMathEcCustomSecSecP256R1Field, P), ((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) nil_chk(((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) cast_chk(b, [OrgSpongycastleMathEcCustomSecSecP256R1FieldElement class]))))->x_, z);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(z, x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)negate {
  IOSIntArray *z = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomSecSecP256R1Field_negateWithIntArray_withIntArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)square {
  IOSIntArray *z = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareWithIntArray_withIntArray_(x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)invert {
  IOSIntArray *z = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathRawMod_invertWithIntArray_withIntArray_withIntArray_(JreLoadStatic(OrgSpongycastleMathEcCustomSecSecP256R1Field, P), x_, z);
  return new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(z);
}

- (OrgSpongycastleMathEcECFieldElement *)sqrt {
  IOSIntArray *x1 = self->x_;
  if (OrgSpongycastleMathRawNat256_isZeroWithIntArray_(x1) || OrgSpongycastleMathRawNat256_isOneWithIntArray_(x1)) {
    return self;
  }
  IOSIntArray *t1 = OrgSpongycastleMathRawNat256_create();
  IOSIntArray *t2 = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareWithIntArray_withIntArray_(x1, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, x1, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(t1, 2, t2);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(t2, t1, t2);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(t2, 4, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, t2, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(t1, 8, t2);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(t2, t1, t2);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(t2, 16, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, t2, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(t1, 32, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, x1, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(t1, 96, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_multiplyWithIntArray_withIntArray_withIntArray_(t1, x1, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareNWithIntArray_withInt_withIntArray_(t1, 94, t1);
  OrgSpongycastleMathEcCustomSecSecP256R1Field_squareWithIntArray_withIntArray_(t1, t2);
  return OrgSpongycastleMathRawNat256_eqWithIntArray_withIntArray_(x1, t2) ? new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(t1) : nil;
}

- (jboolean)isEqual:(id)other {
  if (other == self) {
    return true;
  }
  if (!([other isKindOfClass:[OrgSpongycastleMathEcCustomSecSecP256R1FieldElement class]])) {
    return false;
  }
  OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *o = (OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) cast_chk(other, [OrgSpongycastleMathEcCustomSecSecP256R1FieldElement class]);
  return OrgSpongycastleMathRawNat256_eqWithIntArray_withIntArray_(x_, ((OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *) nil_chk(o))->x_);
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_Q)) hash]) ^ OrgSpongycastleUtilArrays_hashCodeWithIntArray_withInt_withInt_(x_, 0, 8);
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
  static const void *ptrTable[] = { "LJavaMathBigInteger;", "[I", "add", "LOrgSpongycastleMathEcECFieldElement;", "subtract", "multiply", "divide", "equals", "LNSObject;", "hashCode", &OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_Q };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecP256R1FieldElement = { "SecP256R1FieldElement", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, fields, 7, 0x1, 20, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement;
}

+ (void)initialize {
  if (self == [OrgSpongycastleMathEcCustomSecSecP256R1FieldElement class]) {
    OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_Q = JreLoadStatic(OrgSpongycastleMathEcCustomSecSecP256R1Curve, q);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement)
  }
}

@end

void OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithJavaMathBigInteger_(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *self, JavaMathBigInteger *x) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  if (x == nil || [x signum] < 0 || [x compareToWithId:OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_Q] >= 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"x value invalid for SecP256R1FieldElement");
  }
  self->x_ = OrgSpongycastleMathEcCustomSecSecP256R1Field_fromBigIntegerWithJavaMathBigInteger_(x);
}

OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement, initWithJavaMathBigInteger_, x)
}

OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *create_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithJavaMathBigInteger_(JavaMathBigInteger *x) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement, initWithJavaMathBigInteger_, x)
}

void OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_init(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *self) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  self->x_ = OrgSpongycastleMathRawNat256_create();
}

OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement, init)
}

OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *create_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement, init)
}

void OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *self, IOSIntArray *x) {
  OrgSpongycastleMathEcECFieldElement_init(self);
  self->x_ = x;
}

OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *new_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(IOSIntArray *x) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement, initWithIntArray_, x)
}

OrgSpongycastleMathEcCustomSecSecP256R1FieldElement *create_OrgSpongycastleMathEcCustomSecSecP256R1FieldElement_initWithIntArray_(IOSIntArray *x) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement, initWithIntArray_, x)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecP256R1FieldElement)
