//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/SimpleBigDecimal.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/StringBuffer.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ECConstants.h"
#include "org/spongycastle/math/ec/SimpleBigDecimal.h"

@interface OrgSpongycastleMathEcSimpleBigDecimal () {
 @public
  JavaMathBigInteger *bigInt_;
  jint scale__;
}

- (void)checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleMathEcSimpleBigDecimal, bigInt_, JavaMathBigInteger *)

inline jlong OrgSpongycastleMathEcSimpleBigDecimal_get_serialVersionUID(void);
#define OrgSpongycastleMathEcSimpleBigDecimal_serialVersionUID 1LL
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleMathEcSimpleBigDecimal, serialVersionUID, jlong)

__attribute__((unused)) static void OrgSpongycastleMathEcSimpleBigDecimal_checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal_(OrgSpongycastleMathEcSimpleBigDecimal *self, OrgSpongycastleMathEcSimpleBigDecimal *b);

@implementation OrgSpongycastleMathEcSimpleBigDecimal

+ (OrgSpongycastleMathEcSimpleBigDecimal *)getInstanceWithJavaMathBigInteger:(JavaMathBigInteger *)value
                                                                     withInt:(jint)scale_ {
  return OrgSpongycastleMathEcSimpleBigDecimal_getInstanceWithJavaMathBigInteger_withInt_(value, scale_);
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)bigInt
                                   withInt:(jint)scale_ {
  OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(self, bigInt, scale_);
  return self;
}

- (void)checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b {
  OrgSpongycastleMathEcSimpleBigDecimal_checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal_(self, b);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)adjustScaleWithInt:(jint)newScale {
  if (newScale < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"scale may not be negative");
  }
  if (newScale == scale__) {
    return self;
  }
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) shiftLeftWithInt:newScale - scale__], newScale);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)addWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b {
  OrgSpongycastleMathEcSimpleBigDecimal_checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal_(self, b);
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) addWithJavaMathBigInteger:((OrgSpongycastleMathEcSimpleBigDecimal *) nil_chk(b))->bigInt_], scale__);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)addWithJavaMathBigInteger:(JavaMathBigInteger *)b {
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) addWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(b)) shiftLeftWithInt:scale__]], scale__);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)negate {
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) negate], scale__);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)subtractWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b {
  return [self addWithOrgSpongycastleMathEcSimpleBigDecimal:[((OrgSpongycastleMathEcSimpleBigDecimal *) nil_chk(b)) negate]];
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)subtractWithJavaMathBigInteger:(JavaMathBigInteger *)b {
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) subtractWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(b)) shiftLeftWithInt:scale__]], scale__);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)multiplyWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b {
  OrgSpongycastleMathEcSimpleBigDecimal_checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal_(self, b);
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) multiplyWithJavaMathBigInteger:((OrgSpongycastleMathEcSimpleBigDecimal *) nil_chk(b))->bigInt_], scale__ + scale__);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)multiplyWithJavaMathBigInteger:(JavaMathBigInteger *)b {
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) multiplyWithJavaMathBigInteger:b], scale__);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)divideWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)b {
  OrgSpongycastleMathEcSimpleBigDecimal_checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal_(self, b);
  JavaMathBigInteger *dividend = [((JavaMathBigInteger *) nil_chk(bigInt_)) shiftLeftWithInt:scale__];
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(dividend)) divideWithJavaMathBigInteger:((OrgSpongycastleMathEcSimpleBigDecimal *) nil_chk(b))->bigInt_], scale__);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)divideWithJavaMathBigInteger:(JavaMathBigInteger *)b {
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) divideWithJavaMathBigInteger:b], scale__);
}

- (OrgSpongycastleMathEcSimpleBigDecimal *)shiftLeftWithInt:(jint)n {
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) shiftLeftWithInt:n], scale__);
}

- (jint)compareToWithOrgSpongycastleMathEcSimpleBigDecimal:(OrgSpongycastleMathEcSimpleBigDecimal *)val {
  OrgSpongycastleMathEcSimpleBigDecimal_checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal_(self, val);
  return [((JavaMathBigInteger *) nil_chk(bigInt_)) compareToWithId:((OrgSpongycastleMathEcSimpleBigDecimal *) nil_chk(val))->bigInt_];
}

- (jint)compareToWithJavaMathBigInteger:(JavaMathBigInteger *)val {
  return [((JavaMathBigInteger *) nil_chk(bigInt_)) compareToWithId:[((JavaMathBigInteger *) nil_chk(val)) shiftLeftWithInt:scale__]];
}

- (JavaMathBigInteger *)floor {
  return [((JavaMathBigInteger *) nil_chk(bigInt_)) shiftRightWithInt:scale__];
}

- (JavaMathBigInteger *)round {
  OrgSpongycastleMathEcSimpleBigDecimal *oneHalf = new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(JreLoadStatic(OrgSpongycastleMathEcECConstants, ONE), 1);
  return [((OrgSpongycastleMathEcSimpleBigDecimal *) nil_chk([self addWithOrgSpongycastleMathEcSimpleBigDecimal:[oneHalf adjustScaleWithInt:scale__]])) floor];
}

- (jint)intValue {
  return [((JavaMathBigInteger *) nil_chk([self floor])) intValue];
}

- (jlong)longValue {
  return [((JavaMathBigInteger *) nil_chk([self floor])) longLongValue];
}

- (jint)getScale {
  return scale__;
}

- (NSString *)description {
  if (scale__ == 0) {
    return [((JavaMathBigInteger *) nil_chk(bigInt_)) description];
  }
  JavaMathBigInteger *floorBigInt = [self floor];
  JavaMathBigInteger *fract = [((JavaMathBigInteger *) nil_chk(bigInt_)) subtractWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(floorBigInt)) shiftLeftWithInt:scale__]];
  if ([bigInt_ signum] == -1) {
    fract = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(JreLoadStatic(OrgSpongycastleMathEcECConstants, ONE))) shiftLeftWithInt:scale__])) subtractWithJavaMathBigInteger:fract];
  }
  if (([floorBigInt signum] == -1) && (!([((JavaMathBigInteger *) nil_chk(fract)) isEqual:JreLoadStatic(OrgSpongycastleMathEcECConstants, ZERO)]))) {
    floorBigInt = [floorBigInt addWithJavaMathBigInteger:JreLoadStatic(OrgSpongycastleMathEcECConstants, ONE)];
  }
  NSString *leftOfPoint = [((JavaMathBigInteger *) nil_chk(floorBigInt)) description];
  IOSCharArray *fractCharArr = [IOSCharArray newArrayWithLength:scale__];
  NSString *fractStr = [((JavaMathBigInteger *) nil_chk(fract)) toStringWithInt:2];
  jint fractLen = [((NSString *) nil_chk(fractStr)) java_length];
  jint zeroes = scale__ - fractLen;
  for (jint i = 0; i < zeroes; i++) {
    *IOSCharArray_GetRef(fractCharArr, i) = '0';
  }
  for (jint j = 0; j < fractLen; j++) {
    *IOSCharArray_GetRef(fractCharArr, zeroes + j) = [fractStr charAtWithInt:j];
  }
  NSString *rightOfPoint = [NSString java_stringWithCharacters:fractCharArr];
  JavaLangStringBuffer *sb = new_JavaLangStringBuffer_initWithNSString_(leftOfPoint);
  (void) [sb appendWithNSString:@"."];
  (void) [sb appendWithNSString:rightOfPoint];
  return [sb description];
}

- (jboolean)isEqual:(id)o {
  if (self == o) {
    return true;
  }
  if (!([o isKindOfClass:[OrgSpongycastleMathEcSimpleBigDecimal class]])) {
    return false;
  }
  OrgSpongycastleMathEcSimpleBigDecimal *other = (OrgSpongycastleMathEcSimpleBigDecimal *) cast_chk(o, [OrgSpongycastleMathEcSimpleBigDecimal class]);
  return (([((JavaMathBigInteger *) nil_chk(bigInt_)) isEqual:((OrgSpongycastleMathEcSimpleBigDecimal *) nil_chk(other))->bigInt_]) && (scale__ == other->scale__));
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(bigInt_)) hash]) ^ scale__;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 6, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 8, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 8, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 9, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 9, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 10, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 10, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcSimpleBigDecimal;", 0x1, 11, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 12, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 12, 7, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 13, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 14, 15, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 16, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithJavaMathBigInteger:withInt:);
  methods[1].selector = @selector(initWithJavaMathBigInteger:withInt:);
  methods[2].selector = @selector(checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal:);
  methods[3].selector = @selector(adjustScaleWithInt:);
  methods[4].selector = @selector(addWithOrgSpongycastleMathEcSimpleBigDecimal:);
  methods[5].selector = @selector(addWithJavaMathBigInteger:);
  methods[6].selector = @selector(negate);
  methods[7].selector = @selector(subtractWithOrgSpongycastleMathEcSimpleBigDecimal:);
  methods[8].selector = @selector(subtractWithJavaMathBigInteger:);
  methods[9].selector = @selector(multiplyWithOrgSpongycastleMathEcSimpleBigDecimal:);
  methods[10].selector = @selector(multiplyWithJavaMathBigInteger:);
  methods[11].selector = @selector(divideWithOrgSpongycastleMathEcSimpleBigDecimal:);
  methods[12].selector = @selector(divideWithJavaMathBigInteger:);
  methods[13].selector = @selector(shiftLeftWithInt:);
  methods[14].selector = @selector(compareToWithOrgSpongycastleMathEcSimpleBigDecimal:);
  methods[15].selector = @selector(compareToWithJavaMathBigInteger:);
  methods[16].selector = @selector(floor);
  methods[17].selector = @selector(round);
  methods[18].selector = @selector(intValue);
  methods[19].selector = @selector(longValue);
  methods[20].selector = @selector(getScale);
  methods[21].selector = @selector(description);
  methods[22].selector = @selector(isEqual:);
  methods[23].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = OrgSpongycastleMathEcSimpleBigDecimal_serialVersionUID, 0x1a, -1, -1, -1, -1 },
    { "bigInt_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "scale__", "I", .constantValue.asLong = 0, 0x12, 17, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LJavaMathBigInteger;I", "checkScale", "LOrgSpongycastleMathEcSimpleBigDecimal;", "adjustScale", "I", "add", "LJavaMathBigInteger;", "subtract", "multiply", "divide", "shiftLeft", "compareTo", "toString", "equals", "LNSObject;", "hashCode", "scale" };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcSimpleBigDecimal = { "SimpleBigDecimal", "org.spongycastle.math.ec", ptrTable, methods, fields, 7, 0x0, 24, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcSimpleBigDecimal;
}

@end

OrgSpongycastleMathEcSimpleBigDecimal *OrgSpongycastleMathEcSimpleBigDecimal_getInstanceWithJavaMathBigInteger_withInt_(JavaMathBigInteger *value, jint scale_) {
  OrgSpongycastleMathEcSimpleBigDecimal_initialize();
  return new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(value)) shiftLeftWithInt:scale_], scale_);
}

void OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(OrgSpongycastleMathEcSimpleBigDecimal *self, JavaMathBigInteger *bigInt, jint scale_) {
  NSObject_init(self);
  if (scale_ < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"scale may not be negative");
  }
  self->bigInt_ = bigInt;
  self->scale__ = scale_;
}

OrgSpongycastleMathEcSimpleBigDecimal *new_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(JavaMathBigInteger *bigInt, jint scale_) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcSimpleBigDecimal, initWithJavaMathBigInteger_withInt_, bigInt, scale_)
}

OrgSpongycastleMathEcSimpleBigDecimal *create_OrgSpongycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(JavaMathBigInteger *bigInt, jint scale_) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcSimpleBigDecimal, initWithJavaMathBigInteger_withInt_, bigInt, scale_)
}

void OrgSpongycastleMathEcSimpleBigDecimal_checkScaleWithOrgSpongycastleMathEcSimpleBigDecimal_(OrgSpongycastleMathEcSimpleBigDecimal *self, OrgSpongycastleMathEcSimpleBigDecimal *b) {
  if (self->scale__ != ((OrgSpongycastleMathEcSimpleBigDecimal *) nil_chk(b))->scale__) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Only SimpleBigDecimal of same scale allowed in arithmetic operations");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcSimpleBigDecimal)
