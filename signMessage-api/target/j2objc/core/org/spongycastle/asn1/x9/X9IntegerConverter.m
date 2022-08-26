//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x9/X9IntegerConverter.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/x9/X9IntegerConverter.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"

@implementation OrgSpongycastleAsn1X9X9IntegerConverter

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleAsn1X9X9IntegerConverter_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jint)getByteLengthWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)c {
  return ([((OrgSpongycastleMathEcECCurve *) nil_chk(c)) getFieldSize] + 7) / 8;
}

- (jint)getByteLengthWithOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)fe {
  return ([((OrgSpongycastleMathEcECFieldElement *) nil_chk(fe)) getFieldSize] + 7) / 8;
}

- (IOSByteArray *)integerToBytesWithJavaMathBigInteger:(JavaMathBigInteger *)s
                                               withInt:(jint)qLength {
  IOSByteArray *bytes = [((JavaMathBigInteger *) nil_chk(s)) toByteArray];
  if (qLength < ((IOSByteArray *) nil_chk(bytes))->size_) {
    IOSByteArray *tmp = [IOSByteArray newArrayWithLength:qLength];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bytes, bytes->size_ - tmp->size_, tmp, 0, tmp->size_);
    return tmp;
  }
  else if (qLength > bytes->size_) {
    IOSByteArray *tmp = [IOSByteArray newArrayWithLength:qLength];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bytes, 0, tmp, tmp->size_ - bytes->size_, bytes->size_);
    return tmp;
  }
  return bytes;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 0, 2, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getByteLengthWithOrgSpongycastleMathEcECCurve:);
  methods[2].selector = @selector(getByteLengthWithOrgSpongycastleMathEcECFieldElement:);
  methods[3].selector = @selector(integerToBytesWithJavaMathBigInteger:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "getByteLength", "LOrgSpongycastleMathEcECCurve;", "LOrgSpongycastleMathEcECFieldElement;", "integerToBytes", "LJavaMathBigInteger;I" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X9X9IntegerConverter = { "X9IntegerConverter", "org.spongycastle.asn1.x9", ptrTable, methods, NULL, 7, 0x1, 4, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X9X9IntegerConverter;
}

@end

void OrgSpongycastleAsn1X9X9IntegerConverter_init(OrgSpongycastleAsn1X9X9IntegerConverter *self) {
  NSObject_init(self);
}

OrgSpongycastleAsn1X9X9IntegerConverter *new_OrgSpongycastleAsn1X9X9IntegerConverter_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X9X9IntegerConverter, init)
}

OrgSpongycastleAsn1X9X9IntegerConverter *create_OrgSpongycastleAsn1X9X9IntegerConverter_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X9X9IntegerConverter, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X9X9IntegerConverter)