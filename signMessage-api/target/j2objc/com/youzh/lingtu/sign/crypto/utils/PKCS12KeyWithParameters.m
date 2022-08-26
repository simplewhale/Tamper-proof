//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/PKCS12KeyWithParameters.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/PKCS12Key.h"
#include "com/youzh/lingtu/sign/crypto/utils/PKCS12KeyWithParameters.h"
#include "org/spongycastle/util/Arrays.h"

@interface ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters () {
 @public
  IOSByteArray *salt_;
  jint iterationCount_;
}

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters, salt_, IOSByteArray *)

@implementation ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters

- (instancetype)initWithCharArray:(IOSCharArray *)password
                    withByteArray:(IOSByteArray *)salt
                          withInt:(jint)iterationCount {
  ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters_initWithCharArray_withByteArray_withInt_(self, password, salt, iterationCount);
  return self;
}

- (instancetype)initWithCharArray:(IOSCharArray *)password
                      withBoolean:(jboolean)useWrongZeroLengthConversion
                    withByteArray:(IOSByteArray *)salt
                          withInt:(jint)iterationCount {
  ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters_initWithCharArray_withBoolean_withByteArray_withInt_(self, password, useWrongZeroLengthConversion, salt, iterationCount);
  return self;
}

- (IOSByteArray *)getSalt {
  return salt_;
}

- (jint)getIterationCount {
  return iterationCount_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithCharArray:withByteArray:withInt:);
  methods[1].selector = @selector(initWithCharArray:withBoolean:withByteArray:withInt:);
  methods[2].selector = @selector(getSalt);
  methods[3].selector = @selector(getIterationCount);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "salt_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "iterationCount_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[C[BI", "[CZ[BI" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters = { "PKCS12KeyWithParameters", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters;
}

@end

void ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters_initWithCharArray_withByteArray_withInt_(ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters *self, IOSCharArray *password, IOSByteArray *salt, jint iterationCount) {
  ComYouzhLingtuSignCryptoUtilsPKCS12Key_initWithCharArray_(self, password);
  self->salt_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(salt);
  self->iterationCount_ = iterationCount;
}

ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters *new_ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters_initWithCharArray_withByteArray_withInt_(IOSCharArray *password, IOSByteArray *salt, jint iterationCount) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters, initWithCharArray_withByteArray_withInt_, password, salt, iterationCount)
}

ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters *create_ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters_initWithCharArray_withByteArray_withInt_(IOSCharArray *password, IOSByteArray *salt, jint iterationCount) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters, initWithCharArray_withByteArray_withInt_, password, salt, iterationCount)
}

void ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters_initWithCharArray_withBoolean_withByteArray_withInt_(ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters *self, IOSCharArray *password, jboolean useWrongZeroLengthConversion, IOSByteArray *salt, jint iterationCount) {
  ComYouzhLingtuSignCryptoUtilsPKCS12Key_initWithCharArray_withBoolean_(self, password, useWrongZeroLengthConversion);
  self->salt_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(salt);
  self->iterationCount_ = iterationCount;
}

ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters *new_ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters_initWithCharArray_withBoolean_withByteArray_withInt_(IOSCharArray *password, jboolean useWrongZeroLengthConversion, IOSByteArray *salt, jint iterationCount) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters, initWithCharArray_withBoolean_withByteArray_withInt_, password, useWrongZeroLengthConversion, salt, iterationCount)
}

ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters *create_ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters_initWithCharArray_withBoolean_withByteArray_withInt_(IOSCharArray *password, jboolean useWrongZeroLengthConversion, IOSByteArray *salt, jint iterationCount) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters, initWithCharArray_withBoolean_withByteArray_withInt_, password, useWrongZeroLengthConversion, salt, iterationCount)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsPKCS12KeyWithParameters)
