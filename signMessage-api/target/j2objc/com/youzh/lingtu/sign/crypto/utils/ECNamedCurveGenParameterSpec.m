//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/ECNamedCurveGenParameterSpec.java
//

#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/ECNamedCurveGenParameterSpec.h"

@interface ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec () {
 @public
  NSString *name_;
}

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec, name_, NSString *)

@implementation ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec

- (instancetype)initWithNSString:(NSString *)name {
  ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec_initWithNSString_(self, name);
  return self;
}

- (NSString *)getName {
  return name_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(getName);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "name_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec = { "ECNamedCurveGenParameterSpec", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec;
}

@end

void ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec_initWithNSString_(ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec *self, NSString *name) {
  NSObject_init(self);
  self->name_ = name;
}

ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec_initWithNSString_(NSString *name) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec, initWithNSString_, name)
}

ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec_initWithNSString_(NSString *name) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec, initWithNSString_, name)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsECNamedCurveGenParameterSpec)