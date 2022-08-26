//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/PKCS12StoreParameter.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/PKCS12StoreParameter.h"
#include "java/io/OutputStream.h"
#include "java/security/KeyStore.h"

@interface ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter () {
 @public
  JavaIoOutputStream *out_;
  id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter_;
  jboolean forDEREncoding_;
}

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, out_, JavaIoOutputStream *)
J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, protectionParameter_, id<JavaSecurityKeyStore_ProtectionParameter>)

@implementation ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                             withCharArray:(IOSCharArray *)password {
  ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(self, outArg, password);
  return self;
}

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter {
  ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(self, outArg, protectionParameter);
  return self;
}

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                             withCharArray:(IOSCharArray *)password
                               withBoolean:(jboolean)forDEREncoding {
  ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(self, outArg, password, forDEREncoding);
  return self;
}

- (instancetype)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter
                               withBoolean:(jboolean)forDEREncoding {
  ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(self, outArg, protectionParameter, forDEREncoding);
  return self;
}

- (JavaIoOutputStream *)getOutputStream {
  return out_;
}

- (id<JavaSecurityKeyStore_ProtectionParameter>)getProtectionParameter {
  return protectionParameter_;
}

- (jboolean)isForDEREncoding {
  return forDEREncoding_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LJavaIoOutputStream;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyStore_ProtectionParameter;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoOutputStream:withCharArray:);
  methods[1].selector = @selector(initWithJavaIoOutputStream:withJavaSecurityKeyStore_ProtectionParameter:);
  methods[2].selector = @selector(initWithJavaIoOutputStream:withCharArray:withBoolean:);
  methods[3].selector = @selector(initWithJavaIoOutputStream:withJavaSecurityKeyStore_ProtectionParameter:withBoolean:);
  methods[4].selector = @selector(getOutputStream);
  methods[5].selector = @selector(getProtectionParameter);
  methods[6].selector = @selector(isForDEREncoding);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "out_", "LJavaIoOutputStream;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "protectionParameter_", "LJavaSecurityKeyStore_ProtectionParameter;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "forDEREncoding_", "Z", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoOutputStream;[C", "LJavaIoOutputStream;LJavaSecurityKeyStore_ProtectionParameter;", "LJavaIoOutputStream;[CZ", "LJavaIoOutputStream;LJavaSecurityKeyStore_ProtectionParameter;Z" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter = { "PKCS12StoreParameter", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter;
}

@end

void ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *self, JavaIoOutputStream *outArg, IOSCharArray *password) {
  ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(self, outArg, password, false);
}

ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *new_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(JavaIoOutputStream *outArg, IOSCharArray *password) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, initWithJavaIoOutputStream_withCharArray_, outArg, password)
}

ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *create_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(JavaIoOutputStream *outArg, IOSCharArray *password) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, initWithJavaIoOutputStream_withCharArray_, outArg, password)
}

void ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *self, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(self, outArg, protectionParameter, false);
}

ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *new_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_, outArg, protectionParameter)
}

ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *create_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_, outArg, protectionParameter)
}

void ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *self, JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding) {
  ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(self, outArg, new_JavaSecurityKeyStore_PasswordProtection_initWithCharArray_(password), forDEREncoding);
}

ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *new_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, initWithJavaIoOutputStream_withCharArray_withBoolean_, outArg, password, forDEREncoding)
}

ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *create_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, initWithJavaIoOutputStream_withCharArray_withBoolean_, outArg, password, forDEREncoding)
}

void ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *self, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding) {
  NSObject_init(self);
  self->out_ = outArg;
  self->protectionParameter_ = protectionParameter;
  self->forDEREncoding_ = forDEREncoding;
}

ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *new_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_, outArg, protectionParameter, forDEREncoding)
}

ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter *create_ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter, initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_, outArg, protectionParameter, forDEREncoding)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsPKCS12StoreParameter)
