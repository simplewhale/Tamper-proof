//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/RuntimeCryptoException.java
//

#include "J2ObjC_source.h"
#include "java/lang/RuntimeException.h"
#include "org/spongycastle/crypto/RuntimeCryptoException.h"

@implementation OrgSpongycastleCryptoRuntimeCryptoException

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoRuntimeCryptoException_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithNSString:(NSString *)message {
  OrgSpongycastleCryptoRuntimeCryptoException_initWithNSString_(self, message);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoRuntimeCryptoException = { "RuntimeCryptoException", "org.spongycastle.crypto", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoRuntimeCryptoException;
}

@end

void OrgSpongycastleCryptoRuntimeCryptoException_init(OrgSpongycastleCryptoRuntimeCryptoException *self) {
  JavaLangRuntimeException_init(self);
}

OrgSpongycastleCryptoRuntimeCryptoException *new_OrgSpongycastleCryptoRuntimeCryptoException_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoRuntimeCryptoException, init)
}

OrgSpongycastleCryptoRuntimeCryptoException *create_OrgSpongycastleCryptoRuntimeCryptoException_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoRuntimeCryptoException, init)
}

void OrgSpongycastleCryptoRuntimeCryptoException_initWithNSString_(OrgSpongycastleCryptoRuntimeCryptoException *self, NSString *message) {
  JavaLangRuntimeException_initWithNSString_(self, message);
}

OrgSpongycastleCryptoRuntimeCryptoException *new_OrgSpongycastleCryptoRuntimeCryptoException_initWithNSString_(NSString *message) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoRuntimeCryptoException, initWithNSString_, message)
}

OrgSpongycastleCryptoRuntimeCryptoException *create_OrgSpongycastleCryptoRuntimeCryptoException_initWithNSString_(NSString *message) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoRuntimeCryptoException, initWithNSString_, message)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoRuntimeCryptoException)
