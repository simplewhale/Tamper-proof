//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/ClientAuthenticationType.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/tls/ClientAuthenticationType.h"

@implementation OrgSpongycastleCryptoTlsClientAuthenticationType

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsClientAuthenticationType_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "anonymous", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsClientAuthenticationType_anonymous, 0x19, -1, -1, -1, -1 },
    { "certificate_based", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsClientAuthenticationType_certificate_based, 0x19, -1, -1, -1, -1 },
    { "psk", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsClientAuthenticationType_psk, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsClientAuthenticationType = { "ClientAuthenticationType", "org.spongycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsClientAuthenticationType;
}

@end

void OrgSpongycastleCryptoTlsClientAuthenticationType_init(OrgSpongycastleCryptoTlsClientAuthenticationType *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoTlsClientAuthenticationType *new_OrgSpongycastleCryptoTlsClientAuthenticationType_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsClientAuthenticationType, init)
}

OrgSpongycastleCryptoTlsClientAuthenticationType *create_OrgSpongycastleCryptoTlsClientAuthenticationType_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsClientAuthenticationType, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsClientAuthenticationType)
