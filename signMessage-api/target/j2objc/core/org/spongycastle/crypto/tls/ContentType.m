//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/ContentType.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/tls/ContentType.h"

@implementation OrgSpongycastleCryptoTlsContentType

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsContentType_init(self);
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
    { "change_cipher_spec", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsContentType_change_cipher_spec, 0x19, -1, -1, -1, -1 },
    { "alert", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsContentType_alert, 0x19, -1, -1, -1, -1 },
    { "handshake", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsContentType_handshake, 0x19, -1, -1, -1, -1 },
    { "application_data", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsContentType_application_data, 0x19, -1, -1, -1, -1 },
    { "heartbeat", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsContentType_heartbeat, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsContentType = { "ContentType", "org.spongycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 5, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsContentType;
}

@end

void OrgSpongycastleCryptoTlsContentType_init(OrgSpongycastleCryptoTlsContentType *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoTlsContentType *new_OrgSpongycastleCryptoTlsContentType_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsContentType, init)
}

OrgSpongycastleCryptoTlsContentType *create_OrgSpongycastleCryptoTlsContentType_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsContentType, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsContentType)
