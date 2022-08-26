//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/SRTPProtectionProfile.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/tls/SRTPProtectionProfile.h"

@implementation OrgSpongycastleCryptoTlsSRTPProtectionProfile

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsSRTPProtectionProfile_init(self);
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
    { "SRTP_AES128_CM_HMAC_SHA1_80", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsSRTPProtectionProfile_SRTP_AES128_CM_HMAC_SHA1_80, 0x19, -1, -1, -1, -1 },
    { "SRTP_AES128_CM_HMAC_SHA1_32", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsSRTPProtectionProfile_SRTP_AES128_CM_HMAC_SHA1_32, 0x19, -1, -1, -1, -1 },
    { "SRTP_NULL_HMAC_SHA1_80", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsSRTPProtectionProfile_SRTP_NULL_HMAC_SHA1_80, 0x19, -1, -1, -1, -1 },
    { "SRTP_NULL_HMAC_SHA1_32", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsSRTPProtectionProfile_SRTP_NULL_HMAC_SHA1_32, 0x19, -1, -1, -1, -1 },
    { "SRTP_AEAD_AES_128_GCM", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsSRTPProtectionProfile_SRTP_AEAD_AES_128_GCM, 0x19, -1, -1, -1, -1 },
    { "SRTP_AEAD_AES_256_GCM", "I", .constantValue.asInt = OrgSpongycastleCryptoTlsSRTPProtectionProfile_SRTP_AEAD_AES_256_GCM, 0x19, -1, -1, -1, -1 },
  };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsSRTPProtectionProfile = { "SRTPProtectionProfile", "org.spongycastle.crypto.tls", NULL, methods, fields, 7, 0x1, 1, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsSRTPProtectionProfile;
}

@end

void OrgSpongycastleCryptoTlsSRTPProtectionProfile_init(OrgSpongycastleCryptoTlsSRTPProtectionProfile *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoTlsSRTPProtectionProfile *new_OrgSpongycastleCryptoTlsSRTPProtectionProfile_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsSRTPProtectionProfile, init)
}

OrgSpongycastleCryptoTlsSRTPProtectionProfile *create_OrgSpongycastleCryptoTlsSRTPProtectionProfile_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsSRTPProtectionProfile, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsSRTPProtectionProfile)
