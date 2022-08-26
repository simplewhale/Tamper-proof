//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/EphemeralKeyPair.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/AsymmetricCipherKeyPair.h"
#include "org/spongycastle/crypto/EphemeralKeyPair.h"
#include "org/spongycastle/crypto/KeyEncoder.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"

@interface OrgSpongycastleCryptoEphemeralKeyPair () {
 @public
  OrgSpongycastleCryptoAsymmetricCipherKeyPair *keyPair_;
  id<OrgSpongycastleCryptoKeyEncoder> publicKeyEncoder_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEphemeralKeyPair, keyPair_, OrgSpongycastleCryptoAsymmetricCipherKeyPair *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEphemeralKeyPair, publicKeyEncoder_, id<OrgSpongycastleCryptoKeyEncoder>)

@implementation OrgSpongycastleCryptoEphemeralKeyPair

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair:(OrgSpongycastleCryptoAsymmetricCipherKeyPair *)keyPair
                                 withOrgSpongycastleCryptoKeyEncoder:(id<OrgSpongycastleCryptoKeyEncoder>)publicKeyEncoder {
  OrgSpongycastleCryptoEphemeralKeyPair_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair_withOrgSpongycastleCryptoKeyEncoder_(self, keyPair, publicKeyEncoder);
  return self;
}

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)getKeyPair {
  return keyPair_;
}

- (IOSByteArray *)getEncodedPublicKey {
  return [((id<OrgSpongycastleCryptoKeyEncoder>) nil_chk(publicKeyEncoder_)) getEncodedWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:[((OrgSpongycastleCryptoAsymmetricCipherKeyPair *) nil_chk(keyPair_)) getPublic]];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair:withOrgSpongycastleCryptoKeyEncoder:);
  methods[1].selector = @selector(getKeyPair);
  methods[2].selector = @selector(getEncodedPublicKey);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "keyPair_", "LOrgSpongycastleCryptoAsymmetricCipherKeyPair;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicKeyEncoder_", "LOrgSpongycastleCryptoKeyEncoder;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoAsymmetricCipherKeyPair;LOrgSpongycastleCryptoKeyEncoder;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEphemeralKeyPair = { "EphemeralKeyPair", "org.spongycastle.crypto", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoEphemeralKeyPair;
}

@end

void OrgSpongycastleCryptoEphemeralKeyPair_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair_withOrgSpongycastleCryptoKeyEncoder_(OrgSpongycastleCryptoEphemeralKeyPair *self, OrgSpongycastleCryptoAsymmetricCipherKeyPair *keyPair, id<OrgSpongycastleCryptoKeyEncoder> publicKeyEncoder) {
  NSObject_init(self);
  self->keyPair_ = keyPair;
  self->publicKeyEncoder_ = publicKeyEncoder;
}

OrgSpongycastleCryptoEphemeralKeyPair *new_OrgSpongycastleCryptoEphemeralKeyPair_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair_withOrgSpongycastleCryptoKeyEncoder_(OrgSpongycastleCryptoAsymmetricCipherKeyPair *keyPair, id<OrgSpongycastleCryptoKeyEncoder> publicKeyEncoder) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEphemeralKeyPair, initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair_withOrgSpongycastleCryptoKeyEncoder_, keyPair, publicKeyEncoder)
}

OrgSpongycastleCryptoEphemeralKeyPair *create_OrgSpongycastleCryptoEphemeralKeyPair_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair_withOrgSpongycastleCryptoKeyEncoder_(OrgSpongycastleCryptoAsymmetricCipherKeyPair *keyPair, id<OrgSpongycastleCryptoKeyEncoder> publicKeyEncoder) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEphemeralKeyPair, initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair_withOrgSpongycastleCryptoKeyEncoder_, keyPair, publicKeyEncoder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoEphemeralKeyPair)
