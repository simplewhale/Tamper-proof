//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/EphemeralKeyPairGenerator.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/AsymmetricCipherKeyPair.h"
#include "org/spongycastle/crypto/AsymmetricCipherKeyPairGenerator.h"
#include "org/spongycastle/crypto/EphemeralKeyPair.h"
#include "org/spongycastle/crypto/KeyEncoder.h"
#include "org/spongycastle/crypto/generators/EphemeralKeyPairGenerator.h"

@interface OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator () {
 @public
  id<OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator> gen_;
  id<OrgSpongycastleCryptoKeyEncoder> keyEncoder_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator, gen_, id<OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator, keyEncoder_, id<OrgSpongycastleCryptoKeyEncoder>)

@implementation OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator:(id<OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator>)gen
                                          withOrgSpongycastleCryptoKeyEncoder:(id<OrgSpongycastleCryptoKeyEncoder>)keyEncoder {
  OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator_withOrgSpongycastleCryptoKeyEncoder_(self, gen, keyEncoder);
  return self;
}

- (OrgSpongycastleCryptoEphemeralKeyPair *)generate {
  OrgSpongycastleCryptoAsymmetricCipherKeyPair *eph = [((id<OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator>) nil_chk(gen_)) generateKeyPair];
  return new_OrgSpongycastleCryptoEphemeralKeyPair_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPair_withOrgSpongycastleCryptoKeyEncoder_(eph, keyEncoder_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoEphemeralKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator:withOrgSpongycastleCryptoKeyEncoder:);
  methods[1].selector = @selector(generate);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "gen_", "LOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyEncoder_", "LOrgSpongycastleCryptoKeyEncoder;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator;LOrgSpongycastleCryptoKeyEncoder;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator = { "EphemeralKeyPairGenerator", "org.spongycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator;
}

@end

void OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator_withOrgSpongycastleCryptoKeyEncoder_(OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator *self, id<OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator> gen, id<OrgSpongycastleCryptoKeyEncoder> keyEncoder) {
  NSObject_init(self);
  self->gen_ = gen;
  self->keyEncoder_ = keyEncoder;
}

OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator *new_OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator_withOrgSpongycastleCryptoKeyEncoder_(id<OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator> gen, id<OrgSpongycastleCryptoKeyEncoder> keyEncoder) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator, initWithOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator_withOrgSpongycastleCryptoKeyEncoder_, gen, keyEncoder)
}

OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator *create_OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator_initWithOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator_withOrgSpongycastleCryptoKeyEncoder_(id<OrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator> gen, id<OrgSpongycastleCryptoKeyEncoder> keyEncoder) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator, initWithOrgSpongycastleCryptoAsymmetricCipherKeyPairGenerator_withOrgSpongycastleCryptoKeyEncoder_, gen, keyEncoder)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator)
