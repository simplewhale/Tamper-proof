//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/DSTU4145KeyPairGenerator.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/AsymmetricCipherKeyPair.h"
#include "org/spongycastle/crypto/generators/DSTU4145KeyPairGenerator.h"
#include "org/spongycastle/crypto/generators/ECKeyPairGenerator.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/params/ECDomainParameters.h"
#include "org/spongycastle/crypto/params/ECPrivateKeyParameters.h"
#include "org/spongycastle/crypto/params/ECPublicKeyParameters.h"
#include "org/spongycastle/math/ec/ECPoint.h"

@implementation OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  OrgSpongycastleCryptoAsymmetricCipherKeyPair *pair = [super generateKeyPair];
  OrgSpongycastleCryptoParamsECPublicKeyParameters *pub = (OrgSpongycastleCryptoParamsECPublicKeyParameters *) cast_chk([((OrgSpongycastleCryptoAsymmetricCipherKeyPair *) nil_chk(pair)) getPublic], [OrgSpongycastleCryptoParamsECPublicKeyParameters class]);
  OrgSpongycastleCryptoParamsECPrivateKeyParameters *priv = (OrgSpongycastleCryptoParamsECPrivateKeyParameters *) cast_chk([pair getPrivate], [OrgSpongycastleCryptoParamsECPrivateKeyParameters class]);
  pub = new_OrgSpongycastleCryptoParamsECPublicKeyParameters_initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleCryptoParamsECDomainParameters_([((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleCryptoParamsECPublicKeyParameters *) nil_chk(pub)) getQ])) negate], [pub getParameters]);
  return new_OrgSpongycastleCryptoAsymmetricCipherKeyPair_initWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter_withOrgSpongycastleCryptoParamsAsymmetricKeyParameter_(pub, priv);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateKeyPair);
  #pragma clang diagnostic pop
  static const J2ObjcClassInfo _OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator = { "DSTU4145KeyPairGenerator", "org.spongycastle.crypto.generators", NULL, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator;
}

@end

void OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_init(OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator *self) {
  OrgSpongycastleCryptoGeneratorsECKeyPairGenerator_init(self);
}

OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator *new_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator, init)
}

OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator *create_OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoGeneratorsDSTU4145KeyPairGenerator)
