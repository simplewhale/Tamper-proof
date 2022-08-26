//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/CramerShoupKeyPairGenerator.java
//

#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/AsymmetricCipherKeyPair.h"
#include "org/spongycastle/crypto/KeyGenerationParameters.h"
#include "org/spongycastle/crypto/generators/CramerShoupKeyPairGenerator.h"
#include "org/spongycastle/crypto/params/CramerShoupKeyGenerationParameters.h"
#include "org/spongycastle/crypto/params/CramerShoupParameters.h"
#include "org/spongycastle/crypto/params/CramerShoupPrivateKeyParameters.h"
#include "org/spongycastle/crypto/params/CramerShoupPublicKeyParameters.h"
#include "org/spongycastle/util/BigIntegers.h"

@interface OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator () {
 @public
  OrgSpongycastleCryptoParamsCramerShoupKeyGenerationParameters *param_;
}

- (JavaMathBigInteger *)generateRandomElementWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *)generatePrivateKeyWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                                          withOrgSpongycastleCryptoParamsCramerShoupParameters:(OrgSpongycastleCryptoParamsCramerShoupParameters *)csParams;

- (OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *)calculatePublicKeyWithOrgSpongycastleCryptoParamsCramerShoupParameters:(OrgSpongycastleCryptoParamsCramerShoupParameters *)csParams
                                                                       withOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters:(OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *)sk;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator, param_, OrgSpongycastleCryptoParamsCramerShoupKeyGenerationParameters *)

inline JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_get_ONE(void);
static JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator, ONE, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *self, JavaMathBigInteger *p, JavaSecuritySecureRandom *random);

__attribute__((unused)) static OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generatePrivateKeyWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsCramerShoupParameters_(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *self, JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsCramerShoupParameters *csParams);

__attribute__((unused)) static OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_calculatePublicKeyWithOrgSpongycastleCryptoParamsCramerShoupParameters_withOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters_(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *self, OrgSpongycastleCryptoParamsCramerShoupParameters *csParams, OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *sk);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator)

@implementation OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithOrgSpongycastleCryptoKeyGenerationParameters:(OrgSpongycastleCryptoKeyGenerationParameters *)param {
  self->param_ = (OrgSpongycastleCryptoParamsCramerShoupKeyGenerationParameters *) cast_chk(param, [OrgSpongycastleCryptoParamsCramerShoupKeyGenerationParameters class]);
}

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  OrgSpongycastleCryptoParamsCramerShoupParameters *csParams = [((OrgSpongycastleCryptoParamsCramerShoupKeyGenerationParameters *) nil_chk(param_)) getParameters];
  OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *sk = OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generatePrivateKeyWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsCramerShoupParameters_(self, [((OrgSpongycastleCryptoParamsCramerShoupKeyGenerationParameters *) nil_chk(param_)) getRandom], csParams);
  OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *pk = OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_calculatePublicKeyWithOrgSpongycastleCryptoParamsCramerShoupParameters_withOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters_(self, csParams, sk);
  [((OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *) nil_chk(sk)) setPkWithOrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters:pk];
  return new_OrgSpongycastleCryptoAsymmetricCipherKeyPair_initWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter_withOrgSpongycastleCryptoParamsAsymmetricKeyParameter_(pk, sk);
}

- (JavaMathBigInteger *)generateRandomElementWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                       withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(self, p, random);
}

- (OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *)generatePrivateKeyWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                                          withOrgSpongycastleCryptoParamsCramerShoupParameters:(OrgSpongycastleCryptoParamsCramerShoupParameters *)csParams {
  return OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generatePrivateKeyWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsCramerShoupParameters_(self, random, csParams);
}

- (OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *)calculatePublicKeyWithOrgSpongycastleCryptoParamsCramerShoupParameters:(OrgSpongycastleCryptoParamsCramerShoupParameters *)csParams
                                                                       withOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters:(OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *)sk {
  return OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_calculatePublicKeyWithOrgSpongycastleCryptoParamsCramerShoupParameters_withOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters_(self, csParams, sk);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters;", 0x2, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters;", 0x2, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithOrgSpongycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKeyPair);
  methods[3].selector = @selector(generateRandomElementWithJavaMathBigInteger:withJavaSecuritySecureRandom:);
  methods[4].selector = @selector(generatePrivateKeyWithJavaSecuritySecureRandom:withOrgSpongycastleCryptoParamsCramerShoupParameters:);
  methods[5].selector = @selector(calculatePublicKeyWithOrgSpongycastleCryptoParamsCramerShoupParameters:withOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 8, -1, -1 },
    { "param_", "LOrgSpongycastleCryptoParamsCramerShoupKeyGenerationParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LOrgSpongycastleCryptoKeyGenerationParameters;", "generateRandomElement", "LJavaMathBigInteger;LJavaSecuritySecureRandom;", "generatePrivateKey", "LJavaSecuritySecureRandom;LOrgSpongycastleCryptoParamsCramerShoupParameters;", "calculatePublicKey", "LOrgSpongycastleCryptoParamsCramerShoupParameters;LOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters;", &OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_ONE };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator = { "CramerShoupKeyPairGenerator", "org.spongycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator class]) {
    OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator)
  }
}

@end

void OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_init(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *new_OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator, init)
}

OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *create_OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator, init)
}

JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *self, JavaMathBigInteger *p, JavaSecuritySecureRandom *random) {
  return OrgSpongycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_ONE, [((JavaMathBigInteger *) nil_chk(p)) subtractWithJavaMathBigInteger:OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_ONE], random);
}

OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generatePrivateKeyWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsCramerShoupParameters_(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *self, JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsCramerShoupParameters *csParams) {
  JavaMathBigInteger *p = [((OrgSpongycastleCryptoParamsCramerShoupParameters *) nil_chk(csParams)) getP];
  OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *key = new_OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters_initWithOrgSpongycastleCryptoParamsCramerShoupParameters_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(csParams, OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(self, p, random), OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(self, p, random), OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(self, p, random), OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(self, p, random), OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_generateRandomElementWithJavaMathBigInteger_withJavaSecuritySecureRandom_(self, p, random));
  return key;
}

OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator_calculatePublicKeyWithOrgSpongycastleCryptoParamsCramerShoupParameters_withOrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters_(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator *self, OrgSpongycastleCryptoParamsCramerShoupParameters *csParams, OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *sk) {
  JavaMathBigInteger *g1 = [((OrgSpongycastleCryptoParamsCramerShoupParameters *) nil_chk(csParams)) getG1];
  JavaMathBigInteger *g2 = [csParams getG2];
  JavaMathBigInteger *p = [csParams getP];
  JavaMathBigInteger *c = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(g1)) modPowWithJavaMathBigInteger:[((OrgSpongycastleCryptoParamsCramerShoupPrivateKeyParameters *) nil_chk(sk)) getX1] withJavaMathBigInteger:p])) multiplyWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(g2)) modPowWithJavaMathBigInteger:[sk getX2] withJavaMathBigInteger:p]];
  JavaMathBigInteger *d = [((JavaMathBigInteger *) nil_chk([g1 modPowWithJavaMathBigInteger:[sk getY1] withJavaMathBigInteger:p])) multiplyWithJavaMathBigInteger:[g2 modPowWithJavaMathBigInteger:[sk getY2] withJavaMathBigInteger:p]];
  JavaMathBigInteger *h = [g1 modPowWithJavaMathBigInteger:[sk getZ] withJavaMathBigInteger:p];
  return new_OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters_initWithOrgSpongycastleCryptoParamsCramerShoupParameters_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(csParams, c, d, h);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoGeneratorsCramerShoupKeyPairGenerator)
