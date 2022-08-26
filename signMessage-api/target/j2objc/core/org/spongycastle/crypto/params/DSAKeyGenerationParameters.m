//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DSAKeyGenerationParameters.java
//

#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/KeyGenerationParameters.h"
#include "org/spongycastle/crypto/params/DSAKeyGenerationParameters.h"
#include "org/spongycastle/crypto/params/DSAParameters.h"

@interface OrgSpongycastleCryptoParamsDSAKeyGenerationParameters () {
 @public
  OrgSpongycastleCryptoParamsDSAParameters *params_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDSAKeyGenerationParameters, params_, OrgSpongycastleCryptoParamsDSAParameters *)

@implementation OrgSpongycastleCryptoParamsDSAKeyGenerationParameters

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
    withOrgSpongycastleCryptoParamsDSAParameters:(OrgSpongycastleCryptoParamsDSAParameters *)params {
  OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_(self, random, params);
  return self;
}

- (OrgSpongycastleCryptoParamsDSAParameters *)getParameters {
  return params_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsDSAParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:withOrgSpongycastleCryptoParamsDSAParameters:);
  methods[1].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LOrgSpongycastleCryptoParamsDSAParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;LOrgSpongycastleCryptoParamsDSAParameters;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsDSAKeyGenerationParameters = { "DSAKeyGenerationParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters;
}

@end

void OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_(OrgSpongycastleCryptoParamsDSAKeyGenerationParameters *self, JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsDSAParameters *params) {
  OrgSpongycastleCryptoKeyGenerationParameters_initWithJavaSecuritySecureRandom_withInt_(self, random, [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleCryptoParamsDSAParameters *) nil_chk(params)) getP])) bitLength] - 1);
  self->params_ = params;
}

OrgSpongycastleCryptoParamsDSAKeyGenerationParameters *new_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_(JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsDSAParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDSAKeyGenerationParameters, initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_, random, params)
}

OrgSpongycastleCryptoParamsDSAKeyGenerationParameters *create_OrgSpongycastleCryptoParamsDSAKeyGenerationParameters_initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_(JavaSecuritySecureRandom *random, OrgSpongycastleCryptoParamsDSAParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDSAKeyGenerationParameters, initWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDSAParameters_, random, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsDSAKeyGenerationParameters)