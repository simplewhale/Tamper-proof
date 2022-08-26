//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/ParametersWithRandom.java
//

#include "J2ObjC_source.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/params/ParametersWithRandom.h"

@interface OrgSpongycastleCryptoParamsParametersWithRandom () {
 @public
  JavaSecuritySecureRandom *random_;
  id<OrgSpongycastleCryptoCipherParameters> parameters_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsParametersWithRandom, random_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsParametersWithRandom, parameters_, id<OrgSpongycastleCryptoCipherParameters>)

@implementation OrgSpongycastleCryptoParamsParametersWithRandom

- (instancetype)initWithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)parameters
                                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(self, parameters, random);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)parameters {
  OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_(self, parameters);
  return self;
}

- (JavaSecuritySecureRandom *)getRandom {
  return random_;
}

- (id<OrgSpongycastleCryptoCipherParameters>)getParameters {
  return parameters_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySecureRandom;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoCipherParameters:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getRandom);
  methods[3].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "parameters_", "LOrgSpongycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoCipherParameters;LJavaSecuritySecureRandom;", "LOrgSpongycastleCryptoCipherParameters;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsParametersWithRandom = { "ParametersWithRandom", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsParametersWithRandom;
}

@end

void OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(OrgSpongycastleCryptoParamsParametersWithRandom *self, id<OrgSpongycastleCryptoCipherParameters> parameters, JavaSecuritySecureRandom *random) {
  NSObject_init(self);
  self->random_ = random;
  self->parameters_ = parameters;
}

OrgSpongycastleCryptoParamsParametersWithRandom *new_OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(id<OrgSpongycastleCryptoCipherParameters> parameters, JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsParametersWithRandom, initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_, parameters, random)
}

OrgSpongycastleCryptoParamsParametersWithRandom *create_OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(id<OrgSpongycastleCryptoCipherParameters> parameters, JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsParametersWithRandom, initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_, parameters, random)
}

void OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_(OrgSpongycastleCryptoParamsParametersWithRandom *self, id<OrgSpongycastleCryptoCipherParameters> parameters) {
  OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(self, parameters, new_JavaSecuritySecureRandom_init());
}

OrgSpongycastleCryptoParamsParametersWithRandom *new_OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_(id<OrgSpongycastleCryptoCipherParameters> parameters) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsParametersWithRandom, initWithOrgSpongycastleCryptoCipherParameters_, parameters)
}

OrgSpongycastleCryptoParamsParametersWithRandom *create_OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_(id<OrgSpongycastleCryptoCipherParameters> parameters) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsParametersWithRandom, initWithOrgSpongycastleCryptoCipherParameters_, parameters)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsParametersWithRandom)
