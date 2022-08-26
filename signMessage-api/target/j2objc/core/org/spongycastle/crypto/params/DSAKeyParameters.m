//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DSAKeyParameters.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/params/DSAKeyParameters.h"
#include "org/spongycastle/crypto/params/DSAParameters.h"

@interface OrgSpongycastleCryptoParamsDSAKeyParameters () {
 @public
  OrgSpongycastleCryptoParamsDSAParameters *params_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDSAKeyParameters, params_, OrgSpongycastleCryptoParamsDSAParameters *)

@implementation OrgSpongycastleCryptoParamsDSAKeyParameters

- (instancetype)initWithBoolean:(jboolean)isPrivate
withOrgSpongycastleCryptoParamsDSAParameters:(OrgSpongycastleCryptoParamsDSAParameters *)params {
  OrgSpongycastleCryptoParamsDSAKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDSAParameters_(self, isPrivate, params);
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
  methods[0].selector = @selector(initWithBoolean:withOrgSpongycastleCryptoParamsDSAParameters:);
  methods[1].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LOrgSpongycastleCryptoParamsDSAParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZLOrgSpongycastleCryptoParamsDSAParameters;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsDSAKeyParameters = { "DSAKeyParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsDSAKeyParameters;
}

@end

void OrgSpongycastleCryptoParamsDSAKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDSAParameters_(OrgSpongycastleCryptoParamsDSAKeyParameters *self, jboolean isPrivate, OrgSpongycastleCryptoParamsDSAParameters *params) {
  OrgSpongycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, isPrivate);
  self->params_ = params;
}

OrgSpongycastleCryptoParamsDSAKeyParameters *new_OrgSpongycastleCryptoParamsDSAKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDSAParameters_(jboolean isPrivate, OrgSpongycastleCryptoParamsDSAParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDSAKeyParameters, initWithBoolean_withOrgSpongycastleCryptoParamsDSAParameters_, isPrivate, params)
}

OrgSpongycastleCryptoParamsDSAKeyParameters *create_OrgSpongycastleCryptoParamsDSAKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDSAParameters_(jboolean isPrivate, OrgSpongycastleCryptoParamsDSAParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDSAKeyParameters, initWithBoolean_withOrgSpongycastleCryptoParamsDSAParameters_, isPrivate, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsDSAKeyParameters)
