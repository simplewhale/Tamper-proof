//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/ntru/NTRUEncryptionKeyParameters.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUEncryptionKeyParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUEncryptionParameters.h"

@implementation OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters

- (instancetype)initWithBoolean:(jboolean)privateKey
withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters:(OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *)params {
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(self, privateKey, params);
  return self;
}

- (OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *)getParameters {
  return params_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters:);
  methods[1].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZLOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters = { "NTRUEncryptionKeyParameters", "org.spongycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters;
}

@end

void OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters *self, jboolean privateKey, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  OrgSpongycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, privateKey);
  self->params_ = params;
}

OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters *new_OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(jboolean privateKey, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters, initWithBoolean_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_, privateKey, params)
}

OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters *create_OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(jboolean privateKey, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters, initWithBoolean_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_, privateKey, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters)
