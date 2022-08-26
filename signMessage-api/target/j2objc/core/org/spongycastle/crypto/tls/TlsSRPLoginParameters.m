//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsSRPLoginParameters.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/params/SRP6GroupParameters.h"
#include "org/spongycastle/crypto/tls/TlsSRPLoginParameters.h"

@implementation OrgSpongycastleCryptoTlsTlsSRPLoginParameters

- (instancetype)initWithOrgSpongycastleCryptoParamsSRP6GroupParameters:(OrgSpongycastleCryptoParamsSRP6GroupParameters *)group
                                                withJavaMathBigInteger:(JavaMathBigInteger *)verifier
                                                         withByteArray:(IOSByteArray *)salt {
  OrgSpongycastleCryptoTlsTlsSRPLoginParameters_initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withJavaMathBigInteger_withByteArray_(self, group, verifier, salt);
  return self;
}

- (OrgSpongycastleCryptoParamsSRP6GroupParameters *)getGroup {
  return group_;
}

- (IOSByteArray *)getSalt {
  return salt_;
}

- (JavaMathBigInteger *)getVerifier {
  return verifier_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsSRP6GroupParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoParamsSRP6GroupParameters:withJavaMathBigInteger:withByteArray:);
  methods[1].selector = @selector(getGroup);
  methods[2].selector = @selector(getSalt);
  methods[3].selector = @selector(getVerifier);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "group_", "LOrgSpongycastleCryptoParamsSRP6GroupParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "verifier_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "salt_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoParamsSRP6GroupParameters;LJavaMathBigInteger;[B" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsTlsSRPLoginParameters = { "TlsSRPLoginParameters", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 4, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsTlsSRPLoginParameters;
}

@end

void OrgSpongycastleCryptoTlsTlsSRPLoginParameters_initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withJavaMathBigInteger_withByteArray_(OrgSpongycastleCryptoTlsTlsSRPLoginParameters *self, OrgSpongycastleCryptoParamsSRP6GroupParameters *group, JavaMathBigInteger *verifier, IOSByteArray *salt) {
  NSObject_init(self);
  self->group_ = group;
  self->verifier_ = verifier;
  self->salt_ = salt;
}

OrgSpongycastleCryptoTlsTlsSRPLoginParameters *new_OrgSpongycastleCryptoTlsTlsSRPLoginParameters_initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withJavaMathBigInteger_withByteArray_(OrgSpongycastleCryptoParamsSRP6GroupParameters *group, JavaMathBigInteger *verifier, IOSByteArray *salt) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsTlsSRPLoginParameters, initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withJavaMathBigInteger_withByteArray_, group, verifier, salt)
}

OrgSpongycastleCryptoTlsTlsSRPLoginParameters *create_OrgSpongycastleCryptoTlsTlsSRPLoginParameters_initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withJavaMathBigInteger_withByteArray_(OrgSpongycastleCryptoParamsSRP6GroupParameters *group, JavaMathBigInteger *verifier, IOSByteArray *salt) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsTlsSRPLoginParameters, initWithOrgSpongycastleCryptoParamsSRP6GroupParameters_withJavaMathBigInteger_withByteArray_, group, verifier, salt)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsTlsSRPLoginParameters)
