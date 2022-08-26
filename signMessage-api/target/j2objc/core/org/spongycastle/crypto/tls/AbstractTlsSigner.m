//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/AbstractTlsSigner.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/Signer.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/tls/AbstractTlsSigner.h"
#include "org/spongycastle/crypto/tls/TlsContext.h"

#pragma clang diagnostic ignored "-Wprotocol"

@implementation OrgSpongycastleCryptoTlsAbstractTlsSigner

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsAbstractTlsSigner_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithOrgSpongycastleCryptoTlsTlsContext:(id<OrgSpongycastleCryptoTlsTlsContext>)context {
  self->context_ = context;
}

- (IOSByteArray *)generateRawSignatureWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)privateKey
                                                                              withByteArray:(IOSByteArray *)md5AndSha1 {
  return [self generateRawSignatureWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:nil withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:privateKey withByteArray:md5AndSha1];
}

- (jboolean)verifyRawSignatureWithByteArray:(IOSByteArray *)sigBytes
withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)publicKey
                              withByteArray:(IOSByteArray *)md5AndSha1 {
  return [self verifyRawSignatureWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:nil withByteArray:sigBytes withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:publicKey withByteArray:md5AndSha1];
}

- (id<OrgSpongycastleCryptoSigner>)createSignerWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)privateKey {
  return [self createSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:nil withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:privateKey];
}

- (id<OrgSpongycastleCryptoSigner>)createVerifyerWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)publicKey {
  return [self createVerifyerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:nil withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:publicKey];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 2, 3, 4, -1, -1, -1 },
    { NULL, "Z", 0x1, 5, 6, 4, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoSigner;", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoSigner;", 0x1, 9, 8, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithOrgSpongycastleCryptoTlsTlsContext:);
  methods[2].selector = @selector(generateRawSignatureWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:withByteArray:);
  methods[3].selector = @selector(verifyRawSignatureWithByteArray:withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:withByteArray:);
  methods[4].selector = @selector(createSignerWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:);
  methods[5].selector = @selector(createVerifyerWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "context_", "LOrgSpongycastleCryptoTlsTlsContext;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LOrgSpongycastleCryptoTlsTlsContext;", "generateRawSignature", "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;[B", "LOrgSpongycastleCryptoCryptoException;", "verifyRawSignature", "[BLOrgSpongycastleCryptoParamsAsymmetricKeyParameter;[B", "createSigner", "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;", "createVerifyer" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsAbstractTlsSigner = { "AbstractTlsSigner", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x401, 6, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsAbstractTlsSigner;
}

@end

void OrgSpongycastleCryptoTlsAbstractTlsSigner_init(OrgSpongycastleCryptoTlsAbstractTlsSigner *self) {
  NSObject_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsAbstractTlsSigner)
