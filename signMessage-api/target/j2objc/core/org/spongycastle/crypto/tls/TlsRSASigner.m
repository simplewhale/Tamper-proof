//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsRSASigner.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalStateException.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/crypto/AsymmetricBlockCipher.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/Signer.h"
#include "org/spongycastle/crypto/digests/NullDigest.h"
#include "org/spongycastle/crypto/encodings/PKCS1Encoding.h"
#include "org/spongycastle/crypto/engines/RSABlindedEngine.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/params/ParametersWithRandom.h"
#include "org/spongycastle/crypto/params/RSAKeyParameters.h"
#include "org/spongycastle/crypto/signers/GenericSigner.h"
#include "org/spongycastle/crypto/signers/RSADigestSigner.h"
#include "org/spongycastle/crypto/tls/AbstractTlsSigner.h"
#include "org/spongycastle/crypto/tls/CombinedHash.h"
#include "org/spongycastle/crypto/tls/SignatureAlgorithm.h"
#include "org/spongycastle/crypto/tls/SignatureAndHashAlgorithm.h"
#include "org/spongycastle/crypto/tls/TlsContext.h"
#include "org/spongycastle/crypto/tls/TlsRSASigner.h"
#include "org/spongycastle/crypto/tls/TlsUtils.h"

@implementation OrgSpongycastleCryptoTlsTlsRSASigner

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsTlsRSASigner_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)generateRawSignatureWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                      withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)privateKey
                                                                              withByteArray:(IOSByteArray *)hash_ {
  id<OrgSpongycastleCryptoSigner> signer = [self makeSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:algorithm withBoolean:true withBoolean:true withOrgSpongycastleCryptoCipherParameters:new_OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(privateKey, [((id<OrgSpongycastleCryptoTlsTlsContext>) nil_chk(self->context_)) getSecureRandom])];
  [((id<OrgSpongycastleCryptoSigner>) nil_chk(signer)) updateWithByteArray:hash_ withInt:0 withInt:((IOSByteArray *) nil_chk(hash_))->size_];
  return [signer generateSignature];
}

- (jboolean)verifyRawSignatureWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                                                      withByteArray:(IOSByteArray *)sigBytes
                              withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)publicKey
                                                                      withByteArray:(IOSByteArray *)hash_ {
  id<OrgSpongycastleCryptoSigner> signer = [self makeSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:algorithm withBoolean:true withBoolean:false withOrgSpongycastleCryptoCipherParameters:publicKey];
  [((id<OrgSpongycastleCryptoSigner>) nil_chk(signer)) updateWithByteArray:hash_ withInt:0 withInt:((IOSByteArray *) nil_chk(hash_))->size_];
  return [signer verifySignatureWithByteArray:sigBytes];
}

- (id<OrgSpongycastleCryptoSigner>)createSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                               withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)privateKey {
  return [self makeSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:algorithm withBoolean:false withBoolean:true withOrgSpongycastleCryptoCipherParameters:new_OrgSpongycastleCryptoParamsParametersWithRandom_initWithOrgSpongycastleCryptoCipherParameters_withJavaSecuritySecureRandom_(privateKey, [((id<OrgSpongycastleCryptoTlsTlsContext>) nil_chk(self->context_)) getSecureRandom])];
}

- (id<OrgSpongycastleCryptoSigner>)createVerifyerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                                 withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)publicKey {
  return [self makeSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:algorithm withBoolean:false withBoolean:false withOrgSpongycastleCryptoCipherParameters:publicKey];
}

- (jboolean)isValidPublicKeyWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)publicKey {
  return [publicKey isKindOfClass:[OrgSpongycastleCryptoParamsRSAKeyParameters class]] && ![((OrgSpongycastleCryptoParamsAsymmetricKeyParameter *) nil_chk(publicKey)) isPrivate];
}

- (id<OrgSpongycastleCryptoSigner>)makeSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                                                                       withBoolean:(jboolean)raw
                                                                                       withBoolean:(jboolean)forSigning
                                                         withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)cp {
  if ((algorithm != nil) != OrgSpongycastleCryptoTlsTlsUtils_isTLSv12WithOrgSpongycastleCryptoTlsTlsContext_(context_)) {
    @throw new_JavaLangIllegalStateException_init();
  }
  if (algorithm != nil && [algorithm getSignature] != OrgSpongycastleCryptoTlsSignatureAlgorithm_rsa) {
    @throw new_JavaLangIllegalStateException_init();
  }
  id<OrgSpongycastleCryptoDigest> d;
  if (raw) {
    d = new_OrgSpongycastleCryptoDigestsNullDigest_init();
  }
  else if (algorithm == nil) {
    d = new_OrgSpongycastleCryptoTlsCombinedHash_init();
  }
  else {
    d = OrgSpongycastleCryptoTlsTlsUtils_createHashWithShort_([algorithm getHash]);
  }
  id<OrgSpongycastleCryptoSigner> s;
  if (algorithm != nil) {
    s = new_OrgSpongycastleCryptoSignersRSADigestSigner_initWithOrgSpongycastleCryptoDigest_withOrgSpongycastleAsn1ASN1ObjectIdentifier_(d, OrgSpongycastleCryptoTlsTlsUtils_getOIDForHashAlgorithmWithShort_([algorithm getHash]));
  }
  else {
    s = new_OrgSpongycastleCryptoSignersGenericSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_([self createRSAImpl], d);
  }
  [s init__WithBoolean:forSigning withOrgSpongycastleCryptoCipherParameters:cp];
  return s;
}

- (id<OrgSpongycastleCryptoAsymmetricBlockCipher>)createRSAImpl {
  return new_OrgSpongycastleCryptoEncodingsPKCS1Encoding_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_(new_OrgSpongycastleCryptoEnginesRSABlindedEngine_init());
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, 2, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoSigner;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoSigner;", 0x1, 7, 6, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoSigner;", 0x4, 10, 11, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoAsymmetricBlockCipher;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateRawSignatureWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:withByteArray:);
  methods[2].selector = @selector(verifyRawSignatureWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:withByteArray:withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:withByteArray:);
  methods[3].selector = @selector(createSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:);
  methods[4].selector = @selector(createVerifyerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:);
  methods[5].selector = @selector(isValidPublicKeyWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:);
  methods[6].selector = @selector(makeSignerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:withBoolean:withBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[7].selector = @selector(createRSAImpl);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generateRawSignature", "LOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm;LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;[B", "LOrgSpongycastleCryptoCryptoException;", "verifyRawSignature", "LOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm;[BLOrgSpongycastleCryptoParamsAsymmetricKeyParameter;[B", "createSigner", "LOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm;LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;", "createVerifyer", "isValidPublicKey", "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;", "makeSigner", "LOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm;ZZLOrgSpongycastleCryptoCipherParameters;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsTlsRSASigner = { "TlsRSASigner", "org.spongycastle.crypto.tls", ptrTable, methods, NULL, 7, 0x1, 8, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsTlsRSASigner;
}

@end

void OrgSpongycastleCryptoTlsTlsRSASigner_init(OrgSpongycastleCryptoTlsTlsRSASigner *self) {
  OrgSpongycastleCryptoTlsAbstractTlsSigner_init(self);
}

OrgSpongycastleCryptoTlsTlsRSASigner *new_OrgSpongycastleCryptoTlsTlsRSASigner_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsTlsRSASigner, init)
}

OrgSpongycastleCryptoTlsTlsRSASigner *create_OrgSpongycastleCryptoTlsTlsRSASigner_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsTlsRSASigner, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsTlsRSASigner)