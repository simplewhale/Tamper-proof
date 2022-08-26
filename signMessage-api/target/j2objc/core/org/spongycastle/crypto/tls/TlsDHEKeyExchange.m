//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsDHEKeyExchange.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/InputStream.h"
#include "java/security/SecureRandom.h"
#include "java/util/Vector.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/Signer.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/params/DHParameters.h"
#include "org/spongycastle/crypto/params/DHPrivateKeyParameters.h"
#include "org/spongycastle/crypto/params/DHPublicKeyParameters.h"
#include "org/spongycastle/crypto/tls/AlertDescription.h"
#include "org/spongycastle/crypto/tls/Certificate.h"
#include "org/spongycastle/crypto/tls/DigestInputBuffer.h"
#include "org/spongycastle/crypto/tls/DigitallySigned.h"
#include "org/spongycastle/crypto/tls/SecurityParameters.h"
#include "org/spongycastle/crypto/tls/ServerDHParams.h"
#include "org/spongycastle/crypto/tls/SignatureAndHashAlgorithm.h"
#include "org/spongycastle/crypto/tls/SignerInputBuffer.h"
#include "org/spongycastle/crypto/tls/TlsContext.h"
#include "org/spongycastle/crypto/tls/TlsCredentials.h"
#include "org/spongycastle/crypto/tls/TlsDHEKeyExchange.h"
#include "org/spongycastle/crypto/tls/TlsDHKeyExchange.h"
#include "org/spongycastle/crypto/tls/TlsDHUtils.h"
#include "org/spongycastle/crypto/tls/TlsFatalAlert.h"
#include "org/spongycastle/crypto/tls/TlsSigner.h"
#include "org/spongycastle/crypto/tls/TlsSignerCredentials.h"
#include "org/spongycastle/crypto/tls/TlsUtils.h"
#include "org/spongycastle/util/io/TeeInputStream.h"

@implementation OrgSpongycastleCryptoTlsTlsDHEKeyExchange

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
withOrgSpongycastleCryptoParamsDHParameters:(OrgSpongycastleCryptoParamsDHParameters *)dhParameters {
  OrgSpongycastleCryptoTlsTlsDHEKeyExchange_initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_(self, keyExchange, supportedSignatureAlgorithms, dhParameters);
  return self;
}

- (void)processServerCredentialsWithOrgSpongycastleCryptoTlsTlsCredentials:(id<OrgSpongycastleCryptoTlsTlsCredentials>)serverCredentials {
  if (!([OrgSpongycastleCryptoTlsTlsSignerCredentials_class_() isInstance:serverCredentials])) {
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_internal_error);
  }
  [self processServerCertificateWithOrgSpongycastleCryptoTlsCertificate:[((id<OrgSpongycastleCryptoTlsTlsCredentials>) nil_chk(serverCredentials)) getCertificate]];
  self->serverCredentials_ = (id<OrgSpongycastleCryptoTlsTlsSignerCredentials>) cast_check(serverCredentials, OrgSpongycastleCryptoTlsTlsSignerCredentials_class_());
}

- (IOSByteArray *)generateServerKeyExchange {
  if (self->dhParameters_ == nil) {
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_internal_error);
  }
  OrgSpongycastleCryptoTlsDigestInputBuffer *buf = new_OrgSpongycastleCryptoTlsDigestInputBuffer_init();
  self->dhAgreePrivateKey_ = OrgSpongycastleCryptoTlsTlsDHUtils_generateEphemeralServerKeyExchangeWithJavaSecuritySecureRandom_withOrgSpongycastleCryptoParamsDHParameters_withJavaIoOutputStream_([((id<OrgSpongycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom], self->dhParameters_, buf);
  OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *signatureAndHashAlgorithm = OrgSpongycastleCryptoTlsTlsUtils_getSignatureAndHashAlgorithmWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoTlsTlsSignerCredentials_(context_, serverCredentials_);
  id<OrgSpongycastleCryptoDigest> d = OrgSpongycastleCryptoTlsTlsUtils_createHashWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm_(signatureAndHashAlgorithm);
  OrgSpongycastleCryptoTlsSecurityParameters *securityParameters = [((id<OrgSpongycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters];
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(d)) updateWithByteArray:((OrgSpongycastleCryptoTlsSecurityParameters *) nil_chk(securityParameters))->clientRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->clientRandom_))->size_];
  [d updateWithByteArray:securityParameters->serverRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->serverRandom_))->size_];
  [buf updateDigestWithOrgSpongycastleCryptoDigest:d];
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[d getDigestSize]];
  [d doFinalWithByteArray:hash_ withInt:0];
  IOSByteArray *signature = [((id<OrgSpongycastleCryptoTlsTlsSignerCredentials>) nil_chk(serverCredentials_)) generateCertificateSignatureWithByteArray:hash_];
  OrgSpongycastleCryptoTlsDigitallySigned *signed_params = new_OrgSpongycastleCryptoTlsDigitallySigned_initWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(signatureAndHashAlgorithm, signature);
  [signed_params encodeWithJavaIoOutputStream:buf];
  return [buf toByteArray];
}

- (void)processServerKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  OrgSpongycastleCryptoTlsSecurityParameters *securityParameters = [((id<OrgSpongycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters];
  OrgSpongycastleCryptoTlsSignerInputBuffer *buf = new_OrgSpongycastleCryptoTlsSignerInputBuffer_init();
  JavaIoInputStream *teeIn = new_OrgSpongycastleUtilIoTeeInputStream_initWithJavaIoInputStream_withJavaIoOutputStream_(input, buf);
  OrgSpongycastleCryptoTlsServerDHParams *dhParams = OrgSpongycastleCryptoTlsServerDHParams_parseWithJavaIoInputStream_(teeIn);
  OrgSpongycastleCryptoTlsDigitallySigned *signed_params = [self parseSignatureWithJavaIoInputStream:input];
  id<OrgSpongycastleCryptoSigner> signer = [self initVerifyerWithOrgSpongycastleCryptoTlsTlsSigner:tlsSigner_ withOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:[((OrgSpongycastleCryptoTlsDigitallySigned *) nil_chk(signed_params)) getAlgorithm] withOrgSpongycastleCryptoTlsSecurityParameters:securityParameters];
  [buf updateSignerWithOrgSpongycastleCryptoSigner:signer];
  if (![((id<OrgSpongycastleCryptoSigner>) nil_chk(signer)) verifySignatureWithByteArray:[signed_params getSignature]]) {
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_decrypt_error);
  }
  self->dhAgreePublicKey_ = OrgSpongycastleCryptoTlsTlsDHUtils_validateDHPublicKeyWithOrgSpongycastleCryptoParamsDHPublicKeyParameters_([((OrgSpongycastleCryptoTlsServerDHParams *) nil_chk(dhParams)) getPublicKey]);
  self->dhParameters_ = [self validateDHParametersWithOrgSpongycastleCryptoParamsDHParameters:[((OrgSpongycastleCryptoParamsDHPublicKeyParameters *) nil_chk(dhAgreePublicKey_)) getParameters]];
}

- (id<OrgSpongycastleCryptoSigner>)initVerifyerWithOrgSpongycastleCryptoTlsTlsSigner:(id<OrgSpongycastleCryptoTlsTlsSigner>)tlsSigner
                               withOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                      withOrgSpongycastleCryptoTlsSecurityParameters:(OrgSpongycastleCryptoTlsSecurityParameters *)securityParameters {
  id<OrgSpongycastleCryptoSigner> signer = [((id<OrgSpongycastleCryptoTlsTlsSigner>) nil_chk(tlsSigner)) createVerifyerWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:algorithm withOrgSpongycastleCryptoParamsAsymmetricKeyParameter:self->serverPublicKey_];
  [((id<OrgSpongycastleCryptoSigner>) nil_chk(signer)) updateWithByteArray:((OrgSpongycastleCryptoTlsSecurityParameters *) nil_chk(securityParameters))->clientRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->clientRandom_))->size_];
  [signer updateWithByteArray:securityParameters->serverRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->serverRandom_))->size_];
  return signer;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 3, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoSigner;", 0x4, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withJavaUtilVector:withOrgSpongycastleCryptoParamsDHParameters:);
  methods[1].selector = @selector(processServerCredentialsWithOrgSpongycastleCryptoTlsTlsCredentials:);
  methods[2].selector = @selector(generateServerKeyExchange);
  methods[3].selector = @selector(processServerKeyExchangeWithJavaIoInputStream:);
  methods[4].selector = @selector(initVerifyerWithOrgSpongycastleCryptoTlsTlsSigner:withOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:withOrgSpongycastleCryptoTlsSecurityParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serverCredentials_", "LOrgSpongycastleCryptoTlsTlsSignerCredentials;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILJavaUtilVector;LOrgSpongycastleCryptoParamsDHParameters;", "processServerCredentials", "LOrgSpongycastleCryptoTlsTlsCredentials;", "LJavaIoIOException;", "processServerKeyExchange", "LJavaIoInputStream;", "initVerifyer", "LOrgSpongycastleCryptoTlsTlsSigner;LOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm;LOrgSpongycastleCryptoTlsSecurityParameters;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsTlsDHEKeyExchange = { "TlsDHEKeyExchange", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsTlsDHEKeyExchange;
}

@end

void OrgSpongycastleCryptoTlsTlsDHEKeyExchange_initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_(OrgSpongycastleCryptoTlsTlsDHEKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, OrgSpongycastleCryptoParamsDHParameters *dhParameters) {
  OrgSpongycastleCryptoTlsTlsDHKeyExchange_initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_(self, keyExchange, supportedSignatureAlgorithms, dhParameters);
  self->serverCredentials_ = nil;
}

OrgSpongycastleCryptoTlsTlsDHEKeyExchange *new_OrgSpongycastleCryptoTlsTlsDHEKeyExchange_initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, OrgSpongycastleCryptoParamsDHParameters *dhParameters) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsTlsDHEKeyExchange, initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_, keyExchange, supportedSignatureAlgorithms, dhParameters)
}

OrgSpongycastleCryptoTlsTlsDHEKeyExchange *create_OrgSpongycastleCryptoTlsTlsDHEKeyExchange_initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, OrgSpongycastleCryptoParamsDHParameters *dhParameters) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsTlsDHEKeyExchange, initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_, keyExchange, supportedSignatureAlgorithms, dhParameters)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsTlsDHEKeyExchange)
