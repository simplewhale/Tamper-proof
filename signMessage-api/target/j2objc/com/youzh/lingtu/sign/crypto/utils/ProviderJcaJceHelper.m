//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/ProviderJcaJceHelper.java
//

#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/ProviderJcaJceHelper.h"
#include "java/security/AlgorithmParameterGenerator.h"
#include "java/security/AlgorithmParameters.h"
#include "java/security/KeyFactory.h"
#include "java/security/KeyPairGenerator.h"
#include "java/security/MessageDigest.h"
#include "java/security/Provider.h"
#include "java/security/Signature.h"
#include "java/security/cert/CertificateFactory.h"
#include "javax/crypto/Cipher.h"
#include "javax/crypto/KeyAgreement.h"
#include "javax/crypto/KeyGenerator.h"
#include "javax/crypto/Mac.h"
#include "javax/crypto/SecretKeyFactory.h"

@implementation ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper

- (instancetype)initWithJavaSecurityProvider:(JavaSecurityProvider *)provider {
  ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper_initWithJavaSecurityProvider_(self, provider);
  return self;
}

- (JavaxCryptoCipher *)createCipherWithNSString:(NSString *)algorithm {
  return JavaxCryptoCipher_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaxCryptoMac *)createMacWithNSString:(NSString *)algorithm {
  return JavaxCryptoMac_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaxCryptoKeyAgreement *)createKeyAgreementWithNSString:(NSString *)algorithm {
  return JavaxCryptoKeyAgreement_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaSecurityAlgorithmParameterGenerator *)createAlgorithmParameterGeneratorWithNSString:(NSString *)algorithm {
  return JavaSecurityAlgorithmParameterGenerator_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaSecurityAlgorithmParameters *)createAlgorithmParametersWithNSString:(NSString *)algorithm {
  return JavaSecurityAlgorithmParameters_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaxCryptoKeyGenerator *)createKeyGeneratorWithNSString:(NSString *)algorithm {
  return JavaxCryptoKeyGenerator_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaSecurityKeyFactory *)createKeyFactoryWithNSString:(NSString *)algorithm {
  return JavaSecurityKeyFactory_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaxCryptoSecretKeyFactory *)createSecretKeyFactoryWithNSString:(NSString *)algorithm {
  return JavaxCryptoSecretKeyFactory_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaSecurityKeyPairGenerator *)createKeyPairGeneratorWithNSString:(NSString *)algorithm {
  return JavaSecurityKeyPairGenerator_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaSecurityMessageDigest *)createDigestWithNSString:(NSString *)algorithm {
  return JavaSecurityMessageDigest_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaSecuritySignature *)createSignatureWithNSString:(NSString *)algorithm {
  return JavaSecuritySignature_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

- (JavaSecurityCertCertificateFactory *)createCertificateFactoryWithNSString:(NSString *)algorithm {
  return JavaSecurityCertCertificateFactory_getInstanceWithNSString_withJavaSecurityProvider_(algorithm, provider_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaxCryptoCipher;", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LJavaxCryptoMac;", 0x1, 4, 2, 5, -1, -1, -1 },
    { NULL, "LJavaxCryptoKeyAgreement;", 0x1, 6, 2, 5, -1, -1, -1 },
    { NULL, "LJavaSecurityAlgorithmParameterGenerator;", 0x1, 7, 2, 5, -1, -1, -1 },
    { NULL, "LJavaSecurityAlgorithmParameters;", 0x1, 8, 2, 5, -1, -1, -1 },
    { NULL, "LJavaxCryptoKeyGenerator;", 0x1, 9, 2, 5, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyFactory;", 0x1, 10, 2, 5, -1, -1, -1 },
    { NULL, "LJavaxCryptoSecretKeyFactory;", 0x1, 11, 2, 5, -1, -1, -1 },
    { NULL, "LJavaSecurityKeyPairGenerator;", 0x1, 12, 2, 5, -1, -1, -1 },
    { NULL, "LJavaSecurityMessageDigest;", 0x1, 13, 2, 5, -1, -1, -1 },
    { NULL, "LJavaSecuritySignature;", 0x1, 14, 2, 5, -1, -1, -1 },
    { NULL, "LJavaSecurityCertCertificateFactory;", 0x1, 15, 2, 16, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecurityProvider:);
  methods[1].selector = @selector(createCipherWithNSString:);
  methods[2].selector = @selector(createMacWithNSString:);
  methods[3].selector = @selector(createKeyAgreementWithNSString:);
  methods[4].selector = @selector(createAlgorithmParameterGeneratorWithNSString:);
  methods[5].selector = @selector(createAlgorithmParametersWithNSString:);
  methods[6].selector = @selector(createKeyGeneratorWithNSString:);
  methods[7].selector = @selector(createKeyFactoryWithNSString:);
  methods[8].selector = @selector(createSecretKeyFactoryWithNSString:);
  methods[9].selector = @selector(createKeyPairGeneratorWithNSString:);
  methods[10].selector = @selector(createDigestWithNSString:);
  methods[11].selector = @selector(createSignatureWithNSString:);
  methods[12].selector = @selector(createCertificateFactoryWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "provider_", "LJavaSecurityProvider;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecurityProvider;", "createCipher", "LNSString;", "LJavaSecurityNoSuchAlgorithmException;LJavaxCryptoNoSuchPaddingException;", "createMac", "LJavaSecurityNoSuchAlgorithmException;", "createKeyAgreement", "createAlgorithmParameterGenerator", "createAlgorithmParameters", "createKeyGenerator", "createKeyFactory", "createSecretKeyFactory", "createKeyPairGenerator", "createDigest", "createSignature", "createCertificateFactory", "LJavaSecurityCertCertificateException;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper = { "ProviderJcaJceHelper", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 13, 1, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper;
}

@end

void ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper_initWithJavaSecurityProvider_(ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper *self, JavaSecurityProvider *provider) {
  NSObject_init(self);
  self->provider_ = provider;
}

ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper *new_ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper_initWithJavaSecurityProvider_(JavaSecurityProvider *provider) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper, initWithJavaSecurityProvider_, provider)
}

ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper *create_ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper_initWithJavaSecurityProvider_(JavaSecurityProvider *provider) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper, initWithJavaSecurityProvider_, provider)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsProviderJcaJceHelper)
