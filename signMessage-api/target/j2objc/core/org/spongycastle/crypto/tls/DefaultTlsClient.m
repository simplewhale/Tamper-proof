//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/DefaultTlsClient.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/util/Vector.h"
#include "org/spongycastle/crypto/tls/AbstractTlsClient.h"
#include "org/spongycastle/crypto/tls/AlertDescription.h"
#include "org/spongycastle/crypto/tls/CipherSuite.h"
#include "org/spongycastle/crypto/tls/DefaultTlsClient.h"
#include "org/spongycastle/crypto/tls/KeyExchangeAlgorithm.h"
#include "org/spongycastle/crypto/tls/TlsCipherFactory.h"
#include "org/spongycastle/crypto/tls/TlsDHEKeyExchange.h"
#include "org/spongycastle/crypto/tls/TlsDHKeyExchange.h"
#include "org/spongycastle/crypto/tls/TlsECDHEKeyExchange.h"
#include "org/spongycastle/crypto/tls/TlsECDHKeyExchange.h"
#include "org/spongycastle/crypto/tls/TlsFatalAlert.h"
#include "org/spongycastle/crypto/tls/TlsKeyExchange.h"
#include "org/spongycastle/crypto/tls/TlsRSAKeyExchange.h"
#include "org/spongycastle/crypto/tls/TlsUtils.h"

@implementation OrgSpongycastleCryptoTlsDefaultTlsClient

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsDefaultTlsClient_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithOrgSpongycastleCryptoTlsTlsCipherFactory:(id<OrgSpongycastleCryptoTlsTlsCipherFactory>)cipherFactory {
  OrgSpongycastleCryptoTlsDefaultTlsClient_initWithOrgSpongycastleCryptoTlsTlsCipherFactory_(self, cipherFactory);
  return self;
}

- (IOSIntArray *)getCipherSuites {
  return [IOSIntArray newArrayWithInts:(jint[]){ OrgSpongycastleCryptoTlsCipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, OrgSpongycastleCryptoTlsCipherSuite_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, OrgSpongycastleCryptoTlsCipherSuite_TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_DHE_DSS_WITH_AES_128_CBC_SHA, OrgSpongycastleCryptoTlsCipherSuite_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_DHE_RSA_WITH_AES_128_CBC_SHA, OrgSpongycastleCryptoTlsCipherSuite_TLS_RSA_WITH_AES_128_GCM_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_RSA_WITH_AES_128_CBC_SHA256, OrgSpongycastleCryptoTlsCipherSuite_TLS_RSA_WITH_AES_128_CBC_SHA } count:15];
}

- (id<OrgSpongycastleCryptoTlsTlsKeyExchange>)getKeyExchange {
  jint keyExchangeAlgorithm = OrgSpongycastleCryptoTlsTlsUtils_getKeyExchangeAlgorithmWithInt_(selectedCipherSuite_);
  switch (keyExchangeAlgorithm) {
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_DH_anon:
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_DH_DSS:
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_DH_RSA:
    return [self createDHKeyExchangeWithInt:keyExchangeAlgorithm];
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_DHE_DSS:
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_DHE_RSA:
    return [self createDHEKeyExchangeWithInt:keyExchangeAlgorithm];
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_ECDH_anon:
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_ECDH_ECDSA:
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_ECDH_RSA:
    return [self createECDHKeyExchangeWithInt:keyExchangeAlgorithm];
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_ECDSA:
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_RSA:
    return [self createECDHEKeyExchangeWithInt:keyExchangeAlgorithm];
    case OrgSpongycastleCryptoTlsKeyExchangeAlgorithm_RSA:
    return [self createRSAKeyExchange];
    default:
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (id<OrgSpongycastleCryptoTlsTlsKeyExchange>)createDHKeyExchangeWithInt:(jint)keyExchange {
  return new_OrgSpongycastleCryptoTlsTlsDHKeyExchange_initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_(keyExchange, supportedSignatureAlgorithms_, nil);
}

- (id<OrgSpongycastleCryptoTlsTlsKeyExchange>)createDHEKeyExchangeWithInt:(jint)keyExchange {
  return new_OrgSpongycastleCryptoTlsTlsDHEKeyExchange_initWithInt_withJavaUtilVector_withOrgSpongycastleCryptoParamsDHParameters_(keyExchange, supportedSignatureAlgorithms_, nil);
}

- (id<OrgSpongycastleCryptoTlsTlsKeyExchange>)createECDHKeyExchangeWithInt:(jint)keyExchange {
  return new_OrgSpongycastleCryptoTlsTlsECDHKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(keyExchange, supportedSignatureAlgorithms_, namedCurves_, clientECPointFormats_, serverECPointFormats_);
}

- (id<OrgSpongycastleCryptoTlsTlsKeyExchange>)createECDHEKeyExchangeWithInt:(jint)keyExchange {
  return new_OrgSpongycastleCryptoTlsTlsECDHEKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(keyExchange, supportedSignatureAlgorithms_, namedCurves_, clientECPointFormats_, serverECPointFormats_);
}

- (id<OrgSpongycastleCryptoTlsTlsKeyExchange>)createRSAKeyExchange {
  return new_OrgSpongycastleCryptoTlsTlsRSAKeyExchange_initWithJavaUtilVector_(supportedSignatureAlgorithms_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsTlsKeyExchange;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsTlsKeyExchange;", 0x4, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsTlsKeyExchange;", 0x4, 4, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsTlsKeyExchange;", 0x4, 5, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsTlsKeyExchange;", 0x4, 6, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsTlsKeyExchange;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoTlsTlsCipherFactory:);
  methods[2].selector = @selector(getCipherSuites);
  methods[3].selector = @selector(getKeyExchange);
  methods[4].selector = @selector(createDHKeyExchangeWithInt:);
  methods[5].selector = @selector(createDHEKeyExchangeWithInt:);
  methods[6].selector = @selector(createECDHKeyExchangeWithInt:);
  methods[7].selector = @selector(createECDHEKeyExchangeWithInt:);
  methods[8].selector = @selector(createRSAKeyExchange);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoTlsTlsCipherFactory;", "LJavaIoIOException;", "createDHKeyExchange", "I", "createDHEKeyExchange", "createECDHKeyExchange", "createECDHEKeyExchange" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsDefaultTlsClient = { "DefaultTlsClient", "org.spongycastle.crypto.tls", ptrTable, methods, NULL, 7, 0x401, 9, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsDefaultTlsClient;
}

@end

void OrgSpongycastleCryptoTlsDefaultTlsClient_init(OrgSpongycastleCryptoTlsDefaultTlsClient *self) {
  OrgSpongycastleCryptoTlsAbstractTlsClient_init(self);
}

void OrgSpongycastleCryptoTlsDefaultTlsClient_initWithOrgSpongycastleCryptoTlsTlsCipherFactory_(OrgSpongycastleCryptoTlsDefaultTlsClient *self, id<OrgSpongycastleCryptoTlsTlsCipherFactory> cipherFactory) {
  OrgSpongycastleCryptoTlsAbstractTlsClient_initWithOrgSpongycastleCryptoTlsTlsCipherFactory_(self, cipherFactory);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsDefaultTlsClient)
