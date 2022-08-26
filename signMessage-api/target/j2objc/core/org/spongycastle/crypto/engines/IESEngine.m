//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/IESEngine.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/AsymmetricCipherKeyPair.h"
#include "org/spongycastle/crypto/BasicAgreement.h"
#include "org/spongycastle/crypto/BufferedBlockCipher.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/DerivationFunction.h"
#include "org/spongycastle/crypto/EphemeralKeyPair.h"
#include "org/spongycastle/crypto/InvalidCipherTextException.h"
#include "org/spongycastle/crypto/KeyParser.h"
#include "org/spongycastle/crypto/Mac.h"
#include "org/spongycastle/crypto/engines/IESEngine.h"
#include "org/spongycastle/crypto/generators/EphemeralKeyPairGenerator.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/params/IESParameters.h"
#include "org/spongycastle/crypto/params/IESWithCipherParameters.h"
#include "org/spongycastle/crypto/params/KDFParameters.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"
#include "org/spongycastle/crypto/params/ParametersWithIV.h"
#include "org/spongycastle/util/Arrays.h"
#include "org/spongycastle/util/BigIntegers.h"
#include "org/spongycastle/util/Pack.h"

@interface OrgSpongycastleCryptoEnginesIESEngine () {
 @public
  OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator *keyPairGenerator_;
  id<OrgSpongycastleCryptoKeyParser> keyParser_;
  IOSByteArray *IV_;
}

- (void)extractParamsWithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params;

- (IOSByteArray *)encryptBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen;

- (IOSByteArray *)decryptBlockWithByteArray:(IOSByteArray *)in_enc
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesIESEngine, keyPairGenerator_, OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesIESEngine, keyParser_, id<OrgSpongycastleCryptoKeyParser>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesIESEngine, IV_, IOSByteArray *)

__attribute__((unused)) static void OrgSpongycastleCryptoEnginesIESEngine_extractParamsWithOrgSpongycastleCryptoCipherParameters_(OrgSpongycastleCryptoEnginesIESEngine *self, id<OrgSpongycastleCryptoCipherParameters> params);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEnginesIESEngine_encryptBlockWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEnginesIESEngine *self, IOSByteArray *inArg, jint inOff, jint inLen);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEnginesIESEngine_decryptBlockWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEnginesIESEngine *self, IOSByteArray *in_enc, jint inOff, jint inLen);

@implementation OrgSpongycastleCryptoEnginesIESEngine

- (instancetype)initWithOrgSpongycastleCryptoBasicAgreement:(id<OrgSpongycastleCryptoBasicAgreement>)agree
                withOrgSpongycastleCryptoDerivationFunction:(id<OrgSpongycastleCryptoDerivationFunction>)kdf
                               withOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)mac {
  OrgSpongycastleCryptoEnginesIESEngine_initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_(self, agree, kdf, mac);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoBasicAgreement:(id<OrgSpongycastleCryptoBasicAgreement>)agree
                withOrgSpongycastleCryptoDerivationFunction:(id<OrgSpongycastleCryptoDerivationFunction>)kdf
                               withOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)mac
               withOrgSpongycastleCryptoBufferedBlockCipher:(OrgSpongycastleCryptoBufferedBlockCipher *)cipher {
  OrgSpongycastleCryptoEnginesIESEngine_initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_withOrgSpongycastleCryptoBufferedBlockCipher_(self, agree, kdf, mac, cipher);
  return self;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)privParam
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)pubParam
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  self->forEncryption_ = forEncryption;
  self->privParam_ = privParam;
  self->pubParam_ = pubParam;
  self->V_ = [IOSByteArray newArrayWithLength:0];
  OrgSpongycastleCryptoEnginesIESEngine_extractParamsWithOrgSpongycastleCryptoCipherParameters_(self, params);
}

- (void)init__WithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)publicKey
                          withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params
       withOrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator:(OrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator *)ephemeralKeyPairGenerator {
  self->forEncryption_ = true;
  self->pubParam_ = publicKey;
  self->keyPairGenerator_ = ephemeralKeyPairGenerator;
  OrgSpongycastleCryptoEnginesIESEngine_extractParamsWithOrgSpongycastleCryptoCipherParameters_(self, params);
}

- (void)init__WithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:(OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)privateKey
                          withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params
                                 withOrgSpongycastleCryptoKeyParser:(id<OrgSpongycastleCryptoKeyParser>)publicKeyParser {
  self->forEncryption_ = false;
  self->privParam_ = privateKey;
  self->keyParser_ = publicKeyParser;
  OrgSpongycastleCryptoEnginesIESEngine_extractParamsWithOrgSpongycastleCryptoCipherParameters_(self, params);
}

- (void)extractParamsWithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  OrgSpongycastleCryptoEnginesIESEngine_extractParamsWithOrgSpongycastleCryptoCipherParameters_(self, params);
}

- (OrgSpongycastleCryptoBufferedBlockCipher *)getCipher {
  return cipher_;
}

- (id<OrgSpongycastleCryptoMac>)getMac {
  return mac_;
}

- (IOSByteArray *)encryptBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen {
  return OrgSpongycastleCryptoEnginesIESEngine_encryptBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
}

- (IOSByteArray *)decryptBlockWithByteArray:(IOSByteArray *)in_enc
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen {
  return OrgSpongycastleCryptoEnginesIESEngine_decryptBlockWithByteArray_withInt_withInt_(self, in_enc, inOff, inLen);
}

- (IOSByteArray *)processBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen {
  if (forEncryption_) {
    if (keyPairGenerator_ != nil) {
      OrgSpongycastleCryptoEphemeralKeyPair *ephKeyPair = [keyPairGenerator_ generate];
      self->privParam_ = [((OrgSpongycastleCryptoAsymmetricCipherKeyPair *) nil_chk([((OrgSpongycastleCryptoEphemeralKeyPair *) nil_chk(ephKeyPair)) getKeyPair])) getPrivate];
      self->V_ = [ephKeyPair getEncodedPublicKey];
    }
  }
  else {
    if (keyParser_ != nil) {
      JavaIoByteArrayInputStream *bIn = new_JavaIoByteArrayInputStream_initWithByteArray_withInt_withInt_(inArg, inOff, inLen);
      @try {
        self->pubParam_ = [((id<OrgSpongycastleCryptoKeyParser>) nil_chk(keyParser_)) readKeyWithJavaIoInputStream:bIn];
      }
      @catch (JavaIoIOException *e) {
        @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"unable to recover ephemeral public key: ", [e getMessage]), e);
      }
      @catch (JavaLangIllegalArgumentException *e) {
        @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"unable to recover ephemeral public key: ", [e getMessage]), e);
      }
      jint encLength = (inLen - [bIn available]);
      self->V_ = OrgSpongycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(inArg, inOff, inOff + encLength);
    }
  }
  [((id<OrgSpongycastleCryptoBasicAgreement>) nil_chk(agree_)) init__WithOrgSpongycastleCryptoCipherParameters:privParam_];
  JavaMathBigInteger *z = [((id<OrgSpongycastleCryptoBasicAgreement>) nil_chk(agree_)) calculateAgreementWithOrgSpongycastleCryptoCipherParameters:pubParam_];
  IOSByteArray *Z = OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_([((id<OrgSpongycastleCryptoBasicAgreement>) nil_chk(agree_)) getFieldSize], z);
  if (((IOSByteArray *) nil_chk(V_))->size_ != 0) {
    IOSByteArray *VZ = OrgSpongycastleUtilArrays_concatenateWithByteArray_withByteArray_(V_, Z);
    OrgSpongycastleUtilArrays_fillWithByteArray_withByte_(Z, (jbyte) 0);
    Z = VZ;
  }
  @try {
    OrgSpongycastleCryptoParamsKDFParameters *kdfParam = new_OrgSpongycastleCryptoParamsKDFParameters_initWithByteArray_withByteArray_(Z, [((OrgSpongycastleCryptoParamsIESParameters *) nil_chk(param_)) getDerivationV]);
    [((id<OrgSpongycastleCryptoDerivationFunction>) nil_chk(kdf_)) init__WithOrgSpongycastleCryptoDerivationParameters:kdfParam];
    return forEncryption_ ? OrgSpongycastleCryptoEnginesIESEngine_encryptBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen) : OrgSpongycastleCryptoEnginesIESEngine_decryptBlockWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
  }
  @finally {
    OrgSpongycastleUtilArrays_fillWithByteArray_withByte_(Z, (jbyte) 0);
  }
}

- (IOSByteArray *)getLengthTagWithByteArray:(IOSByteArray *)p2 {
  IOSByteArray *L2 = [IOSByteArray newArrayWithLength:8];
  if (p2 != nil) {
    OrgSpongycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(p2->size_ * 8LL, L2, 0);
  }
  return L2;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoBufferedBlockCipher;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoMac;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 8, 9, 10, -1, -1, -1 },
    { NULL, "[B", 0x2, 11, 9, 10, -1, -1, -1 },
    { NULL, "[B", 0x1, 12, 9, 10, -1, -1, -1 },
    { NULL, "[B", 0x4, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoBasicAgreement:withOrgSpongycastleCryptoDerivationFunction:withOrgSpongycastleCryptoMac:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoBasicAgreement:withOrgSpongycastleCryptoDerivationFunction:withOrgSpongycastleCryptoMac:withOrgSpongycastleCryptoBufferedBlockCipher:);
  methods[2].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:withOrgSpongycastleCryptoCipherParameters:withOrgSpongycastleCryptoCipherParameters:);
  methods[3].selector = @selector(init__WithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:withOrgSpongycastleCryptoCipherParameters:withOrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator:);
  methods[4].selector = @selector(init__WithOrgSpongycastleCryptoParamsAsymmetricKeyParameter:withOrgSpongycastleCryptoCipherParameters:withOrgSpongycastleCryptoKeyParser:);
  methods[5].selector = @selector(extractParamsWithOrgSpongycastleCryptoCipherParameters:);
  methods[6].selector = @selector(getCipher);
  methods[7].selector = @selector(getMac);
  methods[8].selector = @selector(encryptBlockWithByteArray:withInt:withInt:);
  methods[9].selector = @selector(decryptBlockWithByteArray:withInt:withInt:);
  methods[10].selector = @selector(processBlockWithByteArray:withInt:withInt:);
  methods[11].selector = @selector(getLengthTagWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "agree_", "LOrgSpongycastleCryptoBasicAgreement;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "kdf_", "LOrgSpongycastleCryptoDerivationFunction;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "mac_", "LOrgSpongycastleCryptoMac;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "cipher_", "LOrgSpongycastleCryptoBufferedBlockCipher;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "macBuf_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "privParam_", "LOrgSpongycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "pubParam_", "LOrgSpongycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "param_", "LOrgSpongycastleCryptoParamsIESParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "V_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "keyPairGenerator_", "LOrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyParser_", "LOrgSpongycastleCryptoKeyParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "IV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoBasicAgreement;LOrgSpongycastleCryptoDerivationFunction;LOrgSpongycastleCryptoMac;", "LOrgSpongycastleCryptoBasicAgreement;LOrgSpongycastleCryptoDerivationFunction;LOrgSpongycastleCryptoMac;LOrgSpongycastleCryptoBufferedBlockCipher;", "init", "ZLOrgSpongycastleCryptoCipherParameters;LOrgSpongycastleCryptoCipherParameters;LOrgSpongycastleCryptoCipherParameters;", "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;LOrgSpongycastleCryptoCipherParameters;LOrgSpongycastleCryptoGeneratorsEphemeralKeyPairGenerator;", "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;LOrgSpongycastleCryptoCipherParameters;LOrgSpongycastleCryptoKeyParser;", "extractParams", "LOrgSpongycastleCryptoCipherParameters;", "encryptBlock", "[BII", "LOrgSpongycastleCryptoInvalidCipherTextException;", "decryptBlock", "processBlock", "getLengthTag", "[B" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEnginesIESEngine = { "IESEngine", "org.spongycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 12, 13, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoEnginesIESEngine;
}

@end

void OrgSpongycastleCryptoEnginesIESEngine_initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_(OrgSpongycastleCryptoEnginesIESEngine *self, id<OrgSpongycastleCryptoBasicAgreement> agree, id<OrgSpongycastleCryptoDerivationFunction> kdf, id<OrgSpongycastleCryptoMac> mac) {
  NSObject_init(self);
  self->agree_ = agree;
  self->kdf_ = kdf;
  self->mac_ = mac;
  self->macBuf_ = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoMac>) nil_chk(mac)) getMacSize]];
  self->cipher_ = nil;
}

OrgSpongycastleCryptoEnginesIESEngine *new_OrgSpongycastleCryptoEnginesIESEngine_initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_(id<OrgSpongycastleCryptoBasicAgreement> agree, id<OrgSpongycastleCryptoDerivationFunction> kdf, id<OrgSpongycastleCryptoMac> mac) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEnginesIESEngine, initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_, agree, kdf, mac)
}

OrgSpongycastleCryptoEnginesIESEngine *create_OrgSpongycastleCryptoEnginesIESEngine_initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_(id<OrgSpongycastleCryptoBasicAgreement> agree, id<OrgSpongycastleCryptoDerivationFunction> kdf, id<OrgSpongycastleCryptoMac> mac) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEnginesIESEngine, initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_, agree, kdf, mac)
}

void OrgSpongycastleCryptoEnginesIESEngine_initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_withOrgSpongycastleCryptoBufferedBlockCipher_(OrgSpongycastleCryptoEnginesIESEngine *self, id<OrgSpongycastleCryptoBasicAgreement> agree, id<OrgSpongycastleCryptoDerivationFunction> kdf, id<OrgSpongycastleCryptoMac> mac, OrgSpongycastleCryptoBufferedBlockCipher *cipher) {
  NSObject_init(self);
  self->agree_ = agree;
  self->kdf_ = kdf;
  self->mac_ = mac;
  self->macBuf_ = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoMac>) nil_chk(mac)) getMacSize]];
  self->cipher_ = cipher;
}

OrgSpongycastleCryptoEnginesIESEngine *new_OrgSpongycastleCryptoEnginesIESEngine_initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_withOrgSpongycastleCryptoBufferedBlockCipher_(id<OrgSpongycastleCryptoBasicAgreement> agree, id<OrgSpongycastleCryptoDerivationFunction> kdf, id<OrgSpongycastleCryptoMac> mac, OrgSpongycastleCryptoBufferedBlockCipher *cipher) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEnginesIESEngine, initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_withOrgSpongycastleCryptoBufferedBlockCipher_, agree, kdf, mac, cipher)
}

OrgSpongycastleCryptoEnginesIESEngine *create_OrgSpongycastleCryptoEnginesIESEngine_initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_withOrgSpongycastleCryptoBufferedBlockCipher_(id<OrgSpongycastleCryptoBasicAgreement> agree, id<OrgSpongycastleCryptoDerivationFunction> kdf, id<OrgSpongycastleCryptoMac> mac, OrgSpongycastleCryptoBufferedBlockCipher *cipher) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEnginesIESEngine, initWithOrgSpongycastleCryptoBasicAgreement_withOrgSpongycastleCryptoDerivationFunction_withOrgSpongycastleCryptoMac_withOrgSpongycastleCryptoBufferedBlockCipher_, agree, kdf, mac, cipher)
}

void OrgSpongycastleCryptoEnginesIESEngine_extractParamsWithOrgSpongycastleCryptoCipherParameters_(OrgSpongycastleCryptoEnginesIESEngine *self, id<OrgSpongycastleCryptoCipherParameters> params) {
  if ([params isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithIV class]]) {
    self->IV_ = [((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(((OrgSpongycastleCryptoParamsParametersWithIV *) params))) getIV];
    self->param_ = (OrgSpongycastleCryptoParamsIESParameters *) cast_chk([((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(((OrgSpongycastleCryptoParamsParametersWithIV *) params))) getParameters], [OrgSpongycastleCryptoParamsIESParameters class]);
  }
  else {
    self->IV_ = nil;
    self->param_ = (OrgSpongycastleCryptoParamsIESParameters *) cast_chk(params, [OrgSpongycastleCryptoParamsIESParameters class]);
  }
}

IOSByteArray *OrgSpongycastleCryptoEnginesIESEngine_encryptBlockWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEnginesIESEngine *self, IOSByteArray *inArg, jint inOff, jint inLen) {
  IOSByteArray *C = nil;
  IOSByteArray *K = nil;
  IOSByteArray *K1 = nil;
  IOSByteArray *K2 = nil;
  jint len;
  if (self->cipher_ == nil) {
    K1 = [IOSByteArray newArrayWithLength:inLen];
    K2 = [IOSByteArray newArrayWithLength:[((OrgSpongycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getMacKeySize] / 8];
    K = [IOSByteArray newArrayWithLength:K1->size_ + K2->size_];
    [((id<OrgSpongycastleCryptoDerivationFunction>) nil_chk(self->kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
    if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K2, 0, K2->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K2->size_, K1, 0, K1->size_);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K1, 0, K1->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, inLen, K2, 0, K2->size_);
    }
    C = [IOSByteArray newArrayWithLength:inLen];
    for (jint i = 0; i != inLen; i++) {
      *IOSByteArray_GetRef(C, i) = (jbyte) (IOSByteArray_Get(nil_chk(inArg), inOff + i) ^ IOSByteArray_Get(K1, i));
    }
    len = inLen;
  }
  else {
    K1 = [IOSByteArray newArrayWithLength:[((OrgSpongycastleCryptoParamsIESWithCipherParameters *) nil_chk(((OrgSpongycastleCryptoParamsIESWithCipherParameters *) cast_chk(self->param_, [OrgSpongycastleCryptoParamsIESWithCipherParameters class])))) getCipherKeySize] / 8];
    K2 = [IOSByteArray newArrayWithLength:[((OrgSpongycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getMacKeySize] / 8];
    K = [IOSByteArray newArrayWithLength:K1->size_ + K2->size_];
    [((id<OrgSpongycastleCryptoDerivationFunction>) nil_chk(self->kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K1, 0, K1->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K1->size_, K2, 0, K2->size_);
    if (self->IV_ != nil) {
      [((OrgSpongycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(new_OrgSpongycastleCryptoParamsKeyParameter_initWithByteArray_(K1), self->IV_)];
    }
    else {
      [((OrgSpongycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:new_OrgSpongycastleCryptoParamsKeyParameter_initWithByteArray_(K1)];
    }
    C = [IOSByteArray newArrayWithLength:[((OrgSpongycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) getOutputSizeWithInt:inLen]];
    len = [((OrgSpongycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) processBytesWithByteArray:inArg withInt:inOff withInt:inLen withByteArray:C withInt:0];
    len += [((OrgSpongycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) doFinalWithByteArray:C withInt:len];
  }
  IOSByteArray *P2 = [((OrgSpongycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getEncodingV];
  IOSByteArray *L2 = nil;
  if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
    L2 = [self getLengthTagWithByteArray:P2];
  }
  IOSByteArray *T = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) getMacSize]];
  [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) init__WithOrgSpongycastleCryptoCipherParameters:new_OrgSpongycastleCryptoParamsKeyParameter_initWithByteArray_(K2)];
  [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:C withInt:0 withInt:C->size_];
  if (P2 != nil) {
    [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:P2 withInt:0 withInt:P2->size_];
  }
  if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
    [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:L2 withInt:0 withInt:((IOSByteArray *) nil_chk(L2))->size_];
  }
  [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) doFinalWithByteArray:T withInt:0];
  IOSByteArray *Output = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(self->V_))->size_ + len + T->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->V_, 0, Output, 0, self->V_->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(C, 0, Output, ((IOSByteArray *) nil_chk(self->V_))->size_, len);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(T, 0, Output, ((IOSByteArray *) nil_chk(self->V_))->size_ + len, T->size_);
  return Output;
}

IOSByteArray *OrgSpongycastleCryptoEnginesIESEngine_decryptBlockWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEnginesIESEngine *self, IOSByteArray *in_enc, jint inOff, jint inLen) {
  IOSByteArray *M;
  IOSByteArray *K;
  IOSByteArray *K1;
  IOSByteArray *K2;
  jint len = 0;
  if (inLen < ((IOSByteArray *) nil_chk(self->V_))->size_ + [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) getMacSize]) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"Length of input must be greater than the MAC and V combined");
  }
  if (self->cipher_ == nil) {
    K1 = [IOSByteArray newArrayWithLength:inLen - ((IOSByteArray *) nil_chk(self->V_))->size_ - [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) getMacSize]];
    K2 = [IOSByteArray newArrayWithLength:[((OrgSpongycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getMacKeySize] / 8];
    K = [IOSByteArray newArrayWithLength:K1->size_ + K2->size_];
    [((id<OrgSpongycastleCryptoDerivationFunction>) nil_chk(self->kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
    if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K2, 0, K2->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K2->size_, K1, 0, K1->size_);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K1, 0, K1->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K1->size_, K2, 0, K2->size_);
    }
    M = [IOSByteArray newArrayWithLength:K1->size_];
    for (jint i = 0; i != K1->size_; i++) {
      *IOSByteArray_GetRef(M, i) = (jbyte) (IOSByteArray_Get(nil_chk(in_enc), inOff + ((IOSByteArray *) nil_chk(self->V_))->size_ + i) ^ IOSByteArray_Get(K1, i));
    }
  }
  else {
    K1 = [IOSByteArray newArrayWithLength:[((OrgSpongycastleCryptoParamsIESWithCipherParameters *) nil_chk(((OrgSpongycastleCryptoParamsIESWithCipherParameters *) cast_chk(self->param_, [OrgSpongycastleCryptoParamsIESWithCipherParameters class])))) getCipherKeySize] / 8];
    K2 = [IOSByteArray newArrayWithLength:[((OrgSpongycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getMacKeySize] / 8];
    K = [IOSByteArray newArrayWithLength:K1->size_ + K2->size_];
    [((id<OrgSpongycastleCryptoDerivationFunction>) nil_chk(self->kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, 0, K1, 0, K1->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(K, K1->size_, K2, 0, K2->size_);
    id<OrgSpongycastleCryptoCipherParameters> cp = new_OrgSpongycastleCryptoParamsKeyParameter_initWithByteArray_(K1);
    if (self->IV_ != nil) {
      cp = new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(cp, self->IV_);
    }
    [((OrgSpongycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) init__WithBoolean:false withOrgSpongycastleCryptoCipherParameters:cp];
    M = [IOSByteArray newArrayWithLength:[((OrgSpongycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) getOutputSizeWithInt:inLen - ((IOSByteArray *) nil_chk(self->V_))->size_ - [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) getMacSize]]];
    len = [((OrgSpongycastleCryptoBufferedBlockCipher *) nil_chk(self->cipher_)) processBytesWithByteArray:in_enc withInt:inOff + ((IOSByteArray *) nil_chk(self->V_))->size_ withInt:inLen - self->V_->size_ - [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) getMacSize] withByteArray:M withInt:0];
  }
  IOSByteArray *P2 = [((OrgSpongycastleCryptoParamsIESParameters *) nil_chk(self->param_)) getEncodingV];
  IOSByteArray *L2 = nil;
  if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
    L2 = [self getLengthTagWithByteArray:P2];
  }
  jint end = inOff + inLen;
  IOSByteArray *T1 = OrgSpongycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(in_enc, end - [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) getMacSize], end);
  IOSByteArray *T2 = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(T1))->size_];
  [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) init__WithOrgSpongycastleCryptoCipherParameters:new_OrgSpongycastleCryptoParamsKeyParameter_initWithByteArray_(K2)];
  [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:in_enc withInt:inOff + ((IOSByteArray *) nil_chk(self->V_))->size_ withInt:inLen - self->V_->size_ - T2->size_];
  if (P2 != nil) {
    [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:P2 withInt:0 withInt:P2->size_];
  }
  if (((IOSByteArray *) nil_chk(self->V_))->size_ != 0) {
    [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) updateWithByteArray:L2 withInt:0 withInt:((IOSByteArray *) nil_chk(L2))->size_];
  }
  [((id<OrgSpongycastleCryptoMac>) nil_chk(self->mac_)) doFinalWithByteArray:T2 withInt:0];
  if (!OrgSpongycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(T1, T2)) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"invalid MAC");
  }
  if (self->cipher_ == nil) {
    return M;
  }
  else {
    len += [self->cipher_ doFinalWithByteArray:M withInt:len];
    return OrgSpongycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(M, 0, len);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoEnginesIESEngine)