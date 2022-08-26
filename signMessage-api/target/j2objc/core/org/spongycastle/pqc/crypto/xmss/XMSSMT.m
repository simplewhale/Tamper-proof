//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSMT.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/NullPointerException.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/AsymmetricCipherKeyPair.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/pqc/crypto/xmss/WOTSPlus.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSMT.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSMTKeyGenerationParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSMTKeyPairGenerator.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSMTParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSMTPrivateKeyParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSMTPublicKeyParameters.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSMTSigner.h"
#include "org/spongycastle/pqc/crypto/xmss/XMSSParameters.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastlePqcCryptoXmssXMSSMT () {
 @public
  OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params_;
  OrgSpongycastlePqcCryptoXmssXMSSParameters *xmssParams_;
  JavaSecuritySecureRandom *prng_;
  OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *privateKey_;
  OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *publicKey_;
}

- (void)importStateWithOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *)privateKey
                    withOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *)publicKey;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSMT, params_, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSMT, xmssParams_, OrgSpongycastlePqcCryptoXmssXMSSParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSMT, prng_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSMT, privateKey_, OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoXmssXMSSMT, publicKey_, OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoXmssXMSSMT_importStateWithOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_withOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_(OrgSpongycastlePqcCryptoXmssXMSSMT *self, OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *privateKey, OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *publicKey);

@implementation OrgSpongycastlePqcCryptoXmssXMSSMT

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)params
                                        withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)prng {
  OrgSpongycastlePqcCryptoXmssXMSSMT_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_(self, params, prng);
  return self;
}

- (void)generateKeys {
  OrgSpongycastlePqcCryptoXmssXMSSMTKeyPairGenerator *kpGen = new_OrgSpongycastlePqcCryptoXmssXMSSMTKeyPairGenerator_init();
  [kpGen init__WithOrgSpongycastleCryptoKeyGenerationParameters:new_OrgSpongycastlePqcCryptoXmssXMSSMTKeyGenerationParameters_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_([self getParams], prng_)];
  OrgSpongycastleCryptoAsymmetricCipherKeyPair *kp = [kpGen generateKeyPair];
  privateKey_ = (OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) cast_chk([((OrgSpongycastleCryptoAsymmetricCipherKeyPair *) nil_chk(kp)) getPrivate], [OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters class]);
  publicKey_ = (OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *) cast_chk([kp getPublic], [OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters class]);
  OrgSpongycastlePqcCryptoXmssXMSSMT_importStateWithOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_withOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_(self, privateKey_, publicKey_);
}

- (void)importStateWithOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *)privateKey
                    withOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *)publicKey {
  OrgSpongycastlePqcCryptoXmssXMSSMT_importStateWithOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_withOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_(self, privateKey, publicKey);
}

- (void)importStateWithByteArray:(IOSByteArray *)privateKey
                   withByteArray:(IOSByteArray *)publicKey {
  if (privateKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"privateKey == null");
  }
  if (publicKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"publicKey == null");
  }
  OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *xmssMTPrivateKey = [((OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_(params_) withPrivateKeyWithByteArray:privateKey withOrgSpongycastlePqcCryptoXmssXMSSParameters:xmssParams_])) build];
  OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *xmssMTPublicKey = [((OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_(params_) withPublicKeyWithByteArray:publicKey])) build];
  if (!OrgSpongycastleUtilArrays_areEqualWithByteArray_withByteArray_([((OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) nil_chk(xmssMTPrivateKey)) getRoot], [((OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *) nil_chk(xmssMTPublicKey)) getRoot])) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"root of private key and public key do not match");
  }
  if (!OrgSpongycastleUtilArrays_areEqualWithByteArray_withByteArray_([xmssMTPrivateKey getPublicSeed], [xmssMTPublicKey getPublicSeed])) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"public seed of private key and public key do not match");
  }
  [((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(xmssParams_)) getWOTSPlus])) importKeysWithByteArray:[IOSByteArray newArrayWithLength:[((OrgSpongycastlePqcCryptoXmssXMSSMTParameters *) nil_chk(params_)) getDigestSize]] withByteArray:[xmssMTPrivateKey getPublicSeed]];
  self->privateKey_ = xmssMTPrivateKey;
  self->publicKey_ = xmssMTPublicKey;
}

- (IOSByteArray *)signWithByteArray:(IOSByteArray *)message {
  if (message == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"message == null");
  }
  OrgSpongycastlePqcCryptoXmssXMSSMTSigner *signer = new_OrgSpongycastlePqcCryptoXmssXMSSMTSigner_init();
  [signer init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:privateKey_];
  IOSByteArray *signature = [signer generateSignatureWithByteArray:message];
  privateKey_ = (OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) cast_chk([signer getUpdatedPrivateKey], [OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters class]);
  OrgSpongycastlePqcCryptoXmssXMSSMT_importStateWithOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_withOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_(self, privateKey_, publicKey_);
  return signature;
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature
                           withByteArray:(IOSByteArray *)publicKey {
  if (message == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"message == null");
  }
  if (signature == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"signature == null");
  }
  if (publicKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"publicKey == null");
  }
  OrgSpongycastlePqcCryptoXmssXMSSMTSigner *signer = new_OrgSpongycastlePqcCryptoXmssXMSSMTSigner_init();
  [signer init__WithBoolean:false withOrgSpongycastleCryptoCipherParameters:[((OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_Builder *) nil_chk([new_OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_([self getParams]) withPublicKeyWithByteArray:publicKey])) build]];
  return [signer verifySignatureWithByteArray:message withByteArray:signature];
}

- (IOSByteArray *)exportPrivateKey {
  return [((OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) nil_chk(privateKey_)) toByteArray];
}

- (IOSByteArray *)exportPublicKey {
  return [((OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *) nil_chk(publicKey_)) toByteArray];
}

- (OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)getParams {
  return params_;
}

- (IOSByteArray *)getPublicSeed {
  return [((OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) nil_chk(privateKey_)) getPublicSeed];
}

- (OrgSpongycastlePqcCryptoXmssXMSSParameters *)getXMSS {
  return xmssParams_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 6, 7, 8, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSMTParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoXmssXMSSParameters;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(generateKeys);
  methods[2].selector = @selector(importStateWithOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters:withOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters:);
  methods[3].selector = @selector(importStateWithByteArray:withByteArray:);
  methods[4].selector = @selector(signWithByteArray:);
  methods[5].selector = @selector(verifySignatureWithByteArray:withByteArray:withByteArray:);
  methods[6].selector = @selector(exportPrivateKey);
  methods[7].selector = @selector(exportPublicKey);
  methods[8].selector = @selector(getParams);
  methods[9].selector = @selector(getPublicSeed);
  methods[10].selector = @selector(getXMSS);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LOrgSpongycastlePqcCryptoXmssXMSSMTParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "xmssParams_", "LOrgSpongycastlePqcCryptoXmssXMSSParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "prng_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "privateKey_", "LOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicKey_", "LOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcCryptoXmssXMSSMTParameters;LJavaSecuritySecureRandom;", "importState", "LOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters;LOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters;", "[B[B", "sign", "[B", "verifySignature", "[B[B[B", "LJavaTextParseException;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoXmssXMSSMT = { "XMSSMT", "org.spongycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x11, 11, 5, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoXmssXMSSMT;
}

@end

void OrgSpongycastlePqcCryptoXmssXMSSMT_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_(OrgSpongycastlePqcCryptoXmssXMSSMT *self, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, JavaSecuritySecureRandom *prng) {
  NSObject_init(self);
  if (params == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"params == null");
  }
  self->params_ = params;
  self->xmssParams_ = [params getXMSSParameters];
  self->prng_ = prng;
  self->privateKey_ = [new_OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_(params) build];
  self->publicKey_ = [new_OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_(params) build];
}

OrgSpongycastlePqcCryptoXmssXMSSMT *new_OrgSpongycastlePqcCryptoXmssXMSSMT_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, JavaSecuritySecureRandom *prng) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoXmssXMSSMT, initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_, params, prng)
}

OrgSpongycastlePqcCryptoXmssXMSSMT *create_OrgSpongycastlePqcCryptoXmssXMSSMT_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params, JavaSecuritySecureRandom *prng) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoXmssXMSSMT, initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_withJavaSecuritySecureRandom_, params, prng)
}

void OrgSpongycastlePqcCryptoXmssXMSSMT_importStateWithOrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters_withOrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters_(OrgSpongycastlePqcCryptoXmssXMSSMT *self, OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *privateKey, OrgSpongycastlePqcCryptoXmssXMSSMTPublicKeyParameters *publicKey) {
  [((OrgSpongycastlePqcCryptoXmssWOTSPlus *) nil_chk([((OrgSpongycastlePqcCryptoXmssXMSSParameters *) nil_chk(self->xmssParams_)) getWOTSPlus])) importKeysWithByteArray:[IOSByteArray newArrayWithLength:[((OrgSpongycastlePqcCryptoXmssXMSSMTParameters *) nil_chk(self->params_)) getDigestSize]] withByteArray:[((OrgSpongycastlePqcCryptoXmssXMSSMTPrivateKeyParameters *) nil_chk(self->privateKey_)) getPublicSeed]];
  self->privateKey_ = privateKey;
  self->publicKey_ = publicKey;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoXmssXMSSMT)
