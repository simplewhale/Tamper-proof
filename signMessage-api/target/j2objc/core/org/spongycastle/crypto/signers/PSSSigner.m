//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/signers/PSSSigner.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/AsymmetricBlockCipher.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/params/ParametersWithRandom.h"
#include "org/spongycastle/crypto/params/RSABlindingParameters.h"
#include "org/spongycastle/crypto/params/RSAKeyParameters.h"
#include "org/spongycastle/crypto/signers/PSSSigner.h"

@interface OrgSpongycastleCryptoSignersPSSSigner () {
 @public
  id<OrgSpongycastleCryptoDigest> contentDigest_;
  id<OrgSpongycastleCryptoDigest> mgfDigest_;
  id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher_;
  JavaSecuritySecureRandom *random_;
  jint hLen_;
  jint mgfhLen_;
  jboolean sSet_;
  jint sLen_;
  jint emBits_;
  IOSByteArray *salt_;
  IOSByteArray *mDash_;
  IOSByteArray *block_;
  jbyte trailer_;
}

- (void)clearBlockWithByteArray:(IOSByteArray *)block;

- (void)ItoOSPWithInt:(jint)i
        withByteArray:(IOSByteArray *)sp;

- (IOSByteArray *)maskGeneratorFunction1WithByteArray:(IOSByteArray *)Z
                                              withInt:(jint)zOff
                                              withInt:(jint)zLen
                                              withInt:(jint)length;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersPSSSigner, contentDigest_, id<OrgSpongycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersPSSSigner, mgfDigest_, id<OrgSpongycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersPSSSigner, cipher_, id<OrgSpongycastleCryptoAsymmetricBlockCipher>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersPSSSigner, random_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersPSSSigner, salt_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersPSSSigner, mDash_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersPSSSigner, block_, IOSByteArray *)

__attribute__((unused)) static void OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(OrgSpongycastleCryptoSignersPSSSigner *self, IOSByteArray *block);

__attribute__((unused)) static void OrgSpongycastleCryptoSignersPSSSigner_ItoOSPWithInt_withByteArray_(OrgSpongycastleCryptoSignersPSSSigner *self, jint i, IOSByteArray *sp);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoSignersPSSSigner_maskGeneratorFunction1WithByteArray_withInt_withInt_withInt_(OrgSpongycastleCryptoSignersPSSSigner *self, IOSByteArray *Z, jint zOff, jint zLen, jint length);

@implementation OrgSpongycastleCryptoSignersPSSSigner

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                                           withInt:(jint)sLen {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_(self, cipher, digest, sLen);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)contentDigest
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)mgfDigest
                                                           withInt:(jint)sLen {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_(self, cipher, contentDigest, mgfDigest, sLen);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                                           withInt:(jint)sLen
                                                          withByte:(jbyte)trailer {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_withByte_(self, cipher, digest, sLen, trailer);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)contentDigest
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)mgfDigest
                                                           withInt:(jint)sLen
                                                          withByte:(jbyte)trailer {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_withByte_(self, cipher, contentDigest, mgfDigest, sLen, trailer);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                                     withByteArray:(IOSByteArray *)salt {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withByteArray_(self, cipher, digest, salt);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)contentDigest
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)mgfDigest
                                                     withByteArray:(IOSByteArray *)salt {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_(self, cipher, contentDigest, mgfDigest, salt);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoAsymmetricBlockCipher:(id<OrgSpongycastleCryptoAsymmetricBlockCipher>)cipher
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)contentDigest
                                   withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)mgfDigest
                                                     withByteArray:(IOSByteArray *)salt
                                                          withByte:(jbyte)trailer {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_withByte_(self, cipher, contentDigest, mgfDigest, salt, trailer);
  return self;
}

- (void)init__WithBoolean:(jboolean)forSigning
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param {
  id<OrgSpongycastleCryptoCipherParameters> params;
  if ([param isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithRandom class]]) {
    OrgSpongycastleCryptoParamsParametersWithRandom *p = (OrgSpongycastleCryptoParamsParametersWithRandom *) param;
    params = [((OrgSpongycastleCryptoParamsParametersWithRandom *) nil_chk(p)) getParameters];
    random_ = [p getRandom];
  }
  else {
    params = param;
    if (forSigning) {
      random_ = new_JavaSecuritySecureRandom_init();
    }
  }
  OrgSpongycastleCryptoParamsRSAKeyParameters *kParam;
  if ([params isKindOfClass:[OrgSpongycastleCryptoParamsRSABlindingParameters class]]) {
    kParam = [((OrgSpongycastleCryptoParamsRSABlindingParameters *) nil_chk(((OrgSpongycastleCryptoParamsRSABlindingParameters *) params))) getPublicKey];
    [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) init__WithBoolean:forSigning withOrgSpongycastleCryptoCipherParameters:param];
  }
  else {
    kParam = (OrgSpongycastleCryptoParamsRSAKeyParameters *) cast_chk(params, [OrgSpongycastleCryptoParamsRSAKeyParameters class]);
    [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) init__WithBoolean:forSigning withOrgSpongycastleCryptoCipherParameters:params];
  }
  emBits_ = [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleCryptoParamsRSAKeyParameters *) nil_chk(kParam)) getModulus])) bitLength] - 1;
  if (emBits_ < (8 * hLen_ + 8 * sLen_ + 9)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key too small for specified hash and salt lengths");
  }
  block_ = [IOSByteArray newArrayWithLength:(emBits_ + 7) / 8];
  [self reset];
}

- (void)clearBlockWithByteArray:(IOSByteArray *)block {
  OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, block);
}

- (void)updateWithByte:(jbyte)b {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) updateWithByte:b];
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)off
                    withInt:(jint)len {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) updateWithByteArray:inArg withInt:off withInt:len];
}

- (void)reset {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) reset];
}

- (IOSByteArray *)generateSignature {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) doFinalWithByteArray:mDash_ withInt:((IOSByteArray *) nil_chk(mDash_))->size_ - hLen_ - sLen_];
  if (sLen_ != 0) {
    if (!sSet_) {
      [((JavaSecuritySecureRandom *) nil_chk(random_)) nextBytesWithByteArray:salt_];
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(salt_, 0, mDash_, ((IOSByteArray *) nil_chk(mDash_))->size_ - sLen_, sLen_);
  }
  IOSByteArray *h = [IOSByteArray newArrayWithLength:hLen_];
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) updateWithByteArray:mDash_ withInt:0 withInt:((IOSByteArray *) nil_chk(mDash_))->size_];
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) doFinalWithByteArray:h withInt:0];
  *IOSByteArray_GetRef(block_, ((IOSByteArray *) nil_chk(block_))->size_ - sLen_ - 1 - hLen_ - 1) = (jint) 0x01;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(salt_, 0, block_, block_->size_ - sLen_ - hLen_ - 1, sLen_);
  IOSByteArray *dbMask = OrgSpongycastleCryptoSignersPSSSigner_maskGeneratorFunction1WithByteArray_withInt_withInt_withInt_(self, h, 0, h->size_, ((IOSByteArray *) nil_chk(block_))->size_ - hLen_ - 1);
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(dbMask))->size_; i++) {
    *IOSByteArray_GetRef(nil_chk(block_), i) ^= IOSByteArray_Get(dbMask, i);
  }
  *IOSByteArray_GetRef(nil_chk(block_), 0) &= (JreRShift32((jint) 0xff, ((block_->size_ * 8) - emBits_)));
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(h, 0, block_, block_->size_ - hLen_ - 1, hLen_);
  *IOSByteArray_GetRef(block_, ((IOSByteArray *) nil_chk(block_))->size_ - 1) = trailer_;
  IOSByteArray *b = [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:block_ withInt:0 withInt:block_->size_];
  OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, block_);
  return b;
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) doFinalWithByteArray:mDash_ withInt:((IOSByteArray *) nil_chk(mDash_))->size_ - hLen_ - sLen_];
  @try {
    IOSByteArray *b = [((id<OrgSpongycastleCryptoAsymmetricBlockCipher>) nil_chk(cipher_)) processBlockWithByteArray:signature withInt:0 withInt:((IOSByteArray *) nil_chk(signature))->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(b, 0, block_, ((IOSByteArray *) nil_chk(block_))->size_ - ((IOSByteArray *) nil_chk(b))->size_, b->size_);
  }
  @catch (JavaLangException *e) {
    return false;
  }
  if (IOSByteArray_Get(block_, ((IOSByteArray *) nil_chk(block_))->size_ - 1) != trailer_) {
    OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, block_);
    return false;
  }
  IOSByteArray *dbMask = OrgSpongycastleCryptoSignersPSSSigner_maskGeneratorFunction1WithByteArray_withInt_withInt_withInt_(self, block_, block_->size_ - hLen_ - 1, hLen_, block_->size_ - hLen_ - 1);
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(dbMask))->size_; i++) {
    *IOSByteArray_GetRef(nil_chk(block_), i) ^= IOSByteArray_Get(dbMask, i);
  }
  *IOSByteArray_GetRef(nil_chk(block_), 0) &= (JreRShift32((jint) 0xff, ((block_->size_ * 8) - emBits_)));
  for (jint i = 0; i != block_->size_ - hLen_ - sLen_ - 2; i++) {
    if (IOSByteArray_Get(block_, i) != 0) {
      OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, block_);
      return false;
    }
  }
  if (IOSByteArray_Get(block_, block_->size_ - hLen_ - sLen_ - 2) != (jint) 0x01) {
    OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, block_);
    return false;
  }
  if (sSet_) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(salt_, 0, mDash_, ((IOSByteArray *) nil_chk(mDash_))->size_ - sLen_, sLen_);
  }
  else {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(block_, block_->size_ - sLen_ - hLen_ - 1, mDash_, ((IOSByteArray *) nil_chk(mDash_))->size_ - sLen_, sLen_);
  }
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) updateWithByteArray:mDash_ withInt:0 withInt:((IOSByteArray *) nil_chk(mDash_))->size_];
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest_)) doFinalWithByteArray:mDash_ withInt:((IOSByteArray *) nil_chk(mDash_))->size_ - hLen_];
  for (jint i = ((IOSByteArray *) nil_chk(block_))->size_ - hLen_ - 1, j = ((IOSByteArray *) nil_chk(mDash_))->size_ - hLen_; j != mDash_->size_; i++, j++) {
    if ((IOSByteArray_Get(block_, i) ^ IOSByteArray_Get(mDash_, j)) != 0) {
      OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, mDash_);
      OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, block_);
      return false;
    }
  }
  OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, mDash_);
  OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(self, block_);
  return true;
}

- (void)ItoOSPWithInt:(jint)i
        withByteArray:(IOSByteArray *)sp {
  OrgSpongycastleCryptoSignersPSSSigner_ItoOSPWithInt_withByteArray_(self, i, sp);
}

- (IOSByteArray *)maskGeneratorFunction1WithByteArray:(IOSByteArray *)Z
                                              withInt:(jint)zOff
                                              withInt:(jint)zLen
                                              withInt:(jint)length {
  return OrgSpongycastleCryptoSignersPSSSigner_maskGeneratorFunction1WithByteArray_withInt_withInt_withInt_(self, Z, zOff, zLen, length);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 11, 12, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 11, 13, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 14, -1, -1, -1 },
    { NULL, "Z", 0x1, 15, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 16, 17, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 18, 19, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withOrgSpongycastleCryptoDigest:withInt:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withOrgSpongycastleCryptoDigest:withOrgSpongycastleCryptoDigest:withInt:);
  methods[2].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withOrgSpongycastleCryptoDigest:withInt:withByte:);
  methods[3].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withOrgSpongycastleCryptoDigest:withOrgSpongycastleCryptoDigest:withInt:withByte:);
  methods[4].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withOrgSpongycastleCryptoDigest:withByteArray:);
  methods[5].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withOrgSpongycastleCryptoDigest:withOrgSpongycastleCryptoDigest:withByteArray:);
  methods[6].selector = @selector(initWithOrgSpongycastleCryptoAsymmetricBlockCipher:withOrgSpongycastleCryptoDigest:withOrgSpongycastleCryptoDigest:withByteArray:withByte:);
  methods[7].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[8].selector = @selector(clearBlockWithByteArray:);
  methods[9].selector = @selector(updateWithByte:);
  methods[10].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[11].selector = @selector(reset);
  methods[12].selector = @selector(generateSignature);
  methods[13].selector = @selector(verifySignatureWithByteArray:);
  methods[14].selector = @selector(ItoOSPWithInt:withByteArray:);
  methods[15].selector = @selector(maskGeneratorFunction1WithByteArray:withInt:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TRAILER_IMPLICIT", "B", .constantValue.asChar = OrgSpongycastleCryptoSignersPSSSigner_TRAILER_IMPLICIT, 0x19, -1, -1, -1, -1 },
    { "contentDigest_", "LOrgSpongycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mgfDigest_", "LOrgSpongycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cipher_", "LOrgSpongycastleCryptoAsymmetricBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hLen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mgfhLen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sSet_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sLen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "emBits_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "salt_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mDash_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "block_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "trailer_", "B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoAsymmetricBlockCipher;LOrgSpongycastleCryptoDigest;I", "LOrgSpongycastleCryptoAsymmetricBlockCipher;LOrgSpongycastleCryptoDigest;LOrgSpongycastleCryptoDigest;I", "LOrgSpongycastleCryptoAsymmetricBlockCipher;LOrgSpongycastleCryptoDigest;IB", "LOrgSpongycastleCryptoAsymmetricBlockCipher;LOrgSpongycastleCryptoDigest;LOrgSpongycastleCryptoDigest;IB", "LOrgSpongycastleCryptoAsymmetricBlockCipher;LOrgSpongycastleCryptoDigest;[B", "LOrgSpongycastleCryptoAsymmetricBlockCipher;LOrgSpongycastleCryptoDigest;LOrgSpongycastleCryptoDigest;[B", "LOrgSpongycastleCryptoAsymmetricBlockCipher;LOrgSpongycastleCryptoDigest;LOrgSpongycastleCryptoDigest;[BB", "init", "ZLOrgSpongycastleCryptoCipherParameters;", "clearBlock", "[B", "update", "B", "[BII", "LOrgSpongycastleCryptoCryptoException;LOrgSpongycastleCryptoDataLengthException;", "verifySignature", "ItoOSP", "I[B", "maskGeneratorFunction1", "[BIII" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoSignersPSSSigner = { "PSSSigner", "org.spongycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 16, 14, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoSignersPSSSigner;
}

@end

void OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_(OrgSpongycastleCryptoSignersPSSSigner *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, jint sLen) {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_withByte_(self, cipher, digest, sLen, OrgSpongycastleCryptoSignersPSSSigner_TRAILER_IMPLICIT);
}

OrgSpongycastleCryptoSignersPSSSigner *new_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, jint sLen) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_, cipher, digest, sLen)
}

OrgSpongycastleCryptoSignersPSSSigner *create_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, jint sLen) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_, cipher, digest, sLen)
}

void OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_(OrgSpongycastleCryptoSignersPSSSigner *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, jint sLen) {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_withByte_(self, cipher, contentDigest, mgfDigest, sLen, OrgSpongycastleCryptoSignersPSSSigner_TRAILER_IMPLICIT);
}

OrgSpongycastleCryptoSignersPSSSigner *new_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, jint sLen) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_, cipher, contentDigest, mgfDigest, sLen)
}

OrgSpongycastleCryptoSignersPSSSigner *create_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, jint sLen) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_, cipher, contentDigest, mgfDigest, sLen)
}

void OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_withByte_(OrgSpongycastleCryptoSignersPSSSigner *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, jint sLen, jbyte trailer) {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_withByte_(self, cipher, digest, digest, sLen, trailer);
}

OrgSpongycastleCryptoSignersPSSSigner *new_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_withByte_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, jint sLen, jbyte trailer) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_withByte_, cipher, digest, sLen, trailer)
}

OrgSpongycastleCryptoSignersPSSSigner *create_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_withByte_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, jint sLen, jbyte trailer) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withInt_withByte_, cipher, digest, sLen, trailer)
}

void OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_withByte_(OrgSpongycastleCryptoSignersPSSSigner *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, jint sLen, jbyte trailer) {
  NSObject_init(self);
  self->cipher_ = cipher;
  self->contentDigest_ = contentDigest;
  self->mgfDigest_ = mgfDigest;
  self->hLen_ = [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest)) getDigestSize];
  self->mgfhLen_ = [((id<OrgSpongycastleCryptoDigest>) nil_chk(mgfDigest)) getDigestSize];
  self->sSet_ = false;
  self->sLen_ = sLen;
  self->salt_ = [IOSByteArray newArrayWithLength:sLen];
  self->mDash_ = [IOSByteArray newArrayWithLength:8 + sLen + self->hLen_];
  self->trailer_ = trailer;
}

OrgSpongycastleCryptoSignersPSSSigner *new_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_withByte_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, jint sLen, jbyte trailer) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_withByte_, cipher, contentDigest, mgfDigest, sLen, trailer)
}

OrgSpongycastleCryptoSignersPSSSigner *create_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_withByte_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, jint sLen, jbyte trailer) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withInt_withByte_, cipher, contentDigest, mgfDigest, sLen, trailer)
}

void OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withByteArray_(OrgSpongycastleCryptoSignersPSSSigner *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, IOSByteArray *salt) {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_withByte_(self, cipher, digest, digest, salt, OrgSpongycastleCryptoSignersPSSSigner_TRAILER_IMPLICIT);
}

OrgSpongycastleCryptoSignersPSSSigner *new_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withByteArray_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, IOSByteArray *salt) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withByteArray_, cipher, digest, salt)
}

OrgSpongycastleCryptoSignersPSSSigner *create_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withByteArray_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> digest, IOSByteArray *salt) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withByteArray_, cipher, digest, salt)
}

void OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_(OrgSpongycastleCryptoSignersPSSSigner *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, IOSByteArray *salt) {
  OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_withByte_(self, cipher, contentDigest, mgfDigest, salt, OrgSpongycastleCryptoSignersPSSSigner_TRAILER_IMPLICIT);
}

OrgSpongycastleCryptoSignersPSSSigner *new_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, IOSByteArray *salt) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_, cipher, contentDigest, mgfDigest, salt)
}

OrgSpongycastleCryptoSignersPSSSigner *create_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, IOSByteArray *salt) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_, cipher, contentDigest, mgfDigest, salt)
}

void OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_withByte_(OrgSpongycastleCryptoSignersPSSSigner *self, id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, IOSByteArray *salt, jbyte trailer) {
  NSObject_init(self);
  self->cipher_ = cipher;
  self->contentDigest_ = contentDigest;
  self->mgfDigest_ = mgfDigest;
  self->hLen_ = [((id<OrgSpongycastleCryptoDigest>) nil_chk(contentDigest)) getDigestSize];
  self->mgfhLen_ = [((id<OrgSpongycastleCryptoDigest>) nil_chk(mgfDigest)) getDigestSize];
  self->sSet_ = true;
  self->sLen_ = ((IOSByteArray *) nil_chk(salt))->size_;
  self->salt_ = salt;
  self->mDash_ = [IOSByteArray newArrayWithLength:8 + self->sLen_ + self->hLen_];
  self->trailer_ = trailer;
}

OrgSpongycastleCryptoSignersPSSSigner *new_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_withByte_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, IOSByteArray *salt, jbyte trailer) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_withByte_, cipher, contentDigest, mgfDigest, salt, trailer)
}

OrgSpongycastleCryptoSignersPSSSigner *create_OrgSpongycastleCryptoSignersPSSSigner_initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_withByte_(id<OrgSpongycastleCryptoAsymmetricBlockCipher> cipher, id<OrgSpongycastleCryptoDigest> contentDigest, id<OrgSpongycastleCryptoDigest> mgfDigest, IOSByteArray *salt, jbyte trailer) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoSignersPSSSigner, initWithOrgSpongycastleCryptoAsymmetricBlockCipher_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_withByteArray_withByte_, cipher, contentDigest, mgfDigest, salt, trailer)
}

void OrgSpongycastleCryptoSignersPSSSigner_clearBlockWithByteArray_(OrgSpongycastleCryptoSignersPSSSigner *self, IOSByteArray *block) {
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(block))->size_; i++) {
    *IOSByteArray_GetRef(block, i) = 0;
  }
}

void OrgSpongycastleCryptoSignersPSSSigner_ItoOSPWithInt_withByteArray_(OrgSpongycastleCryptoSignersPSSSigner *self, jint i, IOSByteArray *sp) {
  *IOSByteArray_GetRef(nil_chk(sp), 0) = (jbyte) (JreURShift32(i, 24));
  *IOSByteArray_GetRef(sp, 1) = (jbyte) (JreURShift32(i, 16));
  *IOSByteArray_GetRef(sp, 2) = (jbyte) (JreURShift32(i, 8));
  *IOSByteArray_GetRef(sp, 3) = (jbyte) (JreURShift32(i, 0));
}

IOSByteArray *OrgSpongycastleCryptoSignersPSSSigner_maskGeneratorFunction1WithByteArray_withInt_withInt_withInt_(OrgSpongycastleCryptoSignersPSSSigner *self, IOSByteArray *Z, jint zOff, jint zLen, jint length) {
  IOSByteArray *mask = [IOSByteArray newArrayWithLength:length];
  IOSByteArray *hashBuf = [IOSByteArray newArrayWithLength:self->mgfhLen_];
  IOSByteArray *C = [IOSByteArray newArrayWithLength:4];
  jint counter = 0;
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->mgfDigest_)) reset];
  while (counter < (length / self->mgfhLen_)) {
    OrgSpongycastleCryptoSignersPSSSigner_ItoOSPWithInt_withByteArray_(self, counter, C);
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->mgfDigest_)) updateWithByteArray:Z withInt:zOff withInt:zLen];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->mgfDigest_)) updateWithByteArray:C withInt:0 withInt:C->size_];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->mgfDigest_)) doFinalWithByteArray:hashBuf withInt:0];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(hashBuf, 0, mask, counter * self->mgfhLen_, self->mgfhLen_);
    counter++;
  }
  if ((counter * self->mgfhLen_) < length) {
    OrgSpongycastleCryptoSignersPSSSigner_ItoOSPWithInt_withByteArray_(self, counter, C);
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->mgfDigest_)) updateWithByteArray:Z withInt:zOff withInt:zLen];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->mgfDigest_)) updateWithByteArray:C withInt:0 withInt:C->size_];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->mgfDigest_)) doFinalWithByteArray:hashBuf withInt:0];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(hashBuf, 0, mask, counter * self->mgfhLen_, mask->size_ - (counter * self->mgfhLen_));
  }
  return mask;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoSignersPSSSigner)
