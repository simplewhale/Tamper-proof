//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/modes/PGPCFBBlockCipher.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/BlockCipher.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/DataLengthException.h"
#include "org/spongycastle/crypto/OutputLengthException.h"
#include "org/spongycastle/crypto/modes/PGPCFBBlockCipher.h"
#include "org/spongycastle/crypto/params/ParametersWithIV.h"

@interface OrgSpongycastleCryptoModesPGPCFBBlockCipher () {
 @public
  IOSByteArray *IV_;
  IOSByteArray *FR_;
  IOSByteArray *FRE_;
  IOSByteArray *tmp_;
  id<OrgSpongycastleCryptoBlockCipher> cipher_;
  jint count_;
  jint blockSize_;
  jboolean forEncryption_;
  jboolean inlineIv_;
}

- (jbyte)encryptByteWithByte:(jbyte)data
                     withInt:(jint)blockOff;

- (jint)encryptBlockWithIVWithByteArray:(IOSByteArray *)inArg
                                withInt:(jint)inOff
                          withByteArray:(IOSByteArray *)outArg
                                withInt:(jint)outOff;

- (jint)decryptBlockWithIVWithByteArray:(IOSByteArray *)inArg
                                withInt:(jint)inOff
                          withByteArray:(IOSByteArray *)outArg
                                withInt:(jint)outOff;

- (jint)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (jint)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesPGPCFBBlockCipher, IV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesPGPCFBBlockCipher, FR_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesPGPCFBBlockCipher, FRE_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesPGPCFBBlockCipher, tmp_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesPGPCFBBlockCipher, cipher_, id<OrgSpongycastleCryptoBlockCipher>)

__attribute__((unused)) static jbyte OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, jbyte data, jint blockOff);

__attribute__((unused)) static jint OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptBlockWithIVWithByteArray_withInt_withByteArray_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff);

__attribute__((unused)) static jint OrgSpongycastleCryptoModesPGPCFBBlockCipher_decryptBlockWithIVWithByteArray_withInt_withByteArray_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff);

__attribute__((unused)) static jint OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptBlockWithByteArray_withInt_withByteArray_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff);

__attribute__((unused)) static jint OrgSpongycastleCryptoModesPGPCFBBlockCipher_decryptBlockWithByteArray_withInt_withByteArray_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff);

@implementation OrgSpongycastleCryptoModesPGPCFBBlockCipher

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher
                                             withBoolean:(jboolean)inlineIv {
  OrgSpongycastleCryptoModesPGPCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withBoolean_(self, cipher, inlineIv);
  return self;
}

- (id<OrgSpongycastleCryptoBlockCipher>)getUnderlyingCipher {
  return cipher_;
}

- (NSString *)getAlgorithmName {
  if (inlineIv_) {
    return JreStrcat("$$", [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) getAlgorithmName], @"/PGPCFBwithIV");
  }
  else {
    return JreStrcat("$$", [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) getAlgorithmName], @"/PGPCFB");
  }
}

- (jint)getBlockSize {
  return [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) getBlockSize];
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (inlineIv_) {
    return (forEncryption_) ? OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptBlockWithIVWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff) : OrgSpongycastleCryptoModesPGPCFBBlockCipher_decryptBlockWithIVWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
  }
  else {
    return (forEncryption_) ? OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff) : OrgSpongycastleCryptoModesPGPCFBBlockCipher_decryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
  }
}

- (void)reset {
  count_ = 0;
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(FR_))->size_; i++) {
    if (inlineIv_) {
      *IOSByteArray_GetRef(FR_, i) = 0;
    }
    else {
      *IOSByteArray_GetRef(FR_, i) = IOSByteArray_Get(nil_chk(IV_), i);
    }
  }
  [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) reset];
}

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  self->forEncryption_ = forEncryption;
  if ([params isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithIV class]]) {
    OrgSpongycastleCryptoParamsParametersWithIV *ivParam = (OrgSpongycastleCryptoParamsParametersWithIV *) params;
    IOSByteArray *iv = [((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(ivParam)) getIV];
    if (((IOSByteArray *) nil_chk(iv))->size_ < ((IOSByteArray *) nil_chk(IV_))->size_) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, IV_, IV_->size_ - iv->size_, iv->size_);
      for (jint i = 0; i < ((IOSByteArray *) nil_chk(IV_))->size_ - iv->size_; i++) {
        *IOSByteArray_GetRef(IV_, i) = 0;
      }
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, IV_, 0, IV_->size_);
    }
    [self reset];
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:[ivParam getParameters]];
  }
  else {
    [self reset];
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:params];
  }
}

- (jbyte)encryptByteWithByte:(jbyte)data
                     withInt:(jint)blockOff {
  return OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, data, blockOff);
}

- (jint)encryptBlockWithIVWithByteArray:(IOSByteArray *)inArg
                                withInt:(jint)inOff
                          withByteArray:(IOSByteArray *)outArg
                                withInt:(jint)outOff {
  return OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptBlockWithIVWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

- (jint)decryptBlockWithIVWithByteArray:(IOSByteArray *)inArg
                                withInt:(jint)inOff
                          withByteArray:(IOSByteArray *)outArg
                                withInt:(jint)outOff {
  return OrgSpongycastleCryptoModesPGPCFBBlockCipher_decryptBlockWithIVWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

- (jint)encryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  return OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

- (jint)decryptBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  return OrgSpongycastleCryptoModesPGPCFBBlockCipher_decryptBlockWithByteArray_withInt_withByteArray_withInt_(self, inArg, inOff, outArg, outOff);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoBlockCipher;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 6, -1, -1, -1 },
    { NULL, "B", 0x2, 7, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 9, 2, 3, -1, -1, -1 },
    { NULL, "I", 0x2, 10, 2, 3, -1, -1, -1 },
    { NULL, "I", 0x2, 11, 2, 3, -1, -1, -1 },
    { NULL, "I", 0x2, 12, 2, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoBlockCipher:withBoolean:);
  methods[1].selector = @selector(getUnderlyingCipher);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getBlockSize);
  methods[4].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[5].selector = @selector(reset);
  methods[6].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[7].selector = @selector(encryptByteWithByte:withInt:);
  methods[8].selector = @selector(encryptBlockWithIVWithByteArray:withInt:withByteArray:withInt:);
  methods[9].selector = @selector(decryptBlockWithIVWithByteArray:withInt:withByteArray:withInt:);
  methods[10].selector = @selector(encryptBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[11].selector = @selector(decryptBlockWithByteArray:withInt:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "IV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "FR_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "FRE_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "tmp_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cipher_", "LOrgSpongycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "count_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "blockSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "inlineIv_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoBlockCipher;Z", "processBlock", "[BI[BI", "LOrgSpongycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "init", "ZLOrgSpongycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "encryptByte", "BI", "encryptBlockWithIV", "decryptBlockWithIV", "encryptBlock", "decryptBlock" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoModesPGPCFBBlockCipher = { "PGPCFBBlockCipher", "org.spongycastle.crypto.modes", ptrTable, methods, fields, 7, 0x1, 12, 9, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoModesPGPCFBBlockCipher;
}

@end

void OrgSpongycastleCryptoModesPGPCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withBoolean_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, id<OrgSpongycastleCryptoBlockCipher> cipher, jboolean inlineIv) {
  NSObject_init(self);
  self->cipher_ = cipher;
  self->inlineIv_ = inlineIv;
  self->blockSize_ = [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(cipher)) getBlockSize];
  self->IV_ = [IOSByteArray newArrayWithLength:self->blockSize_];
  self->FR_ = [IOSByteArray newArrayWithLength:self->blockSize_];
  self->FRE_ = [IOSByteArray newArrayWithLength:self->blockSize_];
  self->tmp_ = [IOSByteArray newArrayWithLength:self->blockSize_];
}

OrgSpongycastleCryptoModesPGPCFBBlockCipher *new_OrgSpongycastleCryptoModesPGPCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withBoolean_(id<OrgSpongycastleCryptoBlockCipher> cipher, jboolean inlineIv) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoModesPGPCFBBlockCipher, initWithOrgSpongycastleCryptoBlockCipher_withBoolean_, cipher, inlineIv)
}

OrgSpongycastleCryptoModesPGPCFBBlockCipher *create_OrgSpongycastleCryptoModesPGPCFBBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_withBoolean_(id<OrgSpongycastleCryptoBlockCipher> cipher, jboolean inlineIv) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoModesPGPCFBBlockCipher, initWithOrgSpongycastleCryptoBlockCipher_withBoolean_, cipher, inlineIv)
}

jbyte OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, jbyte data, jint blockOff) {
  return (jbyte) (IOSByteArray_Get(nil_chk(self->FRE_), blockOff) ^ data);
}

jint OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptBlockWithIVWithByteArray_withInt_withByteArray_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff) {
  if ((inOff + self->blockSize_) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if (self->count_ == 0) {
    if ((outOff + 2 * self->blockSize_ + 2) > ((IOSByteArray *) nil_chk(outArg))->size_) {
      @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
    }
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 0; n < self->blockSize_; n++) {
      *IOSByteArray_GetRef(outArg, outOff + n) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(nil_chk(self->IV_), n), n);
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(outArg, outOff, self->FR_, 0, self->blockSize_);
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    *IOSByteArray_GetRef(outArg, outOff + self->blockSize_) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(nil_chk(self->IV_), self->blockSize_ - 2), 0);
    *IOSByteArray_GetRef(outArg, outOff + self->blockSize_ + 1) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(nil_chk(self->IV_), self->blockSize_ - 1), 1);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(outArg, outOff + 2, self->FR_, 0, self->blockSize_);
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 0; n < self->blockSize_; n++) {
      *IOSByteArray_GetRef(outArg, outOff + self->blockSize_ + 2 + n) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + n), n);
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(outArg, outOff + self->blockSize_ + 2, self->FR_, 0, self->blockSize_);
    self->count_ += 2 * self->blockSize_ + 2;
    return 2 * self->blockSize_ + 2;
  }
  else if (self->count_ >= self->blockSize_ + 2) {
    if ((outOff + self->blockSize_) > ((IOSByteArray *) nil_chk(outArg))->size_) {
      @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
    }
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 0; n < self->blockSize_; n++) {
      *IOSByteArray_GetRef(outArg, outOff + n) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + n), n);
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(outArg, outOff, self->FR_, 0, self->blockSize_);
  }
  return self->blockSize_;
}

jint OrgSpongycastleCryptoModesPGPCFBBlockCipher_decryptBlockWithIVWithByteArray_withInt_withByteArray_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff) {
  if ((inOff + self->blockSize_) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + self->blockSize_) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  if (self->count_ == 0) {
    for (jint n = 0; n < self->blockSize_; n++) {
      *IOSByteArray_GetRef(nil_chk(self->FR_), n) = IOSByteArray_Get(inArg, inOff + n);
    }
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    self->count_ += self->blockSize_;
    return 0;
  }
  else if (self->count_ == self->blockSize_) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, self->tmp_, 0, self->blockSize_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->FR_, 2, self->FR_, 0, self->blockSize_ - 2);
    *IOSByteArray_GetRef(nil_chk(self->FR_), self->blockSize_ - 2) = IOSByteArray_Get(nil_chk(self->tmp_), 0);
    *IOSByteArray_GetRef(self->FR_, self->blockSize_ - 1) = IOSByteArray_Get(self->tmp_, 1);
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 0; n < self->blockSize_ - 2; n++) {
      *IOSByteArray_GetRef(outArg, outOff + n) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(nil_chk(self->tmp_), n + 2), n);
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->tmp_, 2, self->FR_, 0, self->blockSize_ - 2);
    self->count_ += 2;
    return self->blockSize_ - 2;
  }
  else if (self->count_ >= self->blockSize_ + 2) {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, self->tmp_, 0, self->blockSize_);
    *IOSByteArray_GetRef(outArg, outOff + 0) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(nil_chk(self->tmp_), 0), self->blockSize_ - 2);
    *IOSByteArray_GetRef(outArg, outOff + 1) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(nil_chk(self->tmp_), 1), self->blockSize_ - 1);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->tmp_, 0, self->FR_, self->blockSize_ - 2, 2);
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
    for (jint n = 0; n < self->blockSize_ - 2; n++) {
      *IOSByteArray_GetRef(outArg, outOff + n + 2) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(nil_chk(self->tmp_), n + 2), n);
    }
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->tmp_, 2, self->FR_, 0, self->blockSize_ - 2);
  }
  return self->blockSize_;
}

jint OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptBlockWithByteArray_withInt_withByteArray_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff) {
  if ((inOff + self->blockSize_) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + self->blockSize_) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
  for (jint n = 0; n < self->blockSize_; n++) {
    *IOSByteArray_GetRef(outArg, outOff + n) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + n), n);
  }
  for (jint n = 0; n < self->blockSize_; n++) {
    *IOSByteArray_GetRef(nil_chk(self->FR_), n) = IOSByteArray_Get(outArg, outOff + n);
  }
  return self->blockSize_;
}

jint OrgSpongycastleCryptoModesPGPCFBBlockCipher_decryptBlockWithByteArray_withInt_withByteArray_withInt_(OrgSpongycastleCryptoModesPGPCFBBlockCipher *self, IOSByteArray *inArg, jint inOff, IOSByteArray *outArg, jint outOff) {
  if ((inOff + self->blockSize_) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + self->blockSize_) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->cipher_)) processBlockWithByteArray:self->FR_ withInt:0 withByteArray:self->FRE_ withInt:0];
  for (jint n = 0; n < self->blockSize_; n++) {
    *IOSByteArray_GetRef(outArg, outOff + n) = OrgSpongycastleCryptoModesPGPCFBBlockCipher_encryptByteWithByte_withInt_(self, IOSByteArray_Get(inArg, inOff + n), n);
  }
  for (jint n = 0; n < self->blockSize_; n++) {
    *IOSByteArray_GetRef(nil_chk(self->FR_), n) = IOSByteArray_Get(inArg, inOff + n);
  }
  return self->blockSize_;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoModesPGPCFBBlockCipher)