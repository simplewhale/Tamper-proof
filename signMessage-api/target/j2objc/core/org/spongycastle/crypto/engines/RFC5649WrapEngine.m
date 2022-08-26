//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/RFC5649WrapEngine.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/BlockCipher.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/InvalidCipherTextException.h"
#include "org/spongycastle/crypto/Wrapper.h"
#include "org/spongycastle/crypto/engines/RFC3394WrapEngine.h"
#include "org/spongycastle/crypto/engines/RFC5649WrapEngine.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"
#include "org/spongycastle/crypto/params/ParametersWithIV.h"
#include "org/spongycastle/crypto/params/ParametersWithRandom.h"
#include "org/spongycastle/util/Arrays.h"
#include "org/spongycastle/util/Pack.h"

@interface OrgSpongycastleCryptoEnginesRFC5649WrapEngine () {
 @public
  id<OrgSpongycastleCryptoBlockCipher> engine_;
  OrgSpongycastleCryptoParamsKeyParameter *param_;
  jboolean forWrapping_;
  IOSByteArray *highOrderIV_;
  IOSByteArray *preIV_;
  IOSByteArray *extractedAIV_;
}

- (IOSByteArray *)padPlaintextWithByteArray:(IOSByteArray *)plaintext;

- (IOSByteArray *)rfc3394UnwrapNoIvCheckWithByteArray:(IOSByteArray *)inArg
                                              withInt:(jint)inOff
                                              withInt:(jint)inLen;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesRFC5649WrapEngine, engine_, id<OrgSpongycastleCryptoBlockCipher>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesRFC5649WrapEngine, param_, OrgSpongycastleCryptoParamsKeyParameter *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesRFC5649WrapEngine, highOrderIV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesRFC5649WrapEngine, preIV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesRFC5649WrapEngine, extractedAIV_, IOSByteArray *)

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEnginesRFC5649WrapEngine_padPlaintextWithByteArray_(OrgSpongycastleCryptoEnginesRFC5649WrapEngine *self, IOSByteArray *plaintext);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEnginesRFC5649WrapEngine_rfc3394UnwrapNoIvCheckWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEnginesRFC5649WrapEngine *self, IOSByteArray *inArg, jint inOff, jint inLen);

@implementation OrgSpongycastleCryptoEnginesRFC5649WrapEngine

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)engine {
  OrgSpongycastleCryptoEnginesRFC5649WrapEngine_initWithOrgSpongycastleCryptoBlockCipher_(self, engine);
  return self;
}

- (void)init__WithBoolean:(jboolean)forWrapping
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param {
  self->forWrapping_ = forWrapping;
  if ([param isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithRandom class]]) {
    param = [((OrgSpongycastleCryptoParamsParametersWithRandom *) nil_chk(((OrgSpongycastleCryptoParamsParametersWithRandom *) param))) getParameters];
  }
  if ([param isKindOfClass:[OrgSpongycastleCryptoParamsKeyParameter class]]) {
    self->param_ = (OrgSpongycastleCryptoParamsKeyParameter *) param;
    self->preIV_ = highOrderIV_;
  }
  else if ([param isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithIV class]]) {
    self->preIV_ = [((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(((OrgSpongycastleCryptoParamsParametersWithIV *) param))) getIV];
    self->param_ = (OrgSpongycastleCryptoParamsKeyParameter *) cast_chk([((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(((OrgSpongycastleCryptoParamsParametersWithIV *) param))) getParameters], [OrgSpongycastleCryptoParamsKeyParameter class]);
    if (((IOSByteArray *) nil_chk(self->preIV_))->size_ != 4) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"IV length not equal to 4");
    }
  }
}

- (NSString *)getAlgorithmName {
  return [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) getAlgorithmName];
}

- (IOSByteArray *)padPlaintextWithByteArray:(IOSByteArray *)plaintext {
  return OrgSpongycastleCryptoEnginesRFC5649WrapEngine_padPlaintextWithByteArray_(self, plaintext);
}

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                            withInt:(jint)inLen {
  if (!forWrapping_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"not set for wrapping");
  }
  IOSByteArray *iv = [IOSByteArray newArrayWithLength:8];
  IOSByteArray *mli = OrgSpongycastleUtilPack_intToBigEndianWithInt_(inLen);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(preIV_, 0, iv, 0, ((IOSByteArray *) nil_chk(preIV_))->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mli, 0, iv, ((IOSByteArray *) nil_chk(preIV_))->size_, ((IOSByteArray *) nil_chk(mli))->size_);
  IOSByteArray *relevantPlaintext = [IOSByteArray newArrayWithLength:inLen];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, relevantPlaintext, 0, inLen);
  IOSByteArray *paddedPlaintext = OrgSpongycastleCryptoEnginesRFC5649WrapEngine_padPlaintextWithByteArray_(self, relevantPlaintext);
  if (((IOSByteArray *) nil_chk(paddedPlaintext))->size_ == 8) {
    IOSByteArray *paddedPlainTextWithIV = [IOSByteArray newArrayWithLength:paddedPlaintext->size_ + iv->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, paddedPlainTextWithIV, 0, iv->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(paddedPlaintext, 0, paddedPlainTextWithIV, iv->size_, paddedPlaintext->size_);
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:param_];
    for (jint i = 0; i < paddedPlainTextWithIV->size_; i += [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) getBlockSize]) {
      [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:paddedPlainTextWithIV withInt:i withByteArray:paddedPlainTextWithIV withInt:i];
    }
    return paddedPlainTextWithIV;
  }
  else {
    id<OrgSpongycastleCryptoWrapper> wrapper = new_OrgSpongycastleCryptoEnginesRFC3394WrapEngine_initWithOrgSpongycastleCryptoBlockCipher_(engine_);
    OrgSpongycastleCryptoParamsParametersWithIV *paramsWithIV = new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(param_, iv);
    [wrapper init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:paramsWithIV];
    return [wrapper wrapWithByteArray:paddedPlaintext withInt:0 withInt:paddedPlaintext->size_];
  }
}

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)inArg
                              withInt:(jint)inOff
                              withInt:(jint)inLen {
  if (forWrapping_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"not set for unwrapping");
  }
  jint n = inLen / 8;
  if ((n * 8) != inLen) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"unwrap data must be a multiple of 8 bytes");
  }
  if (n == 1) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"unwrap data must be at least 16 bytes");
  }
  IOSByteArray *relevantCiphertext = [IOSByteArray newArrayWithLength:inLen];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, relevantCiphertext, 0, inLen);
  IOSByteArray *decrypted = [IOSByteArray newArrayWithLength:inLen];
  IOSByteArray *paddedPlaintext;
  if (n == 2) {
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) init__WithBoolean:false withOrgSpongycastleCryptoCipherParameters:param_];
    for (jint i = 0; i < relevantCiphertext->size_; i += [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) getBlockSize]) {
      [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:relevantCiphertext withInt:i withByteArray:decrypted withInt:i];
    }
    extractedAIV_ = [IOSByteArray newArrayWithLength:8];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(decrypted, 0, extractedAIV_, 0, extractedAIV_->size_);
    paddedPlaintext = [IOSByteArray newArrayWithLength:decrypted->size_ - ((IOSByteArray *) nil_chk(extractedAIV_))->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(decrypted, extractedAIV_->size_, paddedPlaintext, 0, paddedPlaintext->size_);
  }
  else {
    decrypted = OrgSpongycastleCryptoEnginesRFC5649WrapEngine_rfc3394UnwrapNoIvCheckWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
    paddedPlaintext = decrypted;
  }
  IOSByteArray *extractedHighOrderAIV = [IOSByteArray newArrayWithLength:4];
  IOSByteArray *mliBytes = [IOSByteArray newArrayWithLength:4];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(extractedAIV_, 0, extractedHighOrderAIV, 0, extractedHighOrderAIV->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(extractedAIV_, extractedHighOrderAIV->size_, mliBytes, 0, mliBytes->size_);
  jint mli = OrgSpongycastleUtilPack_bigEndianToIntWithByteArray_withInt_(mliBytes, 0);
  jboolean isValid = true;
  if (!OrgSpongycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(extractedHighOrderAIV, preIV_)) {
    isValid = false;
  }
  jint upperBound = ((IOSByteArray *) nil_chk(paddedPlaintext))->size_;
  jint lowerBound = upperBound - 8;
  if (mli <= lowerBound) {
    isValid = false;
  }
  if (mli > upperBound) {
    isValid = false;
  }
  jint expectedZeros = upperBound - mli;
  if (expectedZeros >= paddedPlaintext->size_) {
    isValid = false;
    expectedZeros = paddedPlaintext->size_;
  }
  IOSByteArray *zeros = [IOSByteArray newArrayWithLength:expectedZeros];
  IOSByteArray *pad = [IOSByteArray newArrayWithLength:expectedZeros];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(paddedPlaintext, paddedPlaintext->size_ - expectedZeros, pad, 0, expectedZeros);
  if (!OrgSpongycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(pad, zeros)) {
    isValid = false;
  }
  if (!isValid) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"checksum failed");
  }
  IOSByteArray *plaintext = [IOSByteArray newArrayWithLength:mli];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(paddedPlaintext, 0, plaintext, 0, plaintext->size_);
  return plaintext;
}

- (IOSByteArray *)rfc3394UnwrapNoIvCheckWithByteArray:(IOSByteArray *)inArg
                                              withInt:(jint)inOff
                                              withInt:(jint)inLen {
  return OrgSpongycastleCryptoEnginesRFC5649WrapEngine_rfc3394UnwrapNoIvCheckWithByteArray_withInt_withInt_(self, inArg, inOff, inLen);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 3, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 7, 6, 8, -1, -1, -1 },
    { NULL, "[B", 0x2, 9, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoBlockCipher:);
  methods[1].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(padPlaintextWithByteArray:);
  methods[4].selector = @selector(wrapWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(unwrapWithByteArray:withInt:withInt:);
  methods[6].selector = @selector(rfc3394UnwrapNoIvCheckWithByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "engine_", "LOrgSpongycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "param_", "LOrgSpongycastleCryptoParamsKeyParameter;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forWrapping_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "highOrderIV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "preIV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "extractedAIV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoBlockCipher;", "init", "ZLOrgSpongycastleCryptoCipherParameters;", "padPlaintext", "[B", "wrap", "[BII", "unwrap", "LOrgSpongycastleCryptoInvalidCipherTextException;", "rfc3394UnwrapNoIvCheck" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEnginesRFC5649WrapEngine = { "RFC5649WrapEngine", "org.spongycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 7, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoEnginesRFC5649WrapEngine;
}

@end

void OrgSpongycastleCryptoEnginesRFC5649WrapEngine_initWithOrgSpongycastleCryptoBlockCipher_(OrgSpongycastleCryptoEnginesRFC5649WrapEngine *self, id<OrgSpongycastleCryptoBlockCipher> engine) {
  NSObject_init(self);
  self->highOrderIV_ = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) (jint) 0xa6, (jbyte) (jint) 0x59, (jbyte) (jint) 0x59, (jbyte) (jint) 0xa6 } count:4];
  self->preIV_ = self->highOrderIV_;
  self->extractedAIV_ = nil;
  self->engine_ = engine;
}

OrgSpongycastleCryptoEnginesRFC5649WrapEngine *new_OrgSpongycastleCryptoEnginesRFC5649WrapEngine_initWithOrgSpongycastleCryptoBlockCipher_(id<OrgSpongycastleCryptoBlockCipher> engine) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEnginesRFC5649WrapEngine, initWithOrgSpongycastleCryptoBlockCipher_, engine)
}

OrgSpongycastleCryptoEnginesRFC5649WrapEngine *create_OrgSpongycastleCryptoEnginesRFC5649WrapEngine_initWithOrgSpongycastleCryptoBlockCipher_(id<OrgSpongycastleCryptoBlockCipher> engine) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEnginesRFC5649WrapEngine, initWithOrgSpongycastleCryptoBlockCipher_, engine)
}

IOSByteArray *OrgSpongycastleCryptoEnginesRFC5649WrapEngine_padPlaintextWithByteArray_(OrgSpongycastleCryptoEnginesRFC5649WrapEngine *self, IOSByteArray *plaintext) {
  jint plaintextLength = ((IOSByteArray *) nil_chk(plaintext))->size_;
  jint numOfZerosToAppend = (8 - (plaintextLength % 8)) % 8;
  IOSByteArray *paddedPlaintext = [IOSByteArray newArrayWithLength:plaintextLength + numOfZerosToAppend];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(plaintext, 0, paddedPlaintext, 0, plaintextLength);
  if (numOfZerosToAppend != 0) {
    IOSByteArray *zeros = [IOSByteArray newArrayWithLength:numOfZerosToAppend];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(zeros, 0, paddedPlaintext, plaintextLength, numOfZerosToAppend);
  }
  return paddedPlaintext;
}

IOSByteArray *OrgSpongycastleCryptoEnginesRFC5649WrapEngine_rfc3394UnwrapNoIvCheckWithByteArray_withInt_withInt_(OrgSpongycastleCryptoEnginesRFC5649WrapEngine *self, IOSByteArray *inArg, jint inOff, jint inLen) {
  IOSByteArray *iv = [IOSByteArray newArrayWithLength:8];
  IOSByteArray *block = [IOSByteArray newArrayWithLength:inLen - iv->size_];
  IOSByteArray *a = [IOSByteArray newArrayWithLength:iv->size_];
  IOSByteArray *buf = [IOSByteArray newArrayWithLength:8 + iv->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, a, 0, iv->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff + iv->size_, block, 0, inLen - iv->size_);
  [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->engine_)) init__WithBoolean:false withOrgSpongycastleCryptoCipherParameters:self->param_];
  jint n = inLen / 8;
  n = n - 1;
  for (jint j = 5; j >= 0; j--) {
    for (jint i = n; i >= 1; i--) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(a, 0, buf, 0, iv->size_);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(block, 8 * (i - 1), buf, iv->size_, 8);
      jint t = n * j + i;
      for (jint k = 1; t != 0; k++) {
        jbyte v = (jbyte) t;
        *IOSByteArray_GetRef(buf, iv->size_ - k) ^= v;
        JreURShiftAssignInt(&t, 8);
      }
      [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(self->engine_)) processBlockWithByteArray:buf withInt:0 withByteArray:buf withInt:0];
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, 0, a, 0, 8);
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, 8, block, 8 * (i - 1), 8);
    }
  }
  self->extractedAIV_ = a;
  return block;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoEnginesRFC5649WrapEngine)
