//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/Salsa20Engine.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/DataLengthException.h"
#include "org/spongycastle/crypto/MaxBytesExceededException.h"
#include "org/spongycastle/crypto/OutputLengthException.h"
#include "org/spongycastle/crypto/engines/Salsa20Engine.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"
#include "org/spongycastle/crypto/params/ParametersWithIV.h"
#include "org/spongycastle/util/Pack.h"
#include "org/spongycastle/util/Strings.h"

@interface OrgSpongycastleCryptoEnginesSalsa20Engine () {
 @public
  jint index_;
  IOSByteArray *keyStream_;
  jboolean initialised_;
  jint cW0_;
  jint cW1_;
  jint cW2_;
}

- (void)resetLimitCounter;

- (jboolean)limitExceeded;

- (jboolean)limitExceededWithInt:(jint)len;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesSalsa20Engine, keyStream_, IOSByteArray *)

inline jint OrgSpongycastleCryptoEnginesSalsa20Engine_get_STATE_SIZE(void);
#define OrgSpongycastleCryptoEnginesSalsa20Engine_STATE_SIZE 16
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoEnginesSalsa20Engine, STATE_SIZE, jint)

inline IOSIntArray *OrgSpongycastleCryptoEnginesSalsa20Engine_get_TAU_SIGMA(void);
static IOSIntArray *OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoEnginesSalsa20Engine, TAU_SIGMA, IOSIntArray *)

__attribute__((unused)) static void OrgSpongycastleCryptoEnginesSalsa20Engine_resetLimitCounter(OrgSpongycastleCryptoEnginesSalsa20Engine *self);

__attribute__((unused)) static jboolean OrgSpongycastleCryptoEnginesSalsa20Engine_limitExceeded(OrgSpongycastleCryptoEnginesSalsa20Engine *self);

__attribute__((unused)) static jboolean OrgSpongycastleCryptoEnginesSalsa20Engine_limitExceededWithInt_(OrgSpongycastleCryptoEnginesSalsa20Engine *self, jint len);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoEnginesSalsa20Engine)

IOSByteArray *OrgSpongycastleCryptoEnginesSalsa20Engine_sigma;
IOSByteArray *OrgSpongycastleCryptoEnginesSalsa20Engine_tau;

@implementation OrgSpongycastleCryptoEnginesSalsa20Engine

- (void)packTauOrSigmaWithInt:(jint)keyLength
                 withIntArray:(IOSIntArray *)state
                      withInt:(jint)stateOffset {
  jint tsOff = (keyLength - 16) / 4;
  *IOSIntArray_GetRef(nil_chk(state), stateOffset) = IOSIntArray_Get(nil_chk(OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA), tsOff);
  *IOSIntArray_GetRef(state, stateOffset + 1) = IOSIntArray_Get(OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA, tsOff + 1);
  *IOSIntArray_GetRef(state, stateOffset + 2) = IOSIntArray_Get(OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA, tsOff + 2);
  *IOSIntArray_GetRef(state, stateOffset + 3) = IOSIntArray_Get(OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA, tsOff + 3);
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoEnginesSalsa20Engine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithInt:(jint)rounds {
  OrgSpongycastleCryptoEnginesSalsa20Engine_initWithInt_(self, rounds);
  return self;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  if (!([params isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithIV class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", [self getAlgorithmName], @" Init parameters must include an IV"));
  }
  OrgSpongycastleCryptoParamsParametersWithIV *ivParams = (OrgSpongycastleCryptoParamsParametersWithIV *) cast_chk(params, [OrgSpongycastleCryptoParamsParametersWithIV class]);
  IOSByteArray *iv = [((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(ivParams)) getIV];
  if (iv == nil || iv->size_ != [self getNonceSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$I$", [self getAlgorithmName], @" requires exactly ", [self getNonceSize], @" bytes of IV"));
  }
  id<OrgSpongycastleCryptoCipherParameters> keyParam = [ivParams getParameters];
  if (keyParam == nil) {
    if (!initialised_) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", [self getAlgorithmName], @" KeyParameter can not be null for first initialisation"));
    }
    [self setKeyWithByteArray:nil withByteArray:iv];
  }
  else if ([keyParam isKindOfClass:[OrgSpongycastleCryptoParamsKeyParameter class]]) {
    [self setKeyWithByteArray:[((OrgSpongycastleCryptoParamsKeyParameter *) keyParam) getKey] withByteArray:iv];
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", [self getAlgorithmName], @" Init parameters must contain a KeyParameter (or null for re-init)"));
  }
  [self reset];
  initialised_ = true;
}

- (jint)getNonceSize {
  return 8;
}

- (NSString *)getAlgorithmName {
  NSString *name = @"Salsa20";
  if (rounds_ != OrgSpongycastleCryptoEnginesSalsa20Engine_DEFAULT_ROUNDS) {
    (void) JreStrAppendStrong(&name, "CI", '/', rounds_);
  }
  return name;
}

- (jbyte)returnByteWithByte:(jbyte)inArg {
  if (OrgSpongycastleCryptoEnginesSalsa20Engine_limitExceeded(self)) {
    @throw new_OrgSpongycastleCryptoMaxBytesExceededException_initWithNSString_(@"2^70 byte limit per IV; Change IV");
  }
  jbyte out = (jbyte) (IOSByteArray_Get(nil_chk(keyStream_), index_) ^ inArg);
  index_ = (index_ + 1) & 63;
  if (index_ == 0) {
    [self advanceCounter];
    [self generateKeyStreamWithByteArray:keyStream_];
  }
  return out;
}

- (void)advanceCounterWithLong:(jlong)diff {
  jint hi = (jint) (JreURShift64(diff, 32));
  jint lo = (jint) diff;
  if (hi > 0) {
    *IOSIntArray_GetRef(nil_chk(engineState_), 9) += hi;
  }
  jint oldState = IOSIntArray_Get(nil_chk(engineState_), 8);
  *IOSIntArray_GetRef(engineState_, 8) += lo;
  if (oldState != 0 && IOSIntArray_Get(engineState_, 8) < oldState) {
    (*IOSIntArray_GetRef(engineState_, 9))++;
  }
}

- (void)advanceCounter {
  if (++(*IOSIntArray_GetRef(nil_chk(engineState_), 8)) == 0) {
    ++(*IOSIntArray_GetRef(engineState_, 9));
  }
}

- (void)retreatCounterWithLong:(jlong)diff {
  jint hi = (jint) (JreURShift64(diff, 32));
  jint lo = (jint) diff;
  if (hi != 0) {
    if ((IOSIntArray_Get(nil_chk(engineState_), 9) & (jlong) 0xffffffffLL) >= (hi & (jlong) 0xffffffffLL)) {
      *IOSIntArray_GetRef(engineState_, 9) -= hi;
    }
    else {
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"attempt to reduce counter past zero.");
    }
  }
  if ((IOSIntArray_Get(nil_chk(engineState_), 8) & (jlong) 0xffffffffLL) >= (lo & (jlong) 0xffffffffLL)) {
    *IOSIntArray_GetRef(engineState_, 8) -= lo;
  }
  else {
    if (IOSIntArray_Get(engineState_, 9) != 0) {
      --(*IOSIntArray_GetRef(engineState_, 9));
      *IOSIntArray_GetRef(engineState_, 8) -= lo;
    }
    else {
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"attempt to reduce counter past zero.");
    }
  }
}

- (void)retreatCounter {
  if (IOSIntArray_Get(nil_chk(engineState_), 8) == 0 && IOSIntArray_Get(engineState_, 9) == 0) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"attempt to reduce counter past zero.");
  }
  if (--(*IOSIntArray_GetRef(engineState_, 8)) == -1) {
    --(*IOSIntArray_GetRef(engineState_, 9));
  }
}

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (!initialised_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", [self getAlgorithmName], @" not initialised"));
  }
  if ((inOff + len) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + len) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  if (OrgSpongycastleCryptoEnginesSalsa20Engine_limitExceededWithInt_(self, len)) {
    @throw new_OrgSpongycastleCryptoMaxBytesExceededException_initWithNSString_(@"2^70 byte limit per IV would be exceeded; Change IV");
  }
  for (jint i = 0; i < len; i++) {
    *IOSByteArray_GetRef(outArg, i + outOff) = (jbyte) (IOSByteArray_Get(nil_chk(keyStream_), index_) ^ IOSByteArray_Get(inArg, i + inOff));
    index_ = (index_ + 1) & 63;
    if (index_ == 0) {
      [self advanceCounter];
      [self generateKeyStreamWithByteArray:keyStream_];
    }
  }
  return len;
}

- (jlong)skipWithLong:(jlong)numberOfBytes {
  if (numberOfBytes >= 0) {
    jlong remaining = numberOfBytes;
    if (remaining >= 64) {
      jlong count = remaining / 64;
      [self advanceCounterWithLong:count];
      remaining -= count * 64;
    }
    jint oldIndex = index_;
    index_ = (index_ + (jint) remaining) & 63;
    if (index_ < oldIndex) {
      [self advanceCounter];
    }
  }
  else {
    jlong remaining = -numberOfBytes;
    if (remaining >= 64) {
      jlong count = remaining / 64;
      [self retreatCounterWithLong:count];
      remaining -= count * 64;
    }
    for (jlong i = 0; i < remaining; i++) {
      if (index_ == 0) {
        [self retreatCounter];
      }
      index_ = (index_ - 1) & 63;
    }
  }
  [self generateKeyStreamWithByteArray:keyStream_];
  return numberOfBytes;
}

- (jlong)seekToWithLong:(jlong)position {
  [self reset];
  return [self skipWithLong:position];
}

- (jlong)getPosition {
  return [self getCounter] * 64 + index_;
}

- (void)reset {
  index_ = 0;
  OrgSpongycastleCryptoEnginesSalsa20Engine_resetLimitCounter(self);
  [self resetCounter];
  [self generateKeyStreamWithByteArray:keyStream_];
}

- (jlong)getCounter {
  return (JreLShift64((jlong) IOSIntArray_Get(nil_chk(engineState_), 9), 32)) | (IOSIntArray_Get(engineState_, 8) & (jlong) 0xffffffffLL);
}

- (void)resetCounter {
  *IOSIntArray_GetRef(nil_chk(engineState_), 8) = *IOSIntArray_GetRef(engineState_, 9) = 0;
}

- (void)setKeyWithByteArray:(IOSByteArray *)keyBytes
              withByteArray:(IOSByteArray *)ivBytes {
  if (keyBytes != nil) {
    if ((keyBytes->size_ != 16) && (keyBytes->size_ != 32)) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", [self getAlgorithmName], @" requires 128 bit or 256 bit key"));
    }
    jint tsOff = (keyBytes->size_ - 16) / 4;
    *IOSIntArray_GetRef(nil_chk(engineState_), 0) = IOSIntArray_Get(nil_chk(OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA), tsOff);
    *IOSIntArray_GetRef(engineState_, 5) = IOSIntArray_Get(OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA, tsOff + 1);
    *IOSIntArray_GetRef(engineState_, 10) = IOSIntArray_Get(OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA, tsOff + 2);
    *IOSIntArray_GetRef(engineState_, 15) = IOSIntArray_Get(OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA, tsOff + 3);
    OrgSpongycastleUtilPack_littleEndianToIntWithByteArray_withInt_withIntArray_withInt_withInt_(keyBytes, 0, engineState_, 1, 4);
    OrgSpongycastleUtilPack_littleEndianToIntWithByteArray_withInt_withIntArray_withInt_withInt_(keyBytes, keyBytes->size_ - 16, engineState_, 11, 4);
  }
  OrgSpongycastleUtilPack_littleEndianToIntWithByteArray_withInt_withIntArray_withInt_withInt_(ivBytes, 0, engineState_, 6, 2);
}

- (void)generateKeyStreamWithByteArray:(IOSByteArray *)output {
  OrgSpongycastleCryptoEnginesSalsa20Engine_salsaCoreWithInt_withIntArray_withIntArray_(rounds_, engineState_, x_);
  OrgSpongycastleUtilPack_intToLittleEndianWithIntArray_withByteArray_withInt_(x_, output, 0);
}

+ (void)salsaCoreWithInt:(jint)rounds
            withIntArray:(IOSIntArray *)input
            withIntArray:(IOSIntArray *)x {
  OrgSpongycastleCryptoEnginesSalsa20Engine_salsaCoreWithInt_withIntArray_withIntArray_(rounds, input, x);
}

+ (jint)rotlWithInt:(jint)x
            withInt:(jint)y {
  return OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x, y);
}

- (void)resetLimitCounter {
  OrgSpongycastleCryptoEnginesSalsa20Engine_resetLimitCounter(self);
}

- (jboolean)limitExceeded {
  return OrgSpongycastleCryptoEnginesSalsa20Engine_limitExceeded(self);
}

- (jboolean)limitExceededWithInt:(jint)len {
  return OrgSpongycastleCryptoEnginesSalsa20Engine_limitExceededWithInt_(self, len);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "B", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 9, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "J", 0x1, 12, 8, -1, -1, -1, -1 },
    { NULL, "J", 0x1, 13, 8, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 14, 15, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 16, 17, -1, -1, -1, -1 },
    { NULL, "V", 0x9, 18, 19, -1, -1, -1, -1 },
    { NULL, "I", 0xc, 20, 21, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 22, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(packTauOrSigmaWithInt:withIntArray:withInt:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(initWithInt:);
  methods[3].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[4].selector = @selector(getNonceSize);
  methods[5].selector = @selector(getAlgorithmName);
  methods[6].selector = @selector(returnByteWithByte:);
  methods[7].selector = @selector(advanceCounterWithLong:);
  methods[8].selector = @selector(advanceCounter);
  methods[9].selector = @selector(retreatCounterWithLong:);
  methods[10].selector = @selector(retreatCounter);
  methods[11].selector = @selector(processBytesWithByteArray:withInt:withInt:withByteArray:withInt:);
  methods[12].selector = @selector(skipWithLong:);
  methods[13].selector = @selector(seekToWithLong:);
  methods[14].selector = @selector(getPosition);
  methods[15].selector = @selector(reset);
  methods[16].selector = @selector(getCounter);
  methods[17].selector = @selector(resetCounter);
  methods[18].selector = @selector(setKeyWithByteArray:withByteArray:);
  methods[19].selector = @selector(generateKeyStreamWithByteArray:);
  methods[20].selector = @selector(salsaCoreWithInt:withIntArray:withIntArray:);
  methods[21].selector = @selector(rotlWithInt:withInt:);
  methods[22].selector = @selector(resetLimitCounter);
  methods[23].selector = @selector(limitExceeded);
  methods[24].selector = @selector(limitExceededWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DEFAULT_ROUNDS", "I", .constantValue.asInt = OrgSpongycastleCryptoEnginesSalsa20Engine_DEFAULT_ROUNDS, 0x19, -1, -1, -1, -1 },
    { "STATE_SIZE", "I", .constantValue.asInt = OrgSpongycastleCryptoEnginesSalsa20Engine_STATE_SIZE, 0x1a, -1, -1, -1, -1 },
    { "TAU_SIGMA", "[I", .constantValue.asLong = 0, 0x1a, -1, 23, -1, -1 },
    { "sigma", "[B", .constantValue.asLong = 0, 0x1c, -1, 24, -1, -1 },
    { "tau", "[B", .constantValue.asLong = 0, 0x1c, -1, 25, -1, -1 },
    { "rounds_", "I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "index_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "engineState_", "[I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "x_", "[I", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "keyStream_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "initialised_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cW0_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cW1_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cW2_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "packTauOrSigma", "I[II", "I", "init", "ZLOrgSpongycastleCryptoCipherParameters;", "returnByte", "B", "advanceCounter", "J", "retreatCounter", "processBytes", "[BII[BI", "skip", "seekTo", "setKey", "[B[B", "generateKeyStream", "[B", "salsaCore", "I[I[I", "rotl", "II", "limitExceeded", &OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA, &OrgSpongycastleCryptoEnginesSalsa20Engine_sigma, &OrgSpongycastleCryptoEnginesSalsa20Engine_tau };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEnginesSalsa20Engine = { "Salsa20Engine", "org.spongycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 25, 14, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoEnginesSalsa20Engine;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoEnginesSalsa20Engine class]) {
    OrgSpongycastleCryptoEnginesSalsa20Engine_TAU_SIGMA = OrgSpongycastleUtilPack_littleEndianToIntWithByteArray_withInt_withInt_(OrgSpongycastleUtilStrings_toByteArrayWithNSString_(@"expand 16-byte kexpand 32-byte k"), 0, 8);
    OrgSpongycastleCryptoEnginesSalsa20Engine_sigma = OrgSpongycastleUtilStrings_toByteArrayWithNSString_(@"expand 32-byte k");
    OrgSpongycastleCryptoEnginesSalsa20Engine_tau = OrgSpongycastleUtilStrings_toByteArrayWithNSString_(@"expand 16-byte k");
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoEnginesSalsa20Engine)
  }
}

@end

void OrgSpongycastleCryptoEnginesSalsa20Engine_init(OrgSpongycastleCryptoEnginesSalsa20Engine *self) {
  OrgSpongycastleCryptoEnginesSalsa20Engine_initWithInt_(self, OrgSpongycastleCryptoEnginesSalsa20Engine_DEFAULT_ROUNDS);
}

OrgSpongycastleCryptoEnginesSalsa20Engine *new_OrgSpongycastleCryptoEnginesSalsa20Engine_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEnginesSalsa20Engine, init)
}

OrgSpongycastleCryptoEnginesSalsa20Engine *create_OrgSpongycastleCryptoEnginesSalsa20Engine_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEnginesSalsa20Engine, init)
}

void OrgSpongycastleCryptoEnginesSalsa20Engine_initWithInt_(OrgSpongycastleCryptoEnginesSalsa20Engine *self, jint rounds) {
  NSObject_init(self);
  self->index_ = 0;
  self->engineState_ = [IOSIntArray newArrayWithLength:OrgSpongycastleCryptoEnginesSalsa20Engine_STATE_SIZE];
  self->x_ = [IOSIntArray newArrayWithLength:OrgSpongycastleCryptoEnginesSalsa20Engine_STATE_SIZE];
  self->keyStream_ = [IOSByteArray newArrayWithLength:OrgSpongycastleCryptoEnginesSalsa20Engine_STATE_SIZE * 4];
  self->initialised_ = false;
  if (rounds <= 0 || (rounds & 1) != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'rounds' must be a positive, even number");
  }
  self->rounds_ = rounds;
}

OrgSpongycastleCryptoEnginesSalsa20Engine *new_OrgSpongycastleCryptoEnginesSalsa20Engine_initWithInt_(jint rounds) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEnginesSalsa20Engine, initWithInt_, rounds)
}

OrgSpongycastleCryptoEnginesSalsa20Engine *create_OrgSpongycastleCryptoEnginesSalsa20Engine_initWithInt_(jint rounds) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEnginesSalsa20Engine, initWithInt_, rounds)
}

void OrgSpongycastleCryptoEnginesSalsa20Engine_salsaCoreWithInt_withIntArray_withIntArray_(jint rounds, IOSIntArray *input, IOSIntArray *x) {
  OrgSpongycastleCryptoEnginesSalsa20Engine_initialize();
  if (((IOSIntArray *) nil_chk(input))->size_ != 16) {
    @throw new_JavaLangIllegalArgumentException_init();
  }
  if (((IOSIntArray *) nil_chk(x))->size_ != 16) {
    @throw new_JavaLangIllegalArgumentException_init();
  }
  if (rounds % 2 != 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Number of rounds must be even");
  }
  jint x00 = IOSIntArray_Get(input, 0);
  jint x01 = IOSIntArray_Get(input, 1);
  jint x02 = IOSIntArray_Get(input, 2);
  jint x03 = IOSIntArray_Get(input, 3);
  jint x04 = IOSIntArray_Get(input, 4);
  jint x05 = IOSIntArray_Get(input, 5);
  jint x06 = IOSIntArray_Get(input, 6);
  jint x07 = IOSIntArray_Get(input, 7);
  jint x08 = IOSIntArray_Get(input, 8);
  jint x09 = IOSIntArray_Get(input, 9);
  jint x10 = IOSIntArray_Get(input, 10);
  jint x11 = IOSIntArray_Get(input, 11);
  jint x12 = IOSIntArray_Get(input, 12);
  jint x13 = IOSIntArray_Get(input, 13);
  jint x14 = IOSIntArray_Get(input, 14);
  jint x15 = IOSIntArray_Get(input, 15);
  for (jint i = rounds; i > 0; i -= 2) {
    x04 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x00 + x12, 7);
    x08 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x04 + x00, 9);
    x12 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x08 + x04, 13);
    x00 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x12 + x08, 18);
    x09 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x05 + x01, 7);
    x13 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x09 + x05, 9);
    x01 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x13 + x09, 13);
    x05 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x01 + x13, 18);
    x14 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x10 + x06, 7);
    x02 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x14 + x10, 9);
    x06 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x02 + x14, 13);
    x10 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x06 + x02, 18);
    x03 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x15 + x11, 7);
    x07 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x03 + x15, 9);
    x11 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x07 + x03, 13);
    x15 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x11 + x07, 18);
    x01 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x00 + x03, 7);
    x02 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x01 + x00, 9);
    x03 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x02 + x01, 13);
    x00 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x03 + x02, 18);
    x06 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x05 + x04, 7);
    x07 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x06 + x05, 9);
    x04 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x07 + x06, 13);
    x05 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x04 + x07, 18);
    x11 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x10 + x09, 7);
    x08 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x11 + x10, 9);
    x09 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x08 + x11, 13);
    x10 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x09 + x08, 18);
    x12 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x15 + x14, 7);
    x13 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x12 + x15, 9);
    x14 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x13 + x12, 13);
    x15 ^= OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(x14 + x13, 18);
  }
  *IOSIntArray_GetRef(x, 0) = x00 + IOSIntArray_Get(input, 0);
  *IOSIntArray_GetRef(x, 1) = x01 + IOSIntArray_Get(input, 1);
  *IOSIntArray_GetRef(x, 2) = x02 + IOSIntArray_Get(input, 2);
  *IOSIntArray_GetRef(x, 3) = x03 + IOSIntArray_Get(input, 3);
  *IOSIntArray_GetRef(x, 4) = x04 + IOSIntArray_Get(input, 4);
  *IOSIntArray_GetRef(x, 5) = x05 + IOSIntArray_Get(input, 5);
  *IOSIntArray_GetRef(x, 6) = x06 + IOSIntArray_Get(input, 6);
  *IOSIntArray_GetRef(x, 7) = x07 + IOSIntArray_Get(input, 7);
  *IOSIntArray_GetRef(x, 8) = x08 + IOSIntArray_Get(input, 8);
  *IOSIntArray_GetRef(x, 9) = x09 + IOSIntArray_Get(input, 9);
  *IOSIntArray_GetRef(x, 10) = x10 + IOSIntArray_Get(input, 10);
  *IOSIntArray_GetRef(x, 11) = x11 + IOSIntArray_Get(input, 11);
  *IOSIntArray_GetRef(x, 12) = x12 + IOSIntArray_Get(input, 12);
  *IOSIntArray_GetRef(x, 13) = x13 + IOSIntArray_Get(input, 13);
  *IOSIntArray_GetRef(x, 14) = x14 + IOSIntArray_Get(input, 14);
  *IOSIntArray_GetRef(x, 15) = x15 + IOSIntArray_Get(input, 15);
}

jint OrgSpongycastleCryptoEnginesSalsa20Engine_rotlWithInt_withInt_(jint x, jint y) {
  OrgSpongycastleCryptoEnginesSalsa20Engine_initialize();
  return (JreLShift32(x, y)) | (JreURShift32(x, -y));
}

void OrgSpongycastleCryptoEnginesSalsa20Engine_resetLimitCounter(OrgSpongycastleCryptoEnginesSalsa20Engine *self) {
  self->cW0_ = 0;
  self->cW1_ = 0;
  self->cW2_ = 0;
}

jboolean OrgSpongycastleCryptoEnginesSalsa20Engine_limitExceeded(OrgSpongycastleCryptoEnginesSalsa20Engine *self) {
  if (++self->cW0_ == 0) {
    if (++self->cW1_ == 0) {
      return (++self->cW2_ & (jint) 0x20) != 0;
    }
  }
  return false;
}

jboolean OrgSpongycastleCryptoEnginesSalsa20Engine_limitExceededWithInt_(OrgSpongycastleCryptoEnginesSalsa20Engine *self, jint len) {
  self->cW0_ += len;
  if (self->cW0_ < len && self->cW0_ >= 0) {
    if (++self->cW1_ == 0) {
      return (++self->cW2_ & (jint) 0x20) != 0;
    }
  }
  return false;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoEnginesSalsa20Engine)