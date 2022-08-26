//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/modes/KCTRBlockCipher.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/BlockCipher.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/DataLengthException.h"
#include "org/spongycastle/crypto/OutputLengthException.h"
#include "org/spongycastle/crypto/StreamBlockCipher.h"
#include "org/spongycastle/crypto/modes/KCTRBlockCipher.h"
#include "org/spongycastle/crypto/params/ParametersWithIV.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleCryptoModesKCTRBlockCipher () {
 @public
  IOSByteArray *iv_;
  IOSByteArray *ofbV_;
  IOSByteArray *ofbOutV_;
  jint byteCount_;
  jboolean initialised_;
  id<OrgSpongycastleCryptoBlockCipher> engine_;
}

- (void)incrementCounterAtWithInt:(jint)pos;

- (void)checkCounter;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesKCTRBlockCipher, iv_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesKCTRBlockCipher, ofbV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesKCTRBlockCipher, ofbOutV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoModesKCTRBlockCipher, engine_, id<OrgSpongycastleCryptoBlockCipher>)

__attribute__((unused)) static void OrgSpongycastleCryptoModesKCTRBlockCipher_incrementCounterAtWithInt_(OrgSpongycastleCryptoModesKCTRBlockCipher *self, jint pos);

__attribute__((unused)) static void OrgSpongycastleCryptoModesKCTRBlockCipher_checkCounter(OrgSpongycastleCryptoModesKCTRBlockCipher *self);

@implementation OrgSpongycastleCryptoModesKCTRBlockCipher

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)engine {
  OrgSpongycastleCryptoModesKCTRBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(self, engine);
  return self;
}

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  self->initialised_ = true;
  if ([params isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithIV class]]) {
    OrgSpongycastleCryptoParamsParametersWithIV *ivParam = (OrgSpongycastleCryptoParamsParametersWithIV *) params;
    IOSByteArray *iv = [((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(ivParam)) getIV];
    jint diff = ((IOSByteArray *) nil_chk(self->iv_))->size_ - ((IOSByteArray *) nil_chk(iv))->size_;
    OrgSpongycastleUtilArrays_fillWithByteArray_withByte_(self->iv_, (jbyte) 0);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(iv, 0, self->iv_, diff, iv->size_);
    params = [ivParam getParameters];
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid parameter passed");
  }
  if (params != nil) {
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:params];
  }
  [self reset];
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) getAlgorithmName], @"/KCTR");
}

- (jint)getBlockSize {
  return [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) getBlockSize];
}

- (jbyte)calculateByteWithByte:(jbyte)b {
  if (byteCount_ == 0) {
    OrgSpongycastleCryptoModesKCTRBlockCipher_incrementCounterAtWithInt_(self, 0);
    OrgSpongycastleCryptoModesKCTRBlockCipher_checkCounter(self);
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:ofbV_ withInt:0 withByteArray:ofbOutV_ withInt:0];
    return (jbyte) (IOSByteArray_Get(nil_chk(ofbOutV_), byteCount_++) ^ b);
  }
  jbyte rv = (jbyte) (IOSByteArray_Get(nil_chk(ofbOutV_), byteCount_++) ^ b);
  if (byteCount_ == ((IOSByteArray *) nil_chk(ofbV_))->size_) {
    byteCount_ = 0;
  }
  return rv;
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (((IOSByteArray *) nil_chk(inArg))->size_ - inOff < [self getBlockSize]) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if (((IOSByteArray *) nil_chk(outArg))->size_ - outOff < [self getBlockSize]) {
    @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  [self processBytesWithByteArray:inArg withInt:inOff withInt:[self getBlockSize] withByteArray:outArg withInt:outOff];
  return [self getBlockSize];
}

- (void)reset {
  if (initialised_) {
    [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) processBlockWithByteArray:self->iv_ withInt:0 withByteArray:ofbV_ withInt:0];
  }
  [((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine_)) reset];
  byteCount_ = 0;
}

- (void)incrementCounterAtWithInt:(jint)pos {
  OrgSpongycastleCryptoModesKCTRBlockCipher_incrementCounterAtWithInt_(self, pos);
}

- (void)checkCounter {
  OrgSpongycastleCryptoModesKCTRBlockCipher_checkCounter(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "B", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, 7, 8, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoBlockCipher:);
  methods[1].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getBlockSize);
  methods[4].selector = @selector(calculateByteWithByte:);
  methods[5].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[6].selector = @selector(reset);
  methods[7].selector = @selector(incrementCounterAtWithInt:);
  methods[8].selector = @selector(checkCounter);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ofbV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ofbOutV_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "byteCount_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "initialised_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "engine_", "LOrgSpongycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoBlockCipher;", "init", "ZLOrgSpongycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "calculateByte", "B", "processBlock", "[BI[BI", "LOrgSpongycastleCryptoDataLengthException;LJavaLangIllegalStateException;", "incrementCounterAt", "I" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoModesKCTRBlockCipher = { "KCTRBlockCipher", "org.spongycastle.crypto.modes", ptrTable, methods, fields, 7, 0x1, 9, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoModesKCTRBlockCipher;
}

@end

void OrgSpongycastleCryptoModesKCTRBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(OrgSpongycastleCryptoModesKCTRBlockCipher *self, id<OrgSpongycastleCryptoBlockCipher> engine) {
  OrgSpongycastleCryptoStreamBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(self, engine);
  self->engine_ = engine;
  self->iv_ = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoBlockCipher>) nil_chk(engine)) getBlockSize]];
  self->ofbV_ = [IOSByteArray newArrayWithLength:[engine getBlockSize]];
  self->ofbOutV_ = [IOSByteArray newArrayWithLength:[engine getBlockSize]];
}

OrgSpongycastleCryptoModesKCTRBlockCipher *new_OrgSpongycastleCryptoModesKCTRBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(id<OrgSpongycastleCryptoBlockCipher> engine) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoModesKCTRBlockCipher, initWithOrgSpongycastleCryptoBlockCipher_, engine)
}

OrgSpongycastleCryptoModesKCTRBlockCipher *create_OrgSpongycastleCryptoModesKCTRBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(id<OrgSpongycastleCryptoBlockCipher> engine) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoModesKCTRBlockCipher, initWithOrgSpongycastleCryptoBlockCipher_, engine)
}

void OrgSpongycastleCryptoModesKCTRBlockCipher_incrementCounterAtWithInt_(OrgSpongycastleCryptoModesKCTRBlockCipher *self, jint pos) {
  jint i = pos;
  while (i < ((IOSByteArray *) nil_chk(self->ofbV_))->size_) {
    if (++(*IOSByteArray_GetRef(self->ofbV_, i++)) != 0) {
      break;
    }
  }
}

void OrgSpongycastleCryptoModesKCTRBlockCipher_checkCounter(OrgSpongycastleCryptoModesKCTRBlockCipher *self) {
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoModesKCTRBlockCipher)