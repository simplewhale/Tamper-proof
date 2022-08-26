//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/DESedeEngine.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/DataLengthException.h"
#include "org/spongycastle/crypto/OutputLengthException.h"
#include "org/spongycastle/crypto/engines/DESEngine.h"
#include "org/spongycastle/crypto/engines/DESedeEngine.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"

@interface OrgSpongycastleCryptoEnginesDESedeEngine () {
 @public
  IOSIntArray *workingKey1_;
  IOSIntArray *workingKey2_;
  IOSIntArray *workingKey3_;
  jboolean forEncryption_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeEngine, workingKey1_, IOSIntArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeEngine, workingKey2_, IOSIntArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeEngine, workingKey3_, IOSIntArray *)

@implementation OrgSpongycastleCryptoEnginesDESedeEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoEnginesDESedeEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)encrypting
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  if (!([params isKindOfClass:[OrgSpongycastleCryptoParamsKeyParameter class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"invalid parameter passed to DESede init - ", [[((id<OrgSpongycastleCryptoCipherParameters>) nil_chk(params)) java_getClass] getName]));
  }
  IOSByteArray *keyMaster = [((OrgSpongycastleCryptoParamsKeyParameter *) nil_chk(((OrgSpongycastleCryptoParamsKeyParameter *) cast_chk(params, [OrgSpongycastleCryptoParamsKeyParameter class])))) getKey];
  if (((IOSByteArray *) nil_chk(keyMaster))->size_ != 24 && keyMaster->size_ != 16) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key size must be 16 or 24 bytes.");
  }
  self->forEncryption_ = encrypting;
  IOSByteArray *key1 = [IOSByteArray newArrayWithLength:8];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(keyMaster, 0, key1, 0, key1->size_);
  workingKey1_ = [self generateWorkingKeyWithBoolean:encrypting withByteArray:key1];
  IOSByteArray *key2 = [IOSByteArray newArrayWithLength:8];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(keyMaster, 8, key2, 0, key2->size_);
  workingKey2_ = [self generateWorkingKeyWithBoolean:!encrypting withByteArray:key2];
  if (keyMaster->size_ == 24) {
    IOSByteArray *key3 = [IOSByteArray newArrayWithLength:8];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(keyMaster, 16, key3, 0, key3->size_);
    workingKey3_ = [self generateWorkingKeyWithBoolean:encrypting withByteArray:key3];
  }
  else {
    workingKey3_ = workingKey1_;
  }
}

- (NSString *)getAlgorithmName {
  return @"DESede";
}

- (jint)getBlockSize {
  return OrgSpongycastleCryptoEnginesDESedeEngine_BLOCK_SIZE;
}

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (workingKey1_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"DESede engine not initialised");
  }
  if ((inOff + OrgSpongycastleCryptoEnginesDESedeEngine_BLOCK_SIZE) > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too short");
  }
  if ((outOff + OrgSpongycastleCryptoEnginesDESedeEngine_BLOCK_SIZE) > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  IOSByteArray *temp = [IOSByteArray newArrayWithLength:OrgSpongycastleCryptoEnginesDESedeEngine_BLOCK_SIZE];
  if (forEncryption_) {
    [self desFuncWithIntArray:workingKey1_ withByteArray:inArg withInt:inOff withByteArray:temp withInt:0];
    [self desFuncWithIntArray:workingKey2_ withByteArray:temp withInt:0 withByteArray:temp withInt:0];
    [self desFuncWithIntArray:workingKey3_ withByteArray:temp withInt:0 withByteArray:outArg withInt:outOff];
  }
  else {
    [self desFuncWithIntArray:workingKey3_ withByteArray:inArg withInt:inOff withByteArray:temp withInt:0];
    [self desFuncWithIntArray:workingKey2_ withByteArray:temp withInt:0 withByteArray:temp withInt:0];
    [self desFuncWithIntArray:workingKey1_ withByteArray:temp withInt:0 withByteArray:outArg withInt:outOff];
  }
  return OrgSpongycastleCryptoEnginesDESedeEngine_BLOCK_SIZE;
}

- (void)reset {
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(getBlockSize);
  methods[4].selector = @selector(processBlockWithByteArray:withInt:withByteArray:withInt:);
  methods[5].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BLOCK_SIZE", "I", .constantValue.asInt = OrgSpongycastleCryptoEnginesDESedeEngine_BLOCK_SIZE, 0x1c, -1, -1, -1, -1 },
    { "workingKey1_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "workingKey2_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "workingKey3_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLOrgSpongycastleCryptoCipherParameters;", "processBlock", "[BI[BI" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEnginesDESedeEngine = { "DESedeEngine", "org.spongycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 6, 5, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoEnginesDESedeEngine;
}

@end

void OrgSpongycastleCryptoEnginesDESedeEngine_init(OrgSpongycastleCryptoEnginesDESedeEngine *self) {
  OrgSpongycastleCryptoEnginesDESEngine_init(self);
  self->workingKey1_ = nil;
  self->workingKey2_ = nil;
  self->workingKey3_ = nil;
}

OrgSpongycastleCryptoEnginesDESedeEngine *new_OrgSpongycastleCryptoEnginesDESedeEngine_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEnginesDESedeEngine, init)
}

OrgSpongycastleCryptoEnginesDESedeEngine *create_OrgSpongycastleCryptoEnginesDESedeEngine_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEnginesDESedeEngine, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoEnginesDESedeEngine)
