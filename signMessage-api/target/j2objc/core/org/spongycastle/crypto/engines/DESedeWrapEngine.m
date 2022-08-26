//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/DESedeWrapEngine.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/InvalidCipherTextException.h"
#include "org/spongycastle/crypto/engines/DESedeEngine.h"
#include "org/spongycastle/crypto/engines/DESedeWrapEngine.h"
#include "org/spongycastle/crypto/modes/CBCBlockCipher.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"
#include "org/spongycastle/crypto/params/ParametersWithIV.h"
#include "org/spongycastle/crypto/params/ParametersWithRandom.h"
#include "org/spongycastle/crypto/util/DigestFactory.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleCryptoEnginesDESedeWrapEngine () {
 @public
  OrgSpongycastleCryptoModesCBCBlockCipher *engine_;
  OrgSpongycastleCryptoParamsKeyParameter *param_;
  OrgSpongycastleCryptoParamsParametersWithIV *paramPlusIV_;
  IOSByteArray *iv_;
  jboolean forWrapping_;
}

- (IOSByteArray *)calculateCMSKeyChecksumWithByteArray:(IOSByteArray *)key;

- (jboolean)checkCMSKeyChecksumWithByteArray:(IOSByteArray *)key
                               withByteArray:(IOSByteArray *)checksum;

+ (IOSByteArray *)reverseWithByteArray:(IOSByteArray *)bs;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeWrapEngine, engine_, OrgSpongycastleCryptoModesCBCBlockCipher *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeWrapEngine, param_, OrgSpongycastleCryptoParamsKeyParameter *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeWrapEngine, paramPlusIV_, OrgSpongycastleCryptoParamsParametersWithIV *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeWrapEngine, iv_, IOSByteArray *)

inline IOSByteArray *OrgSpongycastleCryptoEnginesDESedeWrapEngine_get_IV2(void);
static IOSByteArray *OrgSpongycastleCryptoEnginesDESedeWrapEngine_IV2;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoEnginesDESedeWrapEngine, IV2, IOSByteArray *)

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEnginesDESedeWrapEngine_calculateCMSKeyChecksumWithByteArray_(OrgSpongycastleCryptoEnginesDESedeWrapEngine *self, IOSByteArray *key);

__attribute__((unused)) static jboolean OrgSpongycastleCryptoEnginesDESedeWrapEngine_checkCMSKeyChecksumWithByteArray_withByteArray_(OrgSpongycastleCryptoEnginesDESedeWrapEngine *self, IOSByteArray *key, IOSByteArray *checksum);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoEnginesDESedeWrapEngine_reverseWithByteArray_(IOSByteArray *bs);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoEnginesDESedeWrapEngine)

@implementation OrgSpongycastleCryptoEnginesDESedeWrapEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoEnginesDESedeWrapEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forWrapping
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param {
  self->forWrapping_ = forWrapping;
  self->engine_ = new_OrgSpongycastleCryptoModesCBCBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(new_OrgSpongycastleCryptoEnginesDESedeEngine_init());
  JavaSecuritySecureRandom *sr;
  if ([param isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithRandom class]]) {
    OrgSpongycastleCryptoParamsParametersWithRandom *pr = (OrgSpongycastleCryptoParamsParametersWithRandom *) param;
    param = [((OrgSpongycastleCryptoParamsParametersWithRandom *) nil_chk(pr)) getParameters];
    sr = [pr getRandom];
  }
  else {
    sr = new_JavaSecuritySecureRandom_init();
  }
  if ([param isKindOfClass:[OrgSpongycastleCryptoParamsKeyParameter class]]) {
    self->param_ = (OrgSpongycastleCryptoParamsKeyParameter *) param;
    if (self->forWrapping_) {
      self->iv_ = [IOSByteArray newArrayWithLength:8];
      [((JavaSecuritySecureRandom *) nil_chk(sr)) nextBytesWithByteArray:iv_];
      self->paramPlusIV_ = new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(self->param_, self->iv_);
    }
  }
  else if ([param isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithIV class]]) {
    self->paramPlusIV_ = (OrgSpongycastleCryptoParamsParametersWithIV *) param;
    self->iv_ = [((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(self->paramPlusIV_)) getIV];
    self->param_ = (OrgSpongycastleCryptoParamsKeyParameter *) cast_chk([((OrgSpongycastleCryptoParamsParametersWithIV *) nil_chk(self->paramPlusIV_)) getParameters], [OrgSpongycastleCryptoParamsKeyParameter class]);
    if (self->forWrapping_) {
      if ((self->iv_ == nil) || (((IOSByteArray *) nil_chk(self->iv_))->size_ != 8)) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"IV is not 8 octets");
      }
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"You should not supply an IV for unwrapping");
    }
  }
}

- (NSString *)getAlgorithmName {
  return @"DESede";
}

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                            withInt:(jint)inLen {
  if (!forWrapping_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Not initialized for wrapping");
  }
  IOSByteArray *keyToBeWrapped = [IOSByteArray newArrayWithLength:inLen];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, keyToBeWrapped, 0, inLen);
  IOSByteArray *CKS = OrgSpongycastleCryptoEnginesDESedeWrapEngine_calculateCMSKeyChecksumWithByteArray_(self, keyToBeWrapped);
  IOSByteArray *WKCKS = [IOSByteArray newArrayWithLength:keyToBeWrapped->size_ + ((IOSByteArray *) nil_chk(CKS))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(keyToBeWrapped, 0, WKCKS, 0, keyToBeWrapped->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(CKS, 0, WKCKS, keyToBeWrapped->size_, CKS->size_);
  jint blockSize = [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize];
  if (WKCKS->size_ % blockSize != 0) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Not multiple of block length");
  }
  [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:paramPlusIV_];
  IOSByteArray *TEMP1 = [IOSByteArray newArrayWithLength:WKCKS->size_];
  for (jint currentBytePos = 0; currentBytePos != WKCKS->size_; currentBytePos += blockSize) {
    [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) processBlockWithByteArray:WKCKS withInt:currentBytePos withByteArray:TEMP1 withInt:currentBytePos];
  }
  IOSByteArray *TEMP2 = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(self->iv_))->size_ + TEMP1->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->iv_, 0, TEMP2, 0, self->iv_->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(TEMP1, 0, TEMP2, ((IOSByteArray *) nil_chk(self->iv_))->size_, TEMP1->size_);
  IOSByteArray *TEMP3 = OrgSpongycastleCryptoEnginesDESedeWrapEngine_reverseWithByteArray_(TEMP2);
  OrgSpongycastleCryptoParamsParametersWithIV *param2 = new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(self->param_, OrgSpongycastleCryptoEnginesDESedeWrapEngine_IV2);
  [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(self->engine_)) init__WithBoolean:true withOrgSpongycastleCryptoCipherParameters:param2];
  for (jint currentBytePos = 0; currentBytePos != ((IOSByteArray *) nil_chk(TEMP3))->size_; currentBytePos += blockSize) {
    [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) processBlockWithByteArray:TEMP3 withInt:currentBytePos withByteArray:TEMP3 withInt:currentBytePos];
  }
  return TEMP3;
}

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)inArg
                              withInt:(jint)inOff
                              withInt:(jint)inLen {
  if (forWrapping_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Not set for unwrapping");
  }
  if (inArg == nil) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"Null pointer as ciphertext");
  }
  jint blockSize = [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) getBlockSize];
  if (inLen % blockSize != 0) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(JreStrcat("$I", @"Ciphertext not multiple of ", blockSize));
  }
  OrgSpongycastleCryptoParamsParametersWithIV *param2 = new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(self->param_, OrgSpongycastleCryptoEnginesDESedeWrapEngine_IV2);
  [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(self->engine_)) init__WithBoolean:false withOrgSpongycastleCryptoCipherParameters:param2];
  IOSByteArray *TEMP3 = [IOSByteArray newArrayWithLength:inLen];
  for (jint currentBytePos = 0; currentBytePos != inLen; currentBytePos += blockSize) {
    [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) processBlockWithByteArray:inArg withInt:inOff + currentBytePos withByteArray:TEMP3 withInt:currentBytePos];
  }
  IOSByteArray *TEMP2 = OrgSpongycastleCryptoEnginesDESedeWrapEngine_reverseWithByteArray_(TEMP3);
  self->iv_ = [IOSByteArray newArrayWithLength:8];
  IOSByteArray *TEMP1 = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(TEMP2))->size_ - 8];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(TEMP2, 0, self->iv_, 0, 8);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(TEMP2, 8, TEMP1, 0, TEMP2->size_ - 8);
  self->paramPlusIV_ = new_OrgSpongycastleCryptoParamsParametersWithIV_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(self->param_, self->iv_);
  [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(self->engine_)) init__WithBoolean:false withOrgSpongycastleCryptoCipherParameters:self->paramPlusIV_];
  IOSByteArray *WKCKS = [IOSByteArray newArrayWithLength:TEMP1->size_];
  for (jint currentBytePos = 0; currentBytePos != WKCKS->size_; currentBytePos += blockSize) {
    [((OrgSpongycastleCryptoModesCBCBlockCipher *) nil_chk(engine_)) processBlockWithByteArray:TEMP1 withInt:currentBytePos withByteArray:WKCKS withInt:currentBytePos];
  }
  IOSByteArray *result = [IOSByteArray newArrayWithLength:WKCKS->size_ - 8];
  IOSByteArray *CKStoBeVerified = [IOSByteArray newArrayWithLength:8];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(WKCKS, 0, result, 0, WKCKS->size_ - 8);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(WKCKS, WKCKS->size_ - 8, CKStoBeVerified, 0, 8);
  if (!OrgSpongycastleCryptoEnginesDESedeWrapEngine_checkCMSKeyChecksumWithByteArray_withByteArray_(self, result, CKStoBeVerified)) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"Checksum inside ciphertext is corrupted");
  }
  return result;
}

- (IOSByteArray *)calculateCMSKeyChecksumWithByteArray:(IOSByteArray *)key {
  return OrgSpongycastleCryptoEnginesDESedeWrapEngine_calculateCMSKeyChecksumWithByteArray_(self, key);
}

- (jboolean)checkCMSKeyChecksumWithByteArray:(IOSByteArray *)key
                               withByteArray:(IOSByteArray *)checksum {
  return OrgSpongycastleCryptoEnginesDESedeWrapEngine_checkCMSKeyChecksumWithByteArray_withByteArray_(self, key, checksum);
}

+ (IOSByteArray *)reverseWithByteArray:(IOSByteArray *)bs {
  return OrgSpongycastleCryptoEnginesDESedeWrapEngine_reverseWithByteArray_(bs);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 4, 3, 5, -1, -1, -1 },
    { NULL, "[B", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "[B", 0xa, 10, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getAlgorithmName);
  methods[3].selector = @selector(wrapWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(unwrapWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(calculateCMSKeyChecksumWithByteArray:);
  methods[6].selector = @selector(checkCMSKeyChecksumWithByteArray:withByteArray:);
  methods[7].selector = @selector(reverseWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "engine_", "LOrgSpongycastleCryptoModesCBCBlockCipher;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "param_", "LOrgSpongycastleCryptoParamsKeyParameter;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "paramPlusIV_", "LOrgSpongycastleCryptoParamsParametersWithIV;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "iv_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forWrapping_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "IV2", "[B", .constantValue.asLong = 0, 0x1a, -1, 11, -1, -1 },
    { "sha1_", "LOrgSpongycastleCryptoDigest;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "digest_", "[B", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLOrgSpongycastleCryptoCipherParameters;", "wrap", "[BII", "unwrap", "LOrgSpongycastleCryptoInvalidCipherTextException;", "calculateCMSKeyChecksum", "[B", "checkCMSKeyChecksum", "[B[B", "reverse", &OrgSpongycastleCryptoEnginesDESedeWrapEngine_IV2 };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoEnginesDESedeWrapEngine = { "DESedeWrapEngine", "org.spongycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 8, 8, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoEnginesDESedeWrapEngine;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoEnginesDESedeWrapEngine class]) {
    OrgSpongycastleCryptoEnginesDESedeWrapEngine_IV2 = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) (jint) 0x4a, (jbyte) (jint) 0xdd, (jbyte) (jint) 0xa2, (jbyte) (jint) 0x2c, (jbyte) (jint) 0x79, (jbyte) (jint) 0xe8, (jbyte) (jint) 0x21, (jbyte) (jint) 0x05 } count:8];
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoEnginesDESedeWrapEngine)
  }
}

@end

void OrgSpongycastleCryptoEnginesDESedeWrapEngine_init(OrgSpongycastleCryptoEnginesDESedeWrapEngine *self) {
  NSObject_init(self);
  self->sha1_ = OrgSpongycastleCryptoUtilDigestFactory_createSHA1();
  self->digest_ = [IOSByteArray newArrayWithLength:20];
}

OrgSpongycastleCryptoEnginesDESedeWrapEngine *new_OrgSpongycastleCryptoEnginesDESedeWrapEngine_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoEnginesDESedeWrapEngine, init)
}

OrgSpongycastleCryptoEnginesDESedeWrapEngine *create_OrgSpongycastleCryptoEnginesDESedeWrapEngine_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoEnginesDESedeWrapEngine, init)
}

IOSByteArray *OrgSpongycastleCryptoEnginesDESedeWrapEngine_calculateCMSKeyChecksumWithByteArray_(OrgSpongycastleCryptoEnginesDESedeWrapEngine *self, IOSByteArray *key) {
  IOSByteArray *result = [IOSByteArray newArrayWithLength:8];
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->sha1_)) updateWithByteArray:key withInt:0 withInt:((IOSByteArray *) nil_chk(key))->size_];
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(self->sha1_)) doFinalWithByteArray:self->digest_ withInt:0];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->digest_, 0, result, 0, 8);
  return result;
}

jboolean OrgSpongycastleCryptoEnginesDESedeWrapEngine_checkCMSKeyChecksumWithByteArray_withByteArray_(OrgSpongycastleCryptoEnginesDESedeWrapEngine *self, IOSByteArray *key, IOSByteArray *checksum) {
  return OrgSpongycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(OrgSpongycastleCryptoEnginesDESedeWrapEngine_calculateCMSKeyChecksumWithByteArray_(self, key), checksum);
}

IOSByteArray *OrgSpongycastleCryptoEnginesDESedeWrapEngine_reverseWithByteArray_(IOSByteArray *bs) {
  OrgSpongycastleCryptoEnginesDESedeWrapEngine_initialize();
  IOSByteArray *result = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(bs))->size_];
  for (jint i = 0; i < bs->size_; i++) {
    *IOSByteArray_GetRef(result, i) = IOSByteArray_Get(bs, bs->size_ - (i + 1));
  }
  return result;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoEnginesDESedeWrapEngine)
