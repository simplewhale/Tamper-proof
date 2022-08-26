//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/macs/HMac.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/lang/System.h"
#include "java/util/Hashtable.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/ExtendedDigest.h"
#include "org/spongycastle/crypto/macs/HMac.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"
#include "org/spongycastle/util/Integers.h"
#include "org/spongycastle/util/Memoable.h"

@interface OrgSpongycastleCryptoMacsHMac () {
 @public
  id<OrgSpongycastleCryptoDigest> digest_;
  jint digestSize_;
  jint blockLength_;
  id<OrgSpongycastleUtilMemoable> ipadState_;
  id<OrgSpongycastleUtilMemoable> opadState_;
  IOSByteArray *inputPad_;
  IOSByteArray *outputBuf_;
}

+ (jint)getByteLengthWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest;

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                            withInt:(jint)byteLength;

+ (void)xorPadWithByteArray:(IOSByteArray *)pad
                    withInt:(jint)len
                   withByte:(jbyte)n;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsHMac, digest_, id<OrgSpongycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsHMac, ipadState_, id<OrgSpongycastleUtilMemoable>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsHMac, opadState_, id<OrgSpongycastleUtilMemoable>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsHMac, inputPad_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoMacsHMac, outputBuf_, IOSByteArray *)

inline jbyte OrgSpongycastleCryptoMacsHMac_get_IPAD(void);
#define OrgSpongycastleCryptoMacsHMac_IPAD 54
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoMacsHMac, IPAD, jbyte)

inline jbyte OrgSpongycastleCryptoMacsHMac_get_OPAD(void);
#define OrgSpongycastleCryptoMacsHMac_OPAD 92
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoMacsHMac, OPAD, jbyte)

inline JavaUtilHashtable *OrgSpongycastleCryptoMacsHMac_get_blockLengths(void);
inline JavaUtilHashtable *OrgSpongycastleCryptoMacsHMac_set_blockLengths(JavaUtilHashtable *value);
static JavaUtilHashtable *OrgSpongycastleCryptoMacsHMac_blockLengths;
J2OBJC_STATIC_FIELD_OBJ(OrgSpongycastleCryptoMacsHMac, blockLengths, JavaUtilHashtable *)

__attribute__((unused)) static jint OrgSpongycastleCryptoMacsHMac_getByteLengthWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest);

__attribute__((unused)) static void OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_withInt_(OrgSpongycastleCryptoMacsHMac *self, id<OrgSpongycastleCryptoDigest> digest, jint byteLength);

__attribute__((unused)) static OrgSpongycastleCryptoMacsHMac *new_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_withInt_(id<OrgSpongycastleCryptoDigest> digest, jint byteLength) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleCryptoMacsHMac *create_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_withInt_(id<OrgSpongycastleCryptoDigest> digest, jint byteLength);

__attribute__((unused)) static void OrgSpongycastleCryptoMacsHMac_xorPadWithByteArray_withInt_withByte_(IOSByteArray *pad, jint len, jbyte n);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoMacsHMac)

@implementation OrgSpongycastleCryptoMacsHMac

+ (jint)getByteLengthWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest {
  return OrgSpongycastleCryptoMacsHMac_getByteLengthWithOrgSpongycastleCryptoDigest_(digest);
}

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest {
  OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_(self, digest);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                            withInt:(jint)byteLength {
  OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_withInt_(self, digest, byteLength);
  return self;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$$", [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) getAlgorithmName], @"/HMAC");
}

- (id<OrgSpongycastleCryptoDigest>)getUnderlyingDigest {
  return digest_;
}

- (void)init__WithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) reset];
  IOSByteArray *key = [((OrgSpongycastleCryptoParamsKeyParameter *) nil_chk(((OrgSpongycastleCryptoParamsKeyParameter *) cast_chk(params, [OrgSpongycastleCryptoParamsKeyParameter class])))) getKey];
  jint keyLength = ((IOSByteArray *) nil_chk(key))->size_;
  if (keyLength > blockLength_) {
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:key withInt:0 withInt:keyLength];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:inputPad_ withInt:0];
    keyLength = digestSize_;
  }
  else {
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(key, 0, inputPad_, 0, keyLength);
  }
  for (jint i = keyLength; i < ((IOSByteArray *) nil_chk(inputPad_))->size_; i++) {
    *IOSByteArray_GetRef(inputPad_, i) = 0;
  }
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inputPad_, 0, outputBuf_, 0, blockLength_);
  OrgSpongycastleCryptoMacsHMac_xorPadWithByteArray_withInt_withByte_(inputPad_, blockLength_, OrgSpongycastleCryptoMacsHMac_IPAD);
  OrgSpongycastleCryptoMacsHMac_xorPadWithByteArray_withInt_withByte_(outputBuf_, blockLength_, OrgSpongycastleCryptoMacsHMac_OPAD);
  if ([OrgSpongycastleUtilMemoable_class_() isInstance:digest_]) {
    opadState_ = [((id<OrgSpongycastleUtilMemoable>) nil_chk(((id<OrgSpongycastleUtilMemoable>) cast_check(digest_, OrgSpongycastleUtilMemoable_class_())))) copy__];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(((id<OrgSpongycastleCryptoDigest>) cast_check(opadState_, OrgSpongycastleCryptoDigest_class_())))) updateWithByteArray:outputBuf_ withInt:0 withInt:blockLength_];
  }
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:inputPad_ withInt:0 withInt:((IOSByteArray *) nil_chk(inputPad_))->size_];
  if ([OrgSpongycastleUtilMemoable_class_() isInstance:digest_]) {
    ipadState_ = [((id<OrgSpongycastleUtilMemoable>) nil_chk(((id<OrgSpongycastleUtilMemoable>) cast_check(digest_, OrgSpongycastleUtilMemoable_class_())))) copy__];
  }
}

- (jint)getMacSize {
  return digestSize_;
}

- (void)updateWithByte:(jbyte)inArg {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) updateWithByte:inArg];
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:inArg withInt:inOff withInt:len];
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:outputBuf_ withInt:blockLength_];
  if (opadState_ != nil) {
    [((id<OrgSpongycastleUtilMemoable>) nil_chk(((id<OrgSpongycastleUtilMemoable>) cast_check(digest_, OrgSpongycastleUtilMemoable_class_())))) resetWithOrgSpongycastleUtilMemoable:opadState_];
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:outputBuf_ withInt:blockLength_ withInt:[digest_ getDigestSize]];
  }
  else {
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:outputBuf_ withInt:0 withInt:((IOSByteArray *) nil_chk(outputBuf_))->size_];
  }
  jint len = [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) doFinalWithByteArray:outArg withInt:outOff];
  for (jint i = blockLength_; i < ((IOSByteArray *) nil_chk(outputBuf_))->size_; i++) {
    *IOSByteArray_GetRef(outputBuf_, i) = 0;
  }
  if (ipadState_ != nil) {
    [((id<OrgSpongycastleUtilMemoable>) nil_chk(((id<OrgSpongycastleUtilMemoable>) cast_check(digest_, OrgSpongycastleUtilMemoable_class_())))) resetWithOrgSpongycastleUtilMemoable:ipadState_];
  }
  else {
    [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:inputPad_ withInt:0 withInt:((IOSByteArray *) nil_chk(inputPad_))->size_];
  }
  return len;
}

- (void)reset {
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) reset];
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest_)) updateWithByteArray:inputPad_ withInt:0 withInt:((IOSByteArray *) nil_chk(inputPad_))->size_];
}

+ (void)xorPadWithByteArray:(IOSByteArray *)pad
                    withInt:(jint)len
                   withByte:(jbyte)n {
  OrgSpongycastleCryptoMacsHMac_xorPadWithByteArray_withInt_withByte_(pad, len, n);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "I", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoDigest;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 7, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0xa, 10, 11, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getByteLengthWithOrgSpongycastleCryptoDigest:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoDigest:);
  methods[2].selector = @selector(initWithOrgSpongycastleCryptoDigest:withInt:);
  methods[3].selector = @selector(getAlgorithmName);
  methods[4].selector = @selector(getUnderlyingDigest);
  methods[5].selector = @selector(init__WithOrgSpongycastleCryptoCipherParameters:);
  methods[6].selector = @selector(getMacSize);
  methods[7].selector = @selector(updateWithByte:);
  methods[8].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[9].selector = @selector(doFinalWithByteArray:withInt:);
  methods[10].selector = @selector(reset);
  methods[11].selector = @selector(xorPadWithByteArray:withInt:withByte:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "IPAD", "B", .constantValue.asChar = OrgSpongycastleCryptoMacsHMac_IPAD, 0x1a, -1, -1, -1, -1 },
    { "OPAD", "B", .constantValue.asChar = OrgSpongycastleCryptoMacsHMac_OPAD, 0x1a, -1, -1, -1, -1 },
    { "digest_", "LOrgSpongycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "digestSize_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "blockLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ipadState_", "LOrgSpongycastleUtilMemoable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "opadState_", "LOrgSpongycastleUtilMemoable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "inputPad_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "outputBuf_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "blockLengths", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0xa, -1, 12, -1, -1 },
  };
  static const void *ptrTable[] = { "getByteLength", "LOrgSpongycastleCryptoDigest;", "LOrgSpongycastleCryptoDigest;I", "init", "LOrgSpongycastleCryptoCipherParameters;", "update", "B", "[BII", "doFinal", "[BI", "xorPad", "[BIB", &OrgSpongycastleCryptoMacsHMac_blockLengths };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoMacsHMac = { "HMac", "org.spongycastle.crypto.macs", ptrTable, methods, fields, 7, 0x1, 12, 10, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoMacsHMac;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoMacsHMac class]) {
    {
      OrgSpongycastleCryptoMacsHMac_blockLengths = new_JavaUtilHashtable_init();
      (void) [OrgSpongycastleCryptoMacsHMac_blockLengths putWithId:@"GOST3411" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(32)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"MD2" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(16)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"MD4" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"MD5" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"RIPEMD128" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"RIPEMD160" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"SHA-1" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"SHA-224" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"SHA-256" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"SHA-384" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(128)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"SHA-512" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(128)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"Tiger" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
      (void) [((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) putWithId:@"Whirlpool" withId:OrgSpongycastleUtilIntegers_valueOfWithInt_(64)];
    }
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoMacsHMac)
  }
}

@end

jint OrgSpongycastleCryptoMacsHMac_getByteLengthWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest) {
  OrgSpongycastleCryptoMacsHMac_initialize();
  if ([OrgSpongycastleCryptoExtendedDigest_class_() isInstance:digest]) {
    return [((id<OrgSpongycastleCryptoExtendedDigest>) nil_chk(((id<OrgSpongycastleCryptoExtendedDigest>) cast_check(digest, OrgSpongycastleCryptoExtendedDigest_class_())))) getByteLength];
  }
  JavaLangInteger *b = (JavaLangInteger *) cast_chk([((JavaUtilHashtable *) nil_chk(OrgSpongycastleCryptoMacsHMac_blockLengths)) getWithId:[((id<OrgSpongycastleCryptoDigest>) nil_chk(digest)) getAlgorithmName]], [JavaLangInteger class]);
  if (b == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown digest passed: ", [digest getAlgorithmName]));
  }
  return [b intValue];
}

void OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_(OrgSpongycastleCryptoMacsHMac *self, id<OrgSpongycastleCryptoDigest> digest) {
  OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_withInt_(self, digest, OrgSpongycastleCryptoMacsHMac_getByteLengthWithOrgSpongycastleCryptoDigest_(digest));
}

OrgSpongycastleCryptoMacsHMac *new_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoMacsHMac, initWithOrgSpongycastleCryptoDigest_, digest)
}

OrgSpongycastleCryptoMacsHMac *create_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoMacsHMac, initWithOrgSpongycastleCryptoDigest_, digest)
}

void OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_withInt_(OrgSpongycastleCryptoMacsHMac *self, id<OrgSpongycastleCryptoDigest> digest, jint byteLength) {
  NSObject_init(self);
  self->digest_ = digest;
  self->digestSize_ = [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest)) getDigestSize];
  self->blockLength_ = byteLength;
  self->inputPad_ = [IOSByteArray newArrayWithLength:self->blockLength_];
  self->outputBuf_ = [IOSByteArray newArrayWithLength:self->blockLength_ + self->digestSize_];
}

OrgSpongycastleCryptoMacsHMac *new_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_withInt_(id<OrgSpongycastleCryptoDigest> digest, jint byteLength) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoMacsHMac, initWithOrgSpongycastleCryptoDigest_withInt_, digest, byteLength)
}

OrgSpongycastleCryptoMacsHMac *create_OrgSpongycastleCryptoMacsHMac_initWithOrgSpongycastleCryptoDigest_withInt_(id<OrgSpongycastleCryptoDigest> digest, jint byteLength) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoMacsHMac, initWithOrgSpongycastleCryptoDigest_withInt_, digest, byteLength)
}

void OrgSpongycastleCryptoMacsHMac_xorPadWithByteArray_withInt_withByte_(IOSByteArray *pad, jint len, jbyte n) {
  OrgSpongycastleCryptoMacsHMac_initialize();
  for (jint i = 0; i < len; ++i) {
    *IOSByteArray_GetRef(nil_chk(pad), i) ^= n;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoMacsHMac)
