//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/GeneralDigest.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Math.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/digests/GeneralDigest.h"
#include "org/spongycastle/util/Pack.h"

#pragma clang diagnostic ignored "-Wprotocol"

@interface OrgSpongycastleCryptoDigestsGeneralDigest () {
 @public
  IOSByteArray *xBuf_;
  jint xBufOff_;
  jlong byteCount_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoDigestsGeneralDigest, xBuf_, IOSByteArray *)

inline jint OrgSpongycastleCryptoDigestsGeneralDigest_get_BYTE_LENGTH(void);
#define OrgSpongycastleCryptoDigestsGeneralDigest_BYTE_LENGTH 64
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoDigestsGeneralDigest, BYTE_LENGTH, jint)

@implementation OrgSpongycastleCryptoDigestsGeneralDigest

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoDigestsGeneralDigest_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithOrgSpongycastleCryptoDigestsGeneralDigest:(OrgSpongycastleCryptoDigestsGeneralDigest *)t {
  OrgSpongycastleCryptoDigestsGeneralDigest_initWithOrgSpongycastleCryptoDigestsGeneralDigest_(self, t);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)encodedState {
  OrgSpongycastleCryptoDigestsGeneralDigest_initWithByteArray_(self, encodedState);
  return self;
}

- (void)copyInWithOrgSpongycastleCryptoDigestsGeneralDigest:(OrgSpongycastleCryptoDigestsGeneralDigest *)t {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(((OrgSpongycastleCryptoDigestsGeneralDigest *) nil_chk(t))->xBuf_, 0, xBuf_, 0, ((IOSByteArray *) nil_chk(t->xBuf_))->size_);
  xBufOff_ = t->xBufOff_;
  byteCount_ = t->byteCount_;
}

- (void)updateWithByte:(jbyte)inArg {
  *IOSByteArray_GetRef(nil_chk(xBuf_), xBufOff_++) = inArg;
  if (xBufOff_ == xBuf_->size_) {
    [self processWordWithByteArray:xBuf_ withInt:0];
    xBufOff_ = 0;
  }
  byteCount_++;
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  len = JavaLangMath_maxWithInt_withInt_(0, len);
  jint i = 0;
  if (xBufOff_ != 0) {
    while (i < len) {
      *IOSByteArray_GetRef(nil_chk(xBuf_), xBufOff_++) = IOSByteArray_Get(nil_chk(inArg), inOff + i++);
      if (xBufOff_ == 4) {
        [self processWordWithByteArray:xBuf_ withInt:0];
        xBufOff_ = 0;
        break;
      }
    }
  }
  jint limit = ((len - i) & ~3) + i;
  for (; i < limit; i += 4) {
    [self processWordWithByteArray:inArg withInt:inOff + i];
  }
  while (i < len) {
    *IOSByteArray_GetRef(nil_chk(xBuf_), xBufOff_++) = IOSByteArray_Get(nil_chk(inArg), inOff + i++);
  }
  byteCount_ += len;
}

- (void)finish {
  jlong bitLength = (JreLShift64(byteCount_, 3));
  [self updateWithByte:(jbyte) 128];
  while (xBufOff_ != 0) {
    [self updateWithByte:(jbyte) 0];
  }
  [self processLengthWithLong:bitLength];
  [self processBlock];
}

- (void)reset {
  byteCount_ = 0;
  xBufOff_ = 0;
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(xBuf_))->size_; i++) {
    *IOSByteArray_GetRef(xBuf_, i) = 0;
  }
}

- (void)populateStateWithByteArray:(IOSByteArray *)state {
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(xBuf_, 0, state, 0, xBufOff_);
  OrgSpongycastleUtilPack_intToBigEndianWithInt_withByteArray_withInt_(xBufOff_, state, 4);
  OrgSpongycastleUtilPack_longToBigEndianWithLong_withByteArray_withInt_(byteCount_, state, 8);
}

- (jint)getByteLength {
  return OrgSpongycastleCryptoDigestsGeneralDigest_BYTE_LENGTH;
}

- (void)processWordWithByteArray:(IOSByteArray *)inArg
                         withInt:(jint)inOff {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (void)processLengthWithLong:(jlong)bitLength {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (void)processBlock {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 2, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x404, 7, 8, -1, -1, -1, -1 },
    { NULL, "V", 0x404, 9, 10, -1, -1, -1, -1 },
    { NULL, "V", 0x404, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoDigestsGeneralDigest:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(copyInWithOrgSpongycastleCryptoDigestsGeneralDigest:);
  methods[4].selector = @selector(updateWithByte:);
  methods[5].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[6].selector = @selector(finish);
  methods[7].selector = @selector(reset);
  methods[8].selector = @selector(populateStateWithByteArray:);
  methods[9].selector = @selector(getByteLength);
  methods[10].selector = @selector(processWordWithByteArray:withInt:);
  methods[11].selector = @selector(processLengthWithLong:);
  methods[12].selector = @selector(processBlock);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BYTE_LENGTH", "I", .constantValue.asInt = OrgSpongycastleCryptoDigestsGeneralDigest_BYTE_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "xBuf_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "xBufOff_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "byteCount_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoDigestsGeneralDigest;", "[B", "copyIn", "update", "B", "[BII", "populateState", "processWord", "[BI", "processLength", "J" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoDigestsGeneralDigest = { "GeneralDigest", "org.spongycastle.crypto.digests", ptrTable, methods, fields, 7, 0x401, 13, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoDigestsGeneralDigest;
}

@end

void OrgSpongycastleCryptoDigestsGeneralDigest_init(OrgSpongycastleCryptoDigestsGeneralDigest *self) {
  NSObject_init(self);
  self->xBuf_ = [IOSByteArray newArrayWithLength:4];
  self->xBufOff_ = 0;
}

void OrgSpongycastleCryptoDigestsGeneralDigest_initWithOrgSpongycastleCryptoDigestsGeneralDigest_(OrgSpongycastleCryptoDigestsGeneralDigest *self, OrgSpongycastleCryptoDigestsGeneralDigest *t) {
  NSObject_init(self);
  self->xBuf_ = [IOSByteArray newArrayWithLength:4];
  [self copyInWithOrgSpongycastleCryptoDigestsGeneralDigest:t];
}

void OrgSpongycastleCryptoDigestsGeneralDigest_initWithByteArray_(OrgSpongycastleCryptoDigestsGeneralDigest *self, IOSByteArray *encodedState) {
  NSObject_init(self);
  self->xBuf_ = [IOSByteArray newArrayWithLength:4];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(encodedState, 0, self->xBuf_, 0, self->xBuf_->size_);
  self->xBufOff_ = OrgSpongycastleUtilPack_bigEndianToIntWithByteArray_withInt_(encodedState, 4);
  self->byteCount_ = OrgSpongycastleUtilPack_bigEndianToLongWithByteArray_withInt_(encodedState, 8);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoDigestsGeneralDigest)
