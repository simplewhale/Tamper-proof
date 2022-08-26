//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/digests/ShortenedDigest.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/ExtendedDigest.h"
#include "org/spongycastle/crypto/digests/ShortenedDigest.h"

@interface OrgSpongycastleCryptoDigestsShortenedDigest () {
 @public
  id<OrgSpongycastleCryptoExtendedDigest> baseDigest_;
  jint length_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoDigestsShortenedDigest, baseDigest_, id<OrgSpongycastleCryptoExtendedDigest>)

@implementation OrgSpongycastleCryptoDigestsShortenedDigest

- (instancetype)initWithOrgSpongycastleCryptoExtendedDigest:(id<OrgSpongycastleCryptoExtendedDigest>)baseDigest
                                                    withInt:(jint)length {
  OrgSpongycastleCryptoDigestsShortenedDigest_initWithOrgSpongycastleCryptoExtendedDigest_withInt_(self, baseDigest, length);
  return self;
}

- (NSString *)getAlgorithmName {
  return JreStrcat("$CIC", [((id<OrgSpongycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) getAlgorithmName], '(', length_ * 8, ')');
}

- (jint)getDigestSize {
  return length_;
}

- (void)updateWithByte:(jbyte)inArg {
  [((id<OrgSpongycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) updateWithByte:inArg];
}

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len {
  [((id<OrgSpongycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) updateWithByteArray:inArg withInt:inOff withInt:len];
}

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff {
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) getDigestSize]];
  [((id<OrgSpongycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) doFinalWithByteArray:tmp withInt:0];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(tmp, 0, outArg, outOff, length_);
  return length_;
}

- (void)reset {
  [((id<OrgSpongycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) reset];
}

- (jint)getByteLength {
  return [((id<OrgSpongycastleCryptoExtendedDigest>) nil_chk(baseDigest_)) getByteLength];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoExtendedDigest:withInt:);
  methods[1].selector = @selector(getAlgorithmName);
  methods[2].selector = @selector(getDigestSize);
  methods[3].selector = @selector(updateWithByte:);
  methods[4].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(doFinalWithByteArray:withInt:);
  methods[6].selector = @selector(reset);
  methods[7].selector = @selector(getByteLength);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "baseDigest_", "LOrgSpongycastleCryptoExtendedDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "length_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoExtendedDigest;I", "update", "B", "[BII", "doFinal", "[BI" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoDigestsShortenedDigest = { "ShortenedDigest", "org.spongycastle.crypto.digests", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoDigestsShortenedDigest;
}

@end

void OrgSpongycastleCryptoDigestsShortenedDigest_initWithOrgSpongycastleCryptoExtendedDigest_withInt_(OrgSpongycastleCryptoDigestsShortenedDigest *self, id<OrgSpongycastleCryptoExtendedDigest> baseDigest, jint length) {
  NSObject_init(self);
  if (baseDigest == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"baseDigest must not be null");
  }
  if (length > [baseDigest getDigestSize]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"baseDigest output not large enough to support length");
  }
  self->baseDigest_ = baseDigest;
  self->length_ = length;
}

OrgSpongycastleCryptoDigestsShortenedDigest *new_OrgSpongycastleCryptoDigestsShortenedDigest_initWithOrgSpongycastleCryptoExtendedDigest_withInt_(id<OrgSpongycastleCryptoExtendedDigest> baseDigest, jint length) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoDigestsShortenedDigest, initWithOrgSpongycastleCryptoExtendedDigest_withInt_, baseDigest, length)
}

OrgSpongycastleCryptoDigestsShortenedDigest *create_OrgSpongycastleCryptoDigestsShortenedDigest_initWithOrgSpongycastleCryptoExtendedDigest_withInt_(id<OrgSpongycastleCryptoExtendedDigest> baseDigest, jint length) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoDigestsShortenedDigest, initWithOrgSpongycastleCryptoExtendedDigest_withInt_, baseDigest, length)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoDigestsShortenedDigest)