//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/prng/EntropyUtil.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/prng/EntropySource.h"
#include "org/spongycastle/crypto/prng/EntropyUtil.h"

@implementation OrgSpongycastleCryptoPrngEntropyUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoPrngEntropyUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSByteArray *)generateSeedWithOrgSpongycastleCryptoPrngEntropySource:(id<OrgSpongycastleCryptoPrngEntropySource>)entropySource
                                                                 withInt:(jint)numBytes {
  return OrgSpongycastleCryptoPrngEntropyUtil_generateSeedWithOrgSpongycastleCryptoPrngEntropySource_withInt_(entropySource, numBytes);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateSeedWithOrgSpongycastleCryptoPrngEntropySource:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generateSeed", "LOrgSpongycastleCryptoPrngEntropySource;I" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoPrngEntropyUtil = { "EntropyUtil", "org.spongycastle.crypto.prng", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoPrngEntropyUtil;
}

@end

void OrgSpongycastleCryptoPrngEntropyUtil_init(OrgSpongycastleCryptoPrngEntropyUtil *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoPrngEntropyUtil *new_OrgSpongycastleCryptoPrngEntropyUtil_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoPrngEntropyUtil, init)
}

OrgSpongycastleCryptoPrngEntropyUtil *create_OrgSpongycastleCryptoPrngEntropyUtil_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoPrngEntropyUtil, init)
}

IOSByteArray *OrgSpongycastleCryptoPrngEntropyUtil_generateSeedWithOrgSpongycastleCryptoPrngEntropySource_withInt_(id<OrgSpongycastleCryptoPrngEntropySource> entropySource, jint numBytes) {
  OrgSpongycastleCryptoPrngEntropyUtil_initialize();
  IOSByteArray *bytes = [IOSByteArray newArrayWithLength:numBytes];
  if (numBytes * 8 <= [((id<OrgSpongycastleCryptoPrngEntropySource>) nil_chk(entropySource)) entropySize]) {
    IOSByteArray *ent = [entropySource getEntropy];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(ent, 0, bytes, 0, bytes->size_);
  }
  else {
    jint entSize = [entropySource entropySize] / 8;
    for (jint i = 0; i < bytes->size_; i += entSize) {
      IOSByteArray *ent = [entropySource getEntropy];
      if (((IOSByteArray *) nil_chk(ent))->size_ <= bytes->size_ - i) {
        JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(ent, 0, bytes, i, ent->size_);
      }
      else {
        JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(ent, 0, bytes, i, bytes->size_ - i);
      }
    }
  }
  return bytes;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoPrngEntropyUtil)