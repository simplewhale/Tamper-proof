//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/SkippingCipher.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/SkippingCipher.h"

@interface OrgSpongycastleCryptoSkippingCipher : NSObject

@end

@implementation OrgSpongycastleCryptoSkippingCipher

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "J", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "J", 0x401, 2, 1, -1, -1, -1, -1 },
    { NULL, "J", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(skipWithLong:);
  methods[1].selector = @selector(seekToWithLong:);
  methods[2].selector = @selector(getPosition);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "skip", "J", "seekTo" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoSkippingCipher = { "SkippingCipher", "org.spongycastle.crypto", ptrTable, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoSkippingCipher;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoSkippingCipher)
