//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/modes/gcm/GCMMultiplier.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/modes/gcm/GCMMultiplier.h"

@interface OrgSpongycastleCryptoModesGcmGCMMultiplier : NSObject

@end

@implementation OrgSpongycastleCryptoModesGcmGCMMultiplier

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithByteArray:);
  methods[1].selector = @selector(multiplyHWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "[B", "multiplyH" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoModesGcmGCMMultiplier = { "GCMMultiplier", "org.spongycastle.crypto.modes.gcm", ptrTable, methods, NULL, 7, 0x609, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoModesGcmGCMMultiplier;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoModesGcmGCMMultiplier)