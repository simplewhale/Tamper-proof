//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/Wrapper.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/Wrapper.h"

@interface OrgSpongycastleCryptoWrapper : NSObject

@end

@implementation OrgSpongycastleCryptoWrapper

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x401, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x401, 4, 3, 5, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[1].selector = @selector(getAlgorithmName);
  methods[2].selector = @selector(wrapWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(unwrapWithByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "ZLOrgSpongycastleCryptoCipherParameters;", "wrap", "[BII", "unwrap", "LOrgSpongycastleCryptoInvalidCipherTextException;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoWrapper = { "Wrapper", "org.spongycastle.crypto", ptrTable, methods, NULL, 7, 0x609, 4, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoWrapper;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoWrapper)
