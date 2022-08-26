//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsContext.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/tls/TlsContext.h"

@interface OrgSpongycastleCryptoTlsTlsContext : NSObject

@end

@implementation OrgSpongycastleCryptoTlsTlsContext

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleCryptoPrngRandomGenerator;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySecureRandom;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsSecurityParameters;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsProtocolVersion;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsProtocolVersion;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoTlsTlsSession;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x401, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getNonceRandomGenerator);
  methods[1].selector = @selector(getSecureRandom);
  methods[2].selector = @selector(getSecurityParameters);
  methods[3].selector = @selector(isServer);
  methods[4].selector = @selector(getClientVersion);
  methods[5].selector = @selector(getServerVersion);
  methods[6].selector = @selector(getResumableSession);
  methods[7].selector = @selector(getUserObject);
  methods[8].selector = @selector(setUserObjectWithId:);
  methods[9].selector = @selector(exportKeyingMaterialWithNSString:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "setUserObject", "LNSObject;", "exportKeyingMaterial", "LNSString;[BI" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsTlsContext = { "TlsContext", "org.spongycastle.crypto.tls", ptrTable, methods, NULL, 7, 0x609, 10, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsTlsContext;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsTlsContext)
