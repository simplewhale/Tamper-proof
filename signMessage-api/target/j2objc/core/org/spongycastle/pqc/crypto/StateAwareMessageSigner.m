//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/StateAwareMessageSigner.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/pqc/crypto/StateAwareMessageSigner.h"

@interface OrgSpongycastlePqcCryptoStateAwareMessageSigner : NSObject

@end

@implementation OrgSpongycastlePqcCryptoStateAwareMessageSigner

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getUpdatedPrivateKey);
  #pragma clang diagnostic pop
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoStateAwareMessageSigner = { "StateAwareMessageSigner", "org.spongycastle.pqc.crypto", NULL, methods, NULL, 7, 0x609, 1, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoStateAwareMessageSigner;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoStateAwareMessageSigner)
