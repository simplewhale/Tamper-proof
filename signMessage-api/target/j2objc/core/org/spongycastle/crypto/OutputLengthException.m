//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/OutputLengthException.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/DataLengthException.h"
#include "org/spongycastle/crypto/OutputLengthException.h"

@implementation OrgSpongycastleCryptoOutputLengthException

- (instancetype)initWithNSString:(NSString *)msg {
  OrgSpongycastleCryptoOutputLengthException_initWithNSString_(self, msg);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoOutputLengthException = { "OutputLengthException", "org.spongycastle.crypto", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoOutputLengthException;
}

@end

void OrgSpongycastleCryptoOutputLengthException_initWithNSString_(OrgSpongycastleCryptoOutputLengthException *self, NSString *msg) {
  OrgSpongycastleCryptoDataLengthException_initWithNSString_(self, msg);
}

OrgSpongycastleCryptoOutputLengthException *new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(NSString *msg) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoOutputLengthException, initWithNSString_, msg)
}

OrgSpongycastleCryptoOutputLengthException *create_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(NSString *msg) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoOutputLengthException, initWithNSString_, msg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoOutputLengthException)