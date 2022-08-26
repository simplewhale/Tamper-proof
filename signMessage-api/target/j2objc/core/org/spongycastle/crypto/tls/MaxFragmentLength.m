//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/MaxFragmentLength.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/tls/MaxFragmentLength.h"

@implementation OrgSpongycastleCryptoTlsMaxFragmentLength

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsMaxFragmentLength_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)isValidWithShort:(jshort)maxFragmentLength {
  return OrgSpongycastleCryptoTlsMaxFragmentLength_isValidWithShort_(maxFragmentLength);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isValidWithShort:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "pow2_9", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsMaxFragmentLength_pow2_9, 0x19, -1, -1, -1, -1 },
    { "pow2_10", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsMaxFragmentLength_pow2_10, 0x19, -1, -1, -1, -1 },
    { "pow2_11", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsMaxFragmentLength_pow2_11, 0x19, -1, -1, -1, -1 },
    { "pow2_12", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsMaxFragmentLength_pow2_12, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isValid", "S" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsMaxFragmentLength = { "MaxFragmentLength", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 2, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsMaxFragmentLength;
}

@end

void OrgSpongycastleCryptoTlsMaxFragmentLength_init(OrgSpongycastleCryptoTlsMaxFragmentLength *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoTlsMaxFragmentLength *new_OrgSpongycastleCryptoTlsMaxFragmentLength_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsMaxFragmentLength, init)
}

OrgSpongycastleCryptoTlsMaxFragmentLength *create_OrgSpongycastleCryptoTlsMaxFragmentLength_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsMaxFragmentLength, init)
}

jboolean OrgSpongycastleCryptoTlsMaxFragmentLength_isValidWithShort_(jshort maxFragmentLength) {
  OrgSpongycastleCryptoTlsMaxFragmentLength_initialize();
  return maxFragmentLength >= OrgSpongycastleCryptoTlsMaxFragmentLength_pow2_9 && maxFragmentLength <= OrgSpongycastleCryptoTlsMaxFragmentLength_pow2_12;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsMaxFragmentLength)