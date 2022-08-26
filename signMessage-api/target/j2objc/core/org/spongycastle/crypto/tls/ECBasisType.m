//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/ECBasisType.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/tls/ECBasisType.h"

@implementation OrgSpongycastleCryptoTlsECBasisType

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsECBasisType_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (jboolean)isValidWithShort:(jshort)ecBasisType {
  return OrgSpongycastleCryptoTlsECBasisType_isValidWithShort_(ecBasisType);
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
    { "ec_basis_trinomial", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsECBasisType_ec_basis_trinomial, 0x19, -1, -1, -1, -1 },
    { "ec_basis_pentanomial", "S", .constantValue.asShort = OrgSpongycastleCryptoTlsECBasisType_ec_basis_pentanomial, 0x19, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isValid", "S" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsECBasisType = { "ECBasisType", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsECBasisType;
}

@end

void OrgSpongycastleCryptoTlsECBasisType_init(OrgSpongycastleCryptoTlsECBasisType *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoTlsECBasisType *new_OrgSpongycastleCryptoTlsECBasisType_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsECBasisType, init)
}

OrgSpongycastleCryptoTlsECBasisType *create_OrgSpongycastleCryptoTlsECBasisType_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsECBasisType, init)
}

jboolean OrgSpongycastleCryptoTlsECBasisType_isValidWithShort_(jshort ecBasisType) {
  OrgSpongycastleCryptoTlsECBasisType_initialize();
  return ecBasisType >= OrgSpongycastleCryptoTlsECBasisType_ec_basis_trinomial && ecBasisType <= OrgSpongycastleCryptoTlsECBasisType_ec_basis_pentanomial;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsECBasisType)
