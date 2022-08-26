//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/newhope/NHPrivateKeyParameters.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/pqc/crypto/newhope/NHPrivateKeyParameters.h"
#include "org/spongycastle/util/Arrays.h"

@implementation OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters

- (instancetype)initWithShortArray:(IOSShortArray *)secData {
  OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(self, secData);
  return self;
}

- (IOSShortArray *)getSecData {
  return OrgSpongycastleUtilArrays_cloneWithShortArray_(secData_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[S", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithShortArray:);
  methods[1].selector = @selector(getSecData);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "secData_", "[S", .constantValue.asLong = 0, 0x10, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[S" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters = { "NHPrivateKeyParameters", "org.spongycastle.pqc.crypto.newhope", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters;
}

@end

void OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters *self, IOSShortArray *secData) {
  OrgSpongycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, true);
  self->secData_ = OrgSpongycastleUtilArrays_cloneWithShortArray_(secData);
}

OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters *new_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(IOSShortArray *secData) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters, initWithShortArray_, secData)
}

OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters *create_OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters_initWithShortArray_(IOSShortArray *secData) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters, initWithShortArray_, secData)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoNewhopeNHPrivateKeyParameters)
