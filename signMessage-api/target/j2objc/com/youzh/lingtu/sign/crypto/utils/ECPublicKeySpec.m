//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/ECPublicKeySpec.java
//

#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/ECKeySpec.h"
#include "com/youzh/lingtu/sign/crypto/utils/ECParameterSpec.h"
#include "com/youzh/lingtu/sign/crypto/utils/ECPublicKeySpec.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECPoint.h"

@interface ComYouzhLingtuSignCryptoUtilsECPublicKeySpec () {
 @public
  OrgSpongycastleMathEcECPoint *q_;
}

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsECPublicKeySpec, q_, OrgSpongycastleMathEcECPoint *)

@implementation ComYouzhLingtuSignCryptoUtilsECPublicKeySpec

- (instancetype)initWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)q
    withComYouzhLingtuSignCryptoUtilsECParameterSpec:(ComYouzhLingtuSignCryptoUtilsECParameterSpec *)spec {
  ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_(self, q, spec);
  return self;
}

- (OrgSpongycastleMathEcECPoint *)getQ {
  return q_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleMathEcECPoint:withComYouzhLingtuSignCryptoUtilsECParameterSpec:);
  methods[1].selector = @selector(getQ);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "q_", "LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleMathEcECPoint;LComYouzhLingtuSignCryptoUtilsECParameterSpec;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsECPublicKeySpec = { "ECPublicKeySpec", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec;
}

@end

void ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_(ComYouzhLingtuSignCryptoUtilsECPublicKeySpec *self, OrgSpongycastleMathEcECPoint *q, ComYouzhLingtuSignCryptoUtilsECParameterSpec *spec) {
  ComYouzhLingtuSignCryptoUtilsECKeySpec_initWithComYouzhLingtuSignCryptoUtilsECParameterSpec_(self, spec);
  if ([((OrgSpongycastleMathEcECPoint *) nil_chk(q)) getCurve] != nil) {
    self->q_ = [q normalize];
  }
  else {
    self->q_ = q;
  }
}

ComYouzhLingtuSignCryptoUtilsECPublicKeySpec *new_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_(OrgSpongycastleMathEcECPoint *q, ComYouzhLingtuSignCryptoUtilsECParameterSpec *spec) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsECPublicKeySpec, initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_, q, spec)
}

ComYouzhLingtuSignCryptoUtilsECPublicKeySpec *create_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_(OrgSpongycastleMathEcECPoint *q, ComYouzhLingtuSignCryptoUtilsECParameterSpec *spec) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsECPublicKeySpec, initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_, q, spec)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsECPublicKeySpec)
