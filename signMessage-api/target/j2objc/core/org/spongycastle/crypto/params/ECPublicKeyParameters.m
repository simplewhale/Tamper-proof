//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/ECPublicKeyParameters.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/crypto/params/ECDomainParameters.h"
#include "org/spongycastle/crypto/params/ECKeyParameters.h"
#include "org/spongycastle/crypto/params/ECPublicKeyParameters.h"
#include "org/spongycastle/math/ec/ECPoint.h"

@interface OrgSpongycastleCryptoParamsECPublicKeyParameters () {
 @public
  OrgSpongycastleMathEcECPoint *Q_;
}

- (OrgSpongycastleMathEcECPoint *)validateWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)q;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsECPublicKeyParameters, Q_, OrgSpongycastleMathEcECPoint *)

__attribute__((unused)) static OrgSpongycastleMathEcECPoint *OrgSpongycastleCryptoParamsECPublicKeyParameters_validateWithOrgSpongycastleMathEcECPoint_(OrgSpongycastleCryptoParamsECPublicKeyParameters *self, OrgSpongycastleMathEcECPoint *q);

@implementation OrgSpongycastleCryptoParamsECPublicKeyParameters

- (instancetype)initWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)Q
   withOrgSpongycastleCryptoParamsECDomainParameters:(OrgSpongycastleCryptoParamsECDomainParameters *)params {
  OrgSpongycastleCryptoParamsECPublicKeyParameters_initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleCryptoParamsECDomainParameters_(self, Q, params);
  return self;
}

- (OrgSpongycastleMathEcECPoint *)validateWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)q {
  return OrgSpongycastleCryptoParamsECPublicKeyParameters_validateWithOrgSpongycastleMathEcECPoint_(self, q);
}

- (OrgSpongycastleMathEcECPoint *)getQ {
  return Q_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x2, 1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleMathEcECPoint:withOrgSpongycastleCryptoParamsECDomainParameters:);
  methods[1].selector = @selector(validateWithOrgSpongycastleMathEcECPoint:);
  methods[2].selector = @selector(getQ);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "Q_", "LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleMathEcECPoint;LOrgSpongycastleCryptoParamsECDomainParameters;", "validate", "LOrgSpongycastleMathEcECPoint;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsECPublicKeyParameters = { "ECPublicKeyParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsECPublicKeyParameters;
}

@end

void OrgSpongycastleCryptoParamsECPublicKeyParameters_initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleCryptoParamsECDomainParameters_(OrgSpongycastleCryptoParamsECPublicKeyParameters *self, OrgSpongycastleMathEcECPoint *Q, OrgSpongycastleCryptoParamsECDomainParameters *params) {
  OrgSpongycastleCryptoParamsECKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsECDomainParameters_(self, false, params);
  self->Q_ = OrgSpongycastleCryptoParamsECPublicKeyParameters_validateWithOrgSpongycastleMathEcECPoint_(self, Q);
}

OrgSpongycastleCryptoParamsECPublicKeyParameters *new_OrgSpongycastleCryptoParamsECPublicKeyParameters_initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleCryptoParamsECDomainParameters_(OrgSpongycastleMathEcECPoint *Q, OrgSpongycastleCryptoParamsECDomainParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsECPublicKeyParameters, initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleCryptoParamsECDomainParameters_, Q, params)
}

OrgSpongycastleCryptoParamsECPublicKeyParameters *create_OrgSpongycastleCryptoParamsECPublicKeyParameters_initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleCryptoParamsECDomainParameters_(OrgSpongycastleMathEcECPoint *Q, OrgSpongycastleCryptoParamsECDomainParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsECPublicKeyParameters, initWithOrgSpongycastleMathEcECPoint_withOrgSpongycastleCryptoParamsECDomainParameters_, Q, params)
}

OrgSpongycastleMathEcECPoint *OrgSpongycastleCryptoParamsECPublicKeyParameters_validateWithOrgSpongycastleMathEcECPoint_(OrgSpongycastleCryptoParamsECPublicKeyParameters *self, OrgSpongycastleMathEcECPoint *q) {
  if (q == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"point has null value");
  }
  if ([q isInfinity]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"point at infinity");
  }
  q = [q normalize];
  if (![((OrgSpongycastleMathEcECPoint *) nil_chk(q)) isValid]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"point not on curve");
  }
  return q;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsECPublicKeyParameters)
