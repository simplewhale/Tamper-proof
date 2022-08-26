//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/RSAPrivateCrtKeyParameters.java
//

#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/params/RSAKeyParameters.h"
#include "org/spongycastle/crypto/params/RSAPrivateCrtKeyParameters.h"

@interface OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters () {
 @public
  JavaMathBigInteger *e_;
  JavaMathBigInteger *p_;
  JavaMathBigInteger *q_;
  JavaMathBigInteger *dP_;
  JavaMathBigInteger *dQ_;
  JavaMathBigInteger *qInv_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters, e_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters, p_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters, q_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters, dP_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters, dQ_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters, qInv_, JavaMathBigInteger *)

@implementation OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)modulus
                    withJavaMathBigInteger:(JavaMathBigInteger *)publicExponent
                    withJavaMathBigInteger:(JavaMathBigInteger *)privateExponent
                    withJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                    withJavaMathBigInteger:(JavaMathBigInteger *)dP
                    withJavaMathBigInteger:(JavaMathBigInteger *)dQ
                    withJavaMathBigInteger:(JavaMathBigInteger *)qInv {
  OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(self, modulus, publicExponent, privateExponent, p, q, dP, dQ, qInv);
  return self;
}

- (JavaMathBigInteger *)getPublicExponent {
  return e_;
}

- (JavaMathBigInteger *)getP {
  return p_;
}

- (JavaMathBigInteger *)getQ {
  return q_;
}

- (JavaMathBigInteger *)getDP {
  return dP_;
}

- (JavaMathBigInteger *)getDQ {
  return dQ_;
}

- (JavaMathBigInteger *)getQInv {
  return qInv_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[1].selector = @selector(getPublicExponent);
  methods[2].selector = @selector(getP);
  methods[3].selector = @selector(getQ);
  methods[4].selector = @selector(getDP);
  methods[5].selector = @selector(getDQ);
  methods[6].selector = @selector(getQInv);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "e_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "p_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "q_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dP_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dQ_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "qInv_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters = { "RSAPrivateCrtKeyParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 7, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters;
}

@end

void OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters *self, JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *dP, JavaMathBigInteger *dQ, JavaMathBigInteger *qInv) {
  OrgSpongycastleCryptoParamsRSAKeyParameters_initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_(self, true, modulus, privateExponent);
  self->e_ = publicExponent;
  self->p_ = p;
  self->q_ = q;
  self->dP_ = dP;
  self->dQ_ = dQ;
  self->qInv_ = qInv;
}

OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters *new_OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *dP, JavaMathBigInteger *dQ, JavaMathBigInteger *qInv) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, modulus, publicExponent, privateExponent, p, q, dP, dQ, qInv)
}

OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters *create_OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *modulus, JavaMathBigInteger *publicExponent, JavaMathBigInteger *privateExponent, JavaMathBigInteger *p, JavaMathBigInteger *q, JavaMathBigInteger *dP, JavaMathBigInteger *dQ, JavaMathBigInteger *qInv) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, modulus, publicExponent, privateExponent, p, q, dP, dQ, qInv)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters)