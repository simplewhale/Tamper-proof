//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/CramerShoupPublicKeyParameters.java
//

#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/params/CramerShoupKeyParameters.h"
#include "org/spongycastle/crypto/params/CramerShoupParameters.h"
#include "org/spongycastle/crypto/params/CramerShoupPublicKeyParameters.h"

@interface OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters () {
 @public
  JavaMathBigInteger *c_;
  JavaMathBigInteger *d_;
  JavaMathBigInteger *h_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters, c_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters, d_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters, h_, JavaMathBigInteger *)

@implementation OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters

- (instancetype)initWithOrgSpongycastleCryptoParamsCramerShoupParameters:(OrgSpongycastleCryptoParamsCramerShoupParameters *)params
                                                  withJavaMathBigInteger:(JavaMathBigInteger *)c
                                                  withJavaMathBigInteger:(JavaMathBigInteger *)d
                                                  withJavaMathBigInteger:(JavaMathBigInteger *)h {
  OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters_initWithOrgSpongycastleCryptoParamsCramerShoupParameters_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(self, params, c, d, h);
  return self;
}

- (JavaMathBigInteger *)getC {
  return c_;
}

- (JavaMathBigInteger *)getD {
  return d_;
}

- (JavaMathBigInteger *)getH {
  return h_;
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(c_)) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk(d_)) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk(h_)) hash]) ^ ((jint) [super hash]);
}

- (jboolean)isEqual:(id)obj {
  if (!([obj isKindOfClass:[OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters class]])) {
    return false;
  }
  OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *other = (OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *) cast_chk(obj, [OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters class]);
  return [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *) nil_chk(other)) getC])) isEqual:c_] && [((JavaMathBigInteger *) nil_chk([other getD])) isEqual:d_] && [((JavaMathBigInteger *) nil_chk([other getH])) isEqual:h_] && [super isEqual:obj];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoParamsCramerShoupParameters:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[1].selector = @selector(getC);
  methods[2].selector = @selector(getD);
  methods[3].selector = @selector(getH);
  methods[4].selector = @selector(hash);
  methods[5].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "c_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "d_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "h_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoParamsCramerShoupParameters;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;", "hashCode", "equals", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters = { "CramerShoupPublicKeyParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 6, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters;
}

@end

void OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters_initWithOrgSpongycastleCryptoParamsCramerShoupParameters_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *self, OrgSpongycastleCryptoParamsCramerShoupParameters *params, JavaMathBigInteger *c, JavaMathBigInteger *d, JavaMathBigInteger *h) {
  OrgSpongycastleCryptoParamsCramerShoupKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsCramerShoupParameters_(self, false, params);
  self->c_ = c;
  self->d_ = d;
  self->h_ = h;
}

OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *new_OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters_initWithOrgSpongycastleCryptoParamsCramerShoupParameters_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsCramerShoupParameters *params, JavaMathBigInteger *c, JavaMathBigInteger *d, JavaMathBigInteger *h) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters, initWithOrgSpongycastleCryptoParamsCramerShoupParameters_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, params, c, d, h)
}

OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters *create_OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters_initWithOrgSpongycastleCryptoParamsCramerShoupParameters_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsCramerShoupParameters *params, JavaMathBigInteger *c, JavaMathBigInteger *d, JavaMathBigInteger *h) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters, initWithOrgSpongycastleCryptoParamsCramerShoupParameters_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, params, c, d, h)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsCramerShoupPublicKeyParameters)
