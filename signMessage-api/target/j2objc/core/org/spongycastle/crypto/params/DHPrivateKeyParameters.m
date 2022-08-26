//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DHPrivateKeyParameters.java
//

#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/params/DHKeyParameters.h"
#include "org/spongycastle/crypto/params/DHParameters.h"
#include "org/spongycastle/crypto/params/DHPrivateKeyParameters.h"

@interface OrgSpongycastleCryptoParamsDHPrivateKeyParameters () {
 @public
  JavaMathBigInteger *x_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDHPrivateKeyParameters, x_, JavaMathBigInteger *)

@implementation OrgSpongycastleCryptoParamsDHPrivateKeyParameters

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)x
withOrgSpongycastleCryptoParamsDHParameters:(OrgSpongycastleCryptoParamsDHParameters *)params {
  OrgSpongycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(self, x, params);
  return self;
}

- (JavaMathBigInteger *)getX {
  return x_;
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(x_)) hash]) ^ ((jint) [super hash]);
}

- (jboolean)isEqual:(id)obj {
  if (!([obj isKindOfClass:[OrgSpongycastleCryptoParamsDHPrivateKeyParameters class]])) {
    return false;
  }
  OrgSpongycastleCryptoParamsDHPrivateKeyParameters *other = (OrgSpongycastleCryptoParamsDHPrivateKeyParameters *) cast_chk(obj, [OrgSpongycastleCryptoParamsDHPrivateKeyParameters class]);
  return [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleCryptoParamsDHPrivateKeyParameters *) nil_chk(other)) getX])) isEqual:self->x_] && [super isEqual:obj];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withOrgSpongycastleCryptoParamsDHParameters:);
  methods[1].selector = @selector(getX);
  methods[2].selector = @selector(hash);
  methods[3].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "x_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LOrgSpongycastleCryptoParamsDHParameters;", "hashCode", "equals", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsDHPrivateKeyParameters = { "DHPrivateKeyParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsDHPrivateKeyParameters;
}

@end

void OrgSpongycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(OrgSpongycastleCryptoParamsDHPrivateKeyParameters *self, JavaMathBigInteger *x, OrgSpongycastleCryptoParamsDHParameters *params) {
  OrgSpongycastleCryptoParamsDHKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDHParameters_(self, true, params);
  self->x_ = x;
}

OrgSpongycastleCryptoParamsDHPrivateKeyParameters *new_OrgSpongycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(JavaMathBigInteger *x, OrgSpongycastleCryptoParamsDHParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHPrivateKeyParameters, initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_, x, params)
}

OrgSpongycastleCryptoParamsDHPrivateKeyParameters *create_OrgSpongycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(JavaMathBigInteger *x, OrgSpongycastleCryptoParamsDHParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHPrivateKeyParameters, initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_, x, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsDHPrivateKeyParameters)
