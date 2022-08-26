//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DSAPublicKeyParameters.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/params/DSAKeyParameters.h"
#include "org/spongycastle/crypto/params/DSAParameters.h"
#include "org/spongycastle/crypto/params/DSAPublicKeyParameters.h"

@interface OrgSpongycastleCryptoParamsDSAPublicKeyParameters () {
 @public
  JavaMathBigInteger *y_;
}

- (JavaMathBigInteger *)validateWithJavaMathBigInteger:(JavaMathBigInteger *)y
          withOrgSpongycastleCryptoParamsDSAParameters:(OrgSpongycastleCryptoParamsDSAParameters *)params;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDSAPublicKeyParameters, y_, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoParamsDSAPublicKeyParameters_get_ONE(void);
static JavaMathBigInteger *OrgSpongycastleCryptoParamsDSAPublicKeyParameters_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoParamsDSAPublicKeyParameters, ONE, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoParamsDSAPublicKeyParameters_get_TWO(void);
static JavaMathBigInteger *OrgSpongycastleCryptoParamsDSAPublicKeyParameters_TWO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoParamsDSAPublicKeyParameters, TWO, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *OrgSpongycastleCryptoParamsDSAPublicKeyParameters_validateWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_(OrgSpongycastleCryptoParamsDSAPublicKeyParameters *self, JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDSAParameters *params);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoParamsDSAPublicKeyParameters)

@implementation OrgSpongycastleCryptoParamsDSAPublicKeyParameters

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)y
withOrgSpongycastleCryptoParamsDSAParameters:(OrgSpongycastleCryptoParamsDSAParameters *)params {
  OrgSpongycastleCryptoParamsDSAPublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_(self, y, params);
  return self;
}

- (JavaMathBigInteger *)validateWithJavaMathBigInteger:(JavaMathBigInteger *)y
          withOrgSpongycastleCryptoParamsDSAParameters:(OrgSpongycastleCryptoParamsDSAParameters *)params {
  return OrgSpongycastleCryptoParamsDSAPublicKeyParameters_validateWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_(self, y, params);
}

- (JavaMathBigInteger *)getY {
  return y_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withOrgSpongycastleCryptoParamsDSAParameters:);
  methods[1].selector = @selector(validateWithJavaMathBigInteger:withOrgSpongycastleCryptoParamsDSAParameters:);
  methods[2].selector = @selector(getY);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 2, -1, -1 },
    { "TWO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 3, -1, -1 },
    { "y_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LOrgSpongycastleCryptoParamsDSAParameters;", "validate", &OrgSpongycastleCryptoParamsDSAPublicKeyParameters_ONE, &OrgSpongycastleCryptoParamsDSAPublicKeyParameters_TWO };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsDSAPublicKeyParameters = { "DSAPublicKeyParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 3, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsDSAPublicKeyParameters;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoParamsDSAPublicKeyParameters class]) {
    OrgSpongycastleCryptoParamsDSAPublicKeyParameters_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    OrgSpongycastleCryptoParamsDSAPublicKeyParameters_TWO = JavaMathBigInteger_valueOfWithLong_(2);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoParamsDSAPublicKeyParameters)
  }
}

@end

void OrgSpongycastleCryptoParamsDSAPublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_(OrgSpongycastleCryptoParamsDSAPublicKeyParameters *self, JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDSAParameters *params) {
  OrgSpongycastleCryptoParamsDSAKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDSAParameters_(self, false, params);
  self->y_ = OrgSpongycastleCryptoParamsDSAPublicKeyParameters_validateWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_(self, y, params);
}

OrgSpongycastleCryptoParamsDSAPublicKeyParameters *new_OrgSpongycastleCryptoParamsDSAPublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_(JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDSAParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDSAPublicKeyParameters, initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_, y, params)
}

OrgSpongycastleCryptoParamsDSAPublicKeyParameters *create_OrgSpongycastleCryptoParamsDSAPublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_(JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDSAParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDSAPublicKeyParameters, initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_, y, params)
}

JavaMathBigInteger *OrgSpongycastleCryptoParamsDSAPublicKeyParameters_validateWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_(OrgSpongycastleCryptoParamsDSAPublicKeyParameters *self, JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDSAParameters *params) {
  if (params != nil) {
    if ([((JavaMathBigInteger *) nil_chk(OrgSpongycastleCryptoParamsDSAPublicKeyParameters_TWO)) compareToWithId:y] <= 0 && [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk([params getP])) subtractWithJavaMathBigInteger:OrgSpongycastleCryptoParamsDSAPublicKeyParameters_TWO])) compareToWithId:y] >= 0 && [((JavaMathBigInteger *) nil_chk(OrgSpongycastleCryptoParamsDSAPublicKeyParameters_ONE)) isEqual:[((JavaMathBigInteger *) nil_chk(y)) modPowWithJavaMathBigInteger:[params getQ] withJavaMathBigInteger:[params getP]]]) {
      return y;
    }
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"y value does not appear to be in correct group");
  }
  else {
    return y;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsDSAPublicKeyParameters)