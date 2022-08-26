//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DHPublicKeyParameters.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/params/DHKeyParameters.h"
#include "org/spongycastle/crypto/params/DHParameters.h"
#include "org/spongycastle/crypto/params/DHPublicKeyParameters.h"

@interface OrgSpongycastleCryptoParamsDHPublicKeyParameters () {
 @public
  JavaMathBigInteger *y_;
}

- (JavaMathBigInteger *)validateWithJavaMathBigInteger:(JavaMathBigInteger *)y
           withOrgSpongycastleCryptoParamsDHParameters:(OrgSpongycastleCryptoParamsDHParameters *)dhParams;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDHPublicKeyParameters, y_, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoParamsDHPublicKeyParameters_get_ONE(void);
static JavaMathBigInteger *OrgSpongycastleCryptoParamsDHPublicKeyParameters_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoParamsDHPublicKeyParameters, ONE, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoParamsDHPublicKeyParameters_get_TWO(void);
static JavaMathBigInteger *OrgSpongycastleCryptoParamsDHPublicKeyParameters_TWO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoParamsDHPublicKeyParameters, TWO, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *OrgSpongycastleCryptoParamsDHPublicKeyParameters_validateWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(OrgSpongycastleCryptoParamsDHPublicKeyParameters *self, JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDHParameters *dhParams);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoParamsDHPublicKeyParameters)

@implementation OrgSpongycastleCryptoParamsDHPublicKeyParameters

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)y
withOrgSpongycastleCryptoParamsDHParameters:(OrgSpongycastleCryptoParamsDHParameters *)params {
  OrgSpongycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(self, y, params);
  return self;
}

- (JavaMathBigInteger *)validateWithJavaMathBigInteger:(JavaMathBigInteger *)y
           withOrgSpongycastleCryptoParamsDHParameters:(OrgSpongycastleCryptoParamsDHParameters *)dhParams {
  return OrgSpongycastleCryptoParamsDHPublicKeyParameters_validateWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(self, y, dhParams);
}

- (JavaMathBigInteger *)getY {
  return y_;
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(y_)) hash]) ^ ((jint) [super hash]);
}

- (jboolean)isEqual:(id)obj {
  if (!([obj isKindOfClass:[OrgSpongycastleCryptoParamsDHPublicKeyParameters class]])) {
    return false;
  }
  OrgSpongycastleCryptoParamsDHPublicKeyParameters *other = (OrgSpongycastleCryptoParamsDHPublicKeyParameters *) cast_chk(obj, [OrgSpongycastleCryptoParamsDHPublicKeyParameters class]);
  return [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleCryptoParamsDHPublicKeyParameters *) nil_chk(other)) getY])) isEqual:y_] && [super isEqual:obj];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withOrgSpongycastleCryptoParamsDHParameters:);
  methods[1].selector = @selector(validateWithJavaMathBigInteger:withOrgSpongycastleCryptoParamsDHParameters:);
  methods[2].selector = @selector(getY);
  methods[3].selector = @selector(hash);
  methods[4].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
    { "TWO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 6, -1, -1 },
    { "y_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LOrgSpongycastleCryptoParamsDHParameters;", "validate", "hashCode", "equals", "LNSObject;", &OrgSpongycastleCryptoParamsDHPublicKeyParameters_ONE, &OrgSpongycastleCryptoParamsDHPublicKeyParameters_TWO };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsDHPublicKeyParameters = { "DHPublicKeyParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 5, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsDHPublicKeyParameters;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoParamsDHPublicKeyParameters class]) {
    OrgSpongycastleCryptoParamsDHPublicKeyParameters_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    OrgSpongycastleCryptoParamsDHPublicKeyParameters_TWO = JavaMathBigInteger_valueOfWithLong_(2);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoParamsDHPublicKeyParameters)
  }
}

@end

void OrgSpongycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(OrgSpongycastleCryptoParamsDHPublicKeyParameters *self, JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDHParameters *params) {
  OrgSpongycastleCryptoParamsDHKeyParameters_initWithBoolean_withOrgSpongycastleCryptoParamsDHParameters_(self, false, params);
  self->y_ = OrgSpongycastleCryptoParamsDHPublicKeyParameters_validateWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(self, y, params);
}

OrgSpongycastleCryptoParamsDHPublicKeyParameters *new_OrgSpongycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDHParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHPublicKeyParameters, initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_, y, params)
}

OrgSpongycastleCryptoParamsDHPublicKeyParameters *create_OrgSpongycastleCryptoParamsDHPublicKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDHParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHPublicKeyParameters, initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_, y, params)
}

JavaMathBigInteger *OrgSpongycastleCryptoParamsDHPublicKeyParameters_validateWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_(OrgSpongycastleCryptoParamsDHPublicKeyParameters *self, JavaMathBigInteger *y, OrgSpongycastleCryptoParamsDHParameters *dhParams) {
  if (y == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"y value cannot be null");
  }
  if ([y compareToWithId:OrgSpongycastleCryptoParamsDHPublicKeyParameters_TWO] < 0 || [y compareToWithId:[((JavaMathBigInteger *) nil_chk([((OrgSpongycastleCryptoParamsDHParameters *) nil_chk(dhParams)) getP])) subtractWithJavaMathBigInteger:OrgSpongycastleCryptoParamsDHPublicKeyParameters_TWO]] > 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"invalid DH public key");
  }
  if ([((OrgSpongycastleCryptoParamsDHParameters *) nil_chk(dhParams)) getQ] != nil) {
    if ([((JavaMathBigInteger *) nil_chk(OrgSpongycastleCryptoParamsDHPublicKeyParameters_ONE)) isEqual:[y modPowWithJavaMathBigInteger:[dhParams getQ] withJavaMathBigInteger:[dhParams getP]]]) {
      return y;
    }
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Y value does not appear to be in correct group");
  }
  else {
    return y;
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsDHPublicKeyParameters)
