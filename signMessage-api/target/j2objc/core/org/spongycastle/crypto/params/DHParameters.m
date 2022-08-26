//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DHParameters.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/params/DHParameters.h"
#include "org/spongycastle/crypto/params/DHValidationParameters.h"

@interface OrgSpongycastleCryptoParamsDHParameters () {
 @public
  JavaMathBigInteger *g_;
  JavaMathBigInteger *p_;
  JavaMathBigInteger *q_;
  JavaMathBigInteger *j_;
  jint m_;
  jint l_;
  OrgSpongycastleCryptoParamsDHValidationParameters *validation_;
}

+ (jint)getDefaultMParamWithInt:(jint)lParam;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDHParameters, g_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDHParameters, p_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDHParameters, q_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDHParameters, j_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDHParameters, validation_, OrgSpongycastleCryptoParamsDHValidationParameters *)

inline jint OrgSpongycastleCryptoParamsDHParameters_get_DEFAULT_MINIMUM_LENGTH(void);
#define OrgSpongycastleCryptoParamsDHParameters_DEFAULT_MINIMUM_LENGTH 160
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoParamsDHParameters, DEFAULT_MINIMUM_LENGTH, jint)

__attribute__((unused)) static jint OrgSpongycastleCryptoParamsDHParameters_getDefaultMParamWithInt_(jint lParam);

@implementation OrgSpongycastleCryptoParamsDHParameters

+ (jint)getDefaultMParamWithInt:(jint)lParam {
  return OrgSpongycastleCryptoParamsDHParameters_getDefaultMParamWithInt_(lParam);
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)g {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_(self, p, g);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)g
                    withJavaMathBigInteger:(JavaMathBigInteger *)q {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(self, p, g, q);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)g
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                                   withInt:(jint)l {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(self, p, g, q, l);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)g
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                                   withInt:(jint)m
                                   withInt:(jint)l {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_(self, p, g, q, m, l);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)g
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                    withJavaMathBigInteger:(JavaMathBigInteger *)j
withOrgSpongycastleCryptoParamsDHValidationParameters:(OrgSpongycastleCryptoParamsDHValidationParameters *)validation {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(self, p, g, q, j, validation);
  return self;
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)g
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                                   withInt:(jint)m
                                   withInt:(jint)l
                    withJavaMathBigInteger:(JavaMathBigInteger *)j
withOrgSpongycastleCryptoParamsDHValidationParameters:(OrgSpongycastleCryptoParamsDHValidationParameters *)validation {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(self, p, g, q, m, l, j, validation);
  return self;
}

- (JavaMathBigInteger *)getP {
  return p_;
}

- (JavaMathBigInteger *)getG {
  return g_;
}

- (JavaMathBigInteger *)getQ {
  return q_;
}

- (JavaMathBigInteger *)getJ {
  return j_;
}

- (jint)getM {
  return m_;
}

- (jint)getL {
  return l_;
}

- (OrgSpongycastleCryptoParamsDHValidationParameters *)getValidationParameters {
  return validation_;
}

- (jboolean)isEqual:(id)obj {
  if (!([obj isKindOfClass:[OrgSpongycastleCryptoParamsDHParameters class]])) {
    return false;
  }
  OrgSpongycastleCryptoParamsDHParameters *pm = (OrgSpongycastleCryptoParamsDHParameters *) cast_chk(obj, [OrgSpongycastleCryptoParamsDHParameters class]);
  if ([self getQ] != nil) {
    if (![((JavaMathBigInteger *) nil_chk([self getQ])) isEqual:[((OrgSpongycastleCryptoParamsDHParameters *) nil_chk(pm)) getQ]]) {
      return false;
    }
  }
  else {
    if ([((OrgSpongycastleCryptoParamsDHParameters *) nil_chk(pm)) getQ] != nil) {
      return false;
    }
  }
  return [((JavaMathBigInteger *) nil_chk([pm getP])) isEqual:p_] && [((JavaMathBigInteger *) nil_chk([pm getG])) isEqual:g_];
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk([self getP])) hash]) ^ ((jint) [((JavaMathBigInteger *) nil_chk([self getG])) hash]) ^ ([self getQ] != nil ? ((jint) [((JavaMathBigInteger *) nil_chk([self getQ])) hash]) : 0);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "I", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 7, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsDHValidationParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 8, 9, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 10, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getDefaultMParamWithInt:);
  methods[1].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:);
  methods[2].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[3].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withInt:);
  methods[4].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withInt:withInt:);
  methods[5].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withOrgSpongycastleCryptoParamsDHValidationParameters:);
  methods[6].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withInt:withInt:withJavaMathBigInteger:withOrgSpongycastleCryptoParamsDHValidationParameters:);
  methods[7].selector = @selector(getP);
  methods[8].selector = @selector(getG);
  methods[9].selector = @selector(getQ);
  methods[10].selector = @selector(getJ);
  methods[11].selector = @selector(getM);
  methods[12].selector = @selector(getL);
  methods[13].selector = @selector(getValidationParameters);
  methods[14].selector = @selector(isEqual:);
  methods[15].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DEFAULT_MINIMUM_LENGTH", "I", .constantValue.asInt = OrgSpongycastleCryptoParamsDHParameters_DEFAULT_MINIMUM_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "g_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "p_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "q_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "j_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "m_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "l_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "validation_", "LOrgSpongycastleCryptoParamsDHValidationParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getDefaultMParam", "I", "LJavaMathBigInteger;LJavaMathBigInteger;", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;I", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;II", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LOrgSpongycastleCryptoParamsDHValidationParameters;", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;IILJavaMathBigInteger;LOrgSpongycastleCryptoParamsDHValidationParameters;", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsDHParameters = { "DHParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 16, 8, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsDHParameters;
}

@end

jint OrgSpongycastleCryptoParamsDHParameters_getDefaultMParamWithInt_(jint lParam) {
  OrgSpongycastleCryptoParamsDHParameters_initialize();
  if (lParam == 0) {
    return OrgSpongycastleCryptoParamsDHParameters_DEFAULT_MINIMUM_LENGTH;
  }
  return lParam < OrgSpongycastleCryptoParamsDHParameters_DEFAULT_MINIMUM_LENGTH ? lParam : OrgSpongycastleCryptoParamsDHParameters_DEFAULT_MINIMUM_LENGTH;
}

void OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsDHParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *g) {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(self, p, g, nil, 0);
}

OrgSpongycastleCryptoParamsDHParameters *new_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_, p, g)
}

OrgSpongycastleCryptoParamsDHParameters *create_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_, p, g)
}

void OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsDHParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q) {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(self, p, g, q, 0);
}

OrgSpongycastleCryptoParamsDHParameters *new_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, p, g, q)
}

OrgSpongycastleCryptoParamsDHParameters *create_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_, p, g, q)
}

void OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(OrgSpongycastleCryptoParamsDHParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint l) {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(self, p, g, q, OrgSpongycastleCryptoParamsDHParameters_getDefaultMParamWithInt_(l), l, nil, nil);
}

OrgSpongycastleCryptoParamsDHParameters *new_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint l) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_, p, g, q, l)
}

OrgSpongycastleCryptoParamsDHParameters *create_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint l) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_, p, g, q, l)
}

void OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_(OrgSpongycastleCryptoParamsDHParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint m, jint l) {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(self, p, g, q, m, l, nil, nil);
}

OrgSpongycastleCryptoParamsDHParameters *new_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint m, jint l) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_, p, g, q, m, l)
}

OrgSpongycastleCryptoParamsDHParameters *create_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint m, jint l) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_, p, g, q, m, l)
}

void OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(OrgSpongycastleCryptoParamsDHParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, JavaMathBigInteger *j, OrgSpongycastleCryptoParamsDHValidationParameters *validation) {
  OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(self, p, g, q, OrgSpongycastleCryptoParamsDHParameters_DEFAULT_MINIMUM_LENGTH, 0, j, validation);
}

OrgSpongycastleCryptoParamsDHParameters *new_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, JavaMathBigInteger *j, OrgSpongycastleCryptoParamsDHValidationParameters *validation) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_, p, g, q, j, validation)
}

OrgSpongycastleCryptoParamsDHParameters *create_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, JavaMathBigInteger *j, OrgSpongycastleCryptoParamsDHValidationParameters *validation) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_, p, g, q, j, validation)
}

void OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(OrgSpongycastleCryptoParamsDHParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint m, jint l, JavaMathBigInteger *j, OrgSpongycastleCryptoParamsDHValidationParameters *validation) {
  NSObject_init(self);
  if (l != 0) {
    if (l > [((JavaMathBigInteger *) nil_chk(p)) bitLength]) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"when l value specified, it must satisfy 2^(l-1) <= p");
    }
    if (l < m) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"when l value specified, it may not be less than m value");
    }
  }
  self->g_ = g;
  self->p_ = p;
  self->q_ = q;
  self->m_ = m;
  self->l_ = l;
  self->j_ = j;
  self->validation_ = validation;
}

OrgSpongycastleCryptoParamsDHParameters *new_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint m, jint l, JavaMathBigInteger *j, OrgSpongycastleCryptoParamsDHValidationParameters *validation) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_, p, g, q, m, l, j, validation)
}

OrgSpongycastleCryptoParamsDHParameters *create_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, jint m, jint l, JavaMathBigInteger *j, OrgSpongycastleCryptoParamsDHValidationParameters *validation) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withInt_withJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHValidationParameters_, p, g, q, m, l, j, validation)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsDHParameters)
