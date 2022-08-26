//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/NaccacheSternKeyParameters.java
//

#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/params/NaccacheSternKeyParameters.h"

@interface OrgSpongycastleCryptoParamsNaccacheSternKeyParameters () {
 @public
  JavaMathBigInteger *g_;
  JavaMathBigInteger *n_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsNaccacheSternKeyParameters, g_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsNaccacheSternKeyParameters, n_, JavaMathBigInteger *)

@implementation OrgSpongycastleCryptoParamsNaccacheSternKeyParameters

- (instancetype)initWithBoolean:(jboolean)privateKey
         withJavaMathBigInteger:(JavaMathBigInteger *)g
         withJavaMathBigInteger:(JavaMathBigInteger *)n
                        withInt:(jint)lowerSigmaBound {
  OrgSpongycastleCryptoParamsNaccacheSternKeyParameters_initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(self, privateKey, g, n, lowerSigmaBound);
  return self;
}

- (JavaMathBigInteger *)getG {
  return g_;
}

- (jint)getLowerSigmaBound {
  return lowerSigmaBound_;
}

- (JavaMathBigInteger *)getModulus {
  return n_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withJavaMathBigInteger:withJavaMathBigInteger:withInt:);
  methods[1].selector = @selector(getG);
  methods[2].selector = @selector(getLowerSigmaBound);
  methods[3].selector = @selector(getModulus);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "g_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "n_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "lowerSigmaBound_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZLJavaMathBigInteger;LJavaMathBigInteger;I" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsNaccacheSternKeyParameters = { "NaccacheSternKeyParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 4, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsNaccacheSternKeyParameters;
}

@end

void OrgSpongycastleCryptoParamsNaccacheSternKeyParameters_initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(OrgSpongycastleCryptoParamsNaccacheSternKeyParameters *self, jboolean privateKey, JavaMathBigInteger *g, JavaMathBigInteger *n, jint lowerSigmaBound) {
  OrgSpongycastleCryptoParamsAsymmetricKeyParameter_initWithBoolean_(self, privateKey);
  self->g_ = g;
  self->n_ = n;
  self->lowerSigmaBound_ = lowerSigmaBound;
}

OrgSpongycastleCryptoParamsNaccacheSternKeyParameters *new_OrgSpongycastleCryptoParamsNaccacheSternKeyParameters_initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(jboolean privateKey, JavaMathBigInteger *g, JavaMathBigInteger *n, jint lowerSigmaBound) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsNaccacheSternKeyParameters, initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_withInt_, privateKey, g, n, lowerSigmaBound)
}

OrgSpongycastleCryptoParamsNaccacheSternKeyParameters *create_OrgSpongycastleCryptoParamsNaccacheSternKeyParameters_initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_withInt_(jboolean privateKey, JavaMathBigInteger *g, JavaMathBigInteger *n, jint lowerSigmaBound) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsNaccacheSternKeyParameters, initWithBoolean_withJavaMathBigInteger_withJavaMathBigInteger_withInt_, privateKey, g, n, lowerSigmaBound)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsNaccacheSternKeyParameters)