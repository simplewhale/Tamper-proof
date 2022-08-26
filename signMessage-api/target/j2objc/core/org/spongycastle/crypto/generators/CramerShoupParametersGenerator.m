//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/generators/CramerShoupParametersGenerator.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/digests/SHA256Digest.h"
#include "org/spongycastle/crypto/generators/CramerShoupParametersGenerator.h"
#include "org/spongycastle/crypto/params/CramerShoupParameters.h"
#include "org/spongycastle/crypto/params/DHParameters.h"
#include "org/spongycastle/util/BigIntegers.h"

@interface OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator () {
 @public
  jint size_;
  jint certainty_;
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator, random_, JavaSecuritySecureRandom *)

inline JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_get_ONE(void);
static JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator, ONE, JavaMathBigInteger *)

@interface OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper : NSObject

- (instancetype)init;

+ (IOSObjectArray *)generateSafePrimesWithInt:(jint)size
                                      withInt:(jint)certainty
                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

+ (JavaMathBigInteger *)selectGeneratorWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)

inline JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_get_TWO(void);
static JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper, TWO, JavaMathBigInteger *)

__attribute__((unused)) static void OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *self);

__attribute__((unused)) static OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *new_OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *create_OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(void);

__attribute__((unused)) static IOSObjectArray *OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_generateSafePrimesWithInt_withInt_withJavaSecuritySecureRandom_(jint size, jint certainty, JavaSecuritySecureRandom *random);

__attribute__((unused)) static JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *p, JavaSecuritySecureRandom *random);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator)

@implementation OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithInt:(jint)size
              withInt:(jint)certainty
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->size_ = size;
  self->certainty_ = certainty;
  self->random_ = random;
}

- (OrgSpongycastleCryptoParamsCramerShoupParameters *)generateParameters {
  IOSObjectArray *safePrimes = OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_generateSafePrimesWithInt_withInt_withJavaSecuritySecureRandom_(size_, certainty_, random_);
  JavaMathBigInteger *q = IOSObjectArray_Get(nil_chk(safePrimes), 1);
  JavaMathBigInteger *g1 = OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(q, random_);
  JavaMathBigInteger *g2 = OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(q, random_);
  while ([((JavaMathBigInteger *) nil_chk(g1)) isEqual:g2]) {
    g2 = OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(q, random_);
  }
  return new_OrgSpongycastleCryptoParamsCramerShoupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoDigest_(q, g1, g2, new_OrgSpongycastleCryptoDigestsSHA256Digest_init());
}

- (OrgSpongycastleCryptoParamsCramerShoupParameters *)generateParametersWithOrgSpongycastleCryptoParamsDHParameters:(OrgSpongycastleCryptoParamsDHParameters *)dhParams {
  JavaMathBigInteger *p = [((OrgSpongycastleCryptoParamsDHParameters *) nil_chk(dhParams)) getP];
  JavaMathBigInteger *g1 = [dhParams getG];
  JavaMathBigInteger *g2 = OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(p, random_);
  while ([((JavaMathBigInteger *) nil_chk(g1)) isEqual:g2]) {
    g2 = OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(p, random_);
  }
  return new_OrgSpongycastleCryptoParamsCramerShoupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withOrgSpongycastleCryptoDigest_(p, g1, g2, new_OrgSpongycastleCryptoDigestsSHA256Digest_init());
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsCramerShoupParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsCramerShoupParameters;", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithInt:withInt:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(generateParameters);
  methods[3].selector = @selector(generateParametersWithOrgSpongycastleCryptoParamsDHParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 4, -1, -1 },
    { "size_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certainty_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "IILJavaSecuritySecureRandom;", "generateParameters", "LOrgSpongycastleCryptoParamsDHParameters;", &OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ONE, "LOrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator = { "CramerShoupParametersGenerator", "org.spongycastle.crypto.generators", ptrTable, methods, fields, 7, 0x1, 4, 4, -1, 5, -1, -1, -1 };
  return &_OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator class]) {
    OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator)
  }
}

@end

void OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_init(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator *new_OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator, init)
}

OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator *create_OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)

@implementation OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSObjectArray *)generateSafePrimesWithInt:(jint)size
                                      withInt:(jint)certainty
                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_generateSafePrimesWithInt_withInt_withJavaSecuritySecureRandom_(size, certainty, random);
}

+ (JavaMathBigInteger *)selectGeneratorWithJavaMathBigInteger:(JavaMathBigInteger *)p
                                 withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(p, random);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x8, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateSafePrimesWithInt:withInt:withJavaSecuritySecureRandom:);
  methods[2].selector = @selector(selectGeneratorWithJavaMathBigInteger:withJavaSecuritySecureRandom:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TWO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 4, -1, -1 },
  };
  static const void *ptrTable[] = { "generateSafePrimes", "IILJavaSecuritySecureRandom;", "selectGenerator", "LJavaMathBigInteger;LJavaSecuritySecureRandom;", &OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO, "LOrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper = { "ParametersHelper", "org.spongycastle.crypto.generators", ptrTable, methods, fields, 7, 0xa, 3, 1, 5, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper class]) {
    OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO = JavaMathBigInteger_valueOfWithLong_(2);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)
  }
}

@end

void OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *new_OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper, init)
}

OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper *create_OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper, init)
}

IOSObjectArray *OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_generateSafePrimesWithInt_withInt_withJavaSecuritySecureRandom_(jint size, jint certainty, JavaSecuritySecureRandom *random) {
  OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_initialize();
  JavaMathBigInteger *p;
  JavaMathBigInteger *q;
  jint qLength = size - 1;
  for (; ; ) {
    q = new_JavaMathBigInteger_initWithInt_withInt_withJavaUtilRandom_(qLength, 2, random);
    p = [((JavaMathBigInteger *) nil_chk([q shiftLeftWithInt:1])) addWithJavaMathBigInteger:JreLoadStatic(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator, ONE)];
    if ([((JavaMathBigInteger *) nil_chk(p)) isProbablePrimeWithInt:certainty] && (certainty <= 2 || [q isProbablePrimeWithInt:certainty])) {
      break;
    }
  }
  return [IOSObjectArray newArrayWithObjects:(id[]){ p, q } count:2 type:JavaMathBigInteger_class_()];
}

JavaMathBigInteger *OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_selectGeneratorWithJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *p, JavaSecuritySecureRandom *random) {
  OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_initialize();
  JavaMathBigInteger *pMinusTwo = [((JavaMathBigInteger *) nil_chk(p)) subtractWithJavaMathBigInteger:OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO];
  JavaMathBigInteger *g;
  do {
    JavaMathBigInteger *h = OrgSpongycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO, pMinusTwo, random);
    g = [((JavaMathBigInteger *) nil_chk(h)) modPowWithJavaMathBigInteger:OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper_TWO withJavaMathBigInteger:p];
  }
  while ([((JavaMathBigInteger *) nil_chk(g)) isEqual:JreLoadStatic(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator, ONE)]);
  return g;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoGeneratorsCramerShoupParametersGenerator_ParametersHelper)
