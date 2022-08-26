//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/kems/RSAKeyEncapsulation.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/DerivationFunction.h"
#include "org/spongycastle/crypto/kems/RSAKeyEncapsulation.h"
#include "org/spongycastle/crypto/params/KDFParameters.h"
#include "org/spongycastle/crypto/params/KeyParameter.h"
#include "org/spongycastle/crypto/params/RSAKeyParameters.h"
#include "org/spongycastle/util/BigIntegers.h"

@interface OrgSpongycastleCryptoKemsRSAKeyEncapsulation () {
 @public
  id<OrgSpongycastleCryptoDerivationFunction> kdf_;
  JavaSecuritySecureRandom *rnd_;
  OrgSpongycastleCryptoParamsRSAKeyParameters *key_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoKemsRSAKeyEncapsulation, kdf_, id<OrgSpongycastleCryptoDerivationFunction>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoKemsRSAKeyEncapsulation, rnd_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoKemsRSAKeyEncapsulation, key_, OrgSpongycastleCryptoParamsRSAKeyParameters *)

inline JavaMathBigInteger *OrgSpongycastleCryptoKemsRSAKeyEncapsulation_get_ZERO(void);
static JavaMathBigInteger *OrgSpongycastleCryptoKemsRSAKeyEncapsulation_ZERO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoKemsRSAKeyEncapsulation, ZERO, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoKemsRSAKeyEncapsulation_get_ONE(void);
static JavaMathBigInteger *OrgSpongycastleCryptoKemsRSAKeyEncapsulation_ONE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoKemsRSAKeyEncapsulation, ONE, JavaMathBigInteger *)

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoKemsRSAKeyEncapsulation)

@implementation OrgSpongycastleCryptoKemsRSAKeyEncapsulation

- (instancetype)initWithOrgSpongycastleCryptoDerivationFunction:(id<OrgSpongycastleCryptoDerivationFunction>)kdf
                                   withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)rnd {
  OrgSpongycastleCryptoKemsRSAKeyEncapsulation_initWithOrgSpongycastleCryptoDerivationFunction_withJavaSecuritySecureRandom_(self, kdf, rnd);
  return self;
}

- (void)init__WithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)key {
  if (!([key isKindOfClass:[OrgSpongycastleCryptoParamsRSAKeyParameters class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"RSA key required");
  }
  self->key_ = (OrgSpongycastleCryptoParamsRSAKeyParameters *) cast_chk(key, [OrgSpongycastleCryptoParamsRSAKeyParameters class]);
}

- (id<OrgSpongycastleCryptoCipherParameters>)encryptWithByteArray:(IOSByteArray *)outArg
                                                          withInt:(jint)outOff
                                                          withInt:(jint)keyLen {
  if ([((OrgSpongycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) isPrivate]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Public key required for encryption");
  }
  JavaMathBigInteger *n = [((OrgSpongycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getModulus];
  JavaMathBigInteger *e = [((OrgSpongycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getExponent];
  JavaMathBigInteger *r = OrgSpongycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(OrgSpongycastleCryptoKemsRSAKeyEncapsulation_ZERO, [((JavaMathBigInteger *) nil_chk(n)) subtractWithJavaMathBigInteger:OrgSpongycastleCryptoKemsRSAKeyEncapsulation_ONE], rnd_);
  JavaMathBigInteger *c = [((JavaMathBigInteger *) nil_chk(r)) modPowWithJavaMathBigInteger:e withJavaMathBigInteger:n];
  IOSByteArray *C = OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(([n bitLength] + 7) / 8, c);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(C, 0, outArg, outOff, ((IOSByteArray *) nil_chk(C))->size_);
  return [self generateKeyWithJavaMathBigInteger:n withJavaMathBigInteger:r withInt:keyLen];
}

- (id<OrgSpongycastleCryptoCipherParameters>)encryptWithByteArray:(IOSByteArray *)outArg
                                                          withInt:(jint)keyLen {
  return [self encryptWithByteArray:outArg withInt:0 withInt:keyLen];
}

- (id<OrgSpongycastleCryptoCipherParameters>)decryptWithByteArray:(IOSByteArray *)inArg
                                                          withInt:(jint)inOff
                                                          withInt:(jint)inLen
                                                          withInt:(jint)keyLen {
  if (![((OrgSpongycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) isPrivate]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Private key required for decryption");
  }
  JavaMathBigInteger *n = [((OrgSpongycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getModulus];
  JavaMathBigInteger *d = [((OrgSpongycastleCryptoParamsRSAKeyParameters *) nil_chk(key_)) getExponent];
  IOSByteArray *C = [IOSByteArray newArrayWithLength:inLen];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(inArg, inOff, C, 0, C->size_);
  JavaMathBigInteger *c = new_JavaMathBigInteger_initWithInt_withByteArray_(1, C);
  JavaMathBigInteger *r = [c modPowWithJavaMathBigInteger:d withJavaMathBigInteger:n];
  return [self generateKeyWithJavaMathBigInteger:n withJavaMathBigInteger:r withInt:keyLen];
}

- (id<OrgSpongycastleCryptoCipherParameters>)decryptWithByteArray:(IOSByteArray *)inArg
                                                          withInt:(jint)keyLen {
  return [self decryptWithByteArray:inArg withInt:0 withInt:((IOSByteArray *) nil_chk(inArg))->size_ withInt:keyLen];
}

- (OrgSpongycastleCryptoParamsKeyParameter *)generateKeyWithJavaMathBigInteger:(JavaMathBigInteger *)n
                                                        withJavaMathBigInteger:(JavaMathBigInteger *)r
                                                                       withInt:(jint)keyLen {
  IOSByteArray *R = OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(([((JavaMathBigInteger *) nil_chk(n)) bitLength] + 7) / 8, r);
  [((id<OrgSpongycastleCryptoDerivationFunction>) nil_chk(kdf_)) init__WithOrgSpongycastleCryptoDerivationParameters:new_OrgSpongycastleCryptoParamsKDFParameters_initWithByteArray_withByteArray_(R, nil)];
  IOSByteArray *K = [IOSByteArray newArrayWithLength:keyLen];
  [((id<OrgSpongycastleCryptoDerivationFunction>) nil_chk(kdf_)) generateBytesWithByteArray:K withInt:0 withInt:K->size_];
  return new_OrgSpongycastleCryptoParamsKeyParameter_initWithByteArray_(K);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, 4, 5, 3, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, 4, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, 7, 8, 3, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, 7, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsKeyParameter;", 0x4, 9, 10, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoDerivationFunction:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(init__WithOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(encryptWithByteArray:withInt:withInt:);
  methods[3].selector = @selector(encryptWithByteArray:withInt:);
  methods[4].selector = @selector(decryptWithByteArray:withInt:withInt:withInt:);
  methods[5].selector = @selector(decryptWithByteArray:withInt:);
  methods[6].selector = @selector(generateKeyWithJavaMathBigInteger:withJavaMathBigInteger:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ZERO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 11, -1, -1 },
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 12, -1, -1 },
    { "kdf_", "LOrgSpongycastleCryptoDerivationFunction;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "rnd_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "key_", "LOrgSpongycastleCryptoParamsRSAKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoDerivationFunction;LJavaSecuritySecureRandom;", "init", "LOrgSpongycastleCryptoCipherParameters;", "LJavaLangIllegalArgumentException;", "encrypt", "[BII", "[BI", "decrypt", "[BIII", "generateKey", "LJavaMathBigInteger;LJavaMathBigInteger;I", &OrgSpongycastleCryptoKemsRSAKeyEncapsulation_ZERO, &OrgSpongycastleCryptoKemsRSAKeyEncapsulation_ONE };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoKemsRSAKeyEncapsulation = { "RSAKeyEncapsulation", "org.spongycastle.crypto.kems", ptrTable, methods, fields, 7, 0x1, 7, 5, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoKemsRSAKeyEncapsulation;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoKemsRSAKeyEncapsulation class]) {
    OrgSpongycastleCryptoKemsRSAKeyEncapsulation_ZERO = JavaMathBigInteger_valueOfWithLong_(0);
    OrgSpongycastleCryptoKemsRSAKeyEncapsulation_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoKemsRSAKeyEncapsulation)
  }
}

@end

void OrgSpongycastleCryptoKemsRSAKeyEncapsulation_initWithOrgSpongycastleCryptoDerivationFunction_withJavaSecuritySecureRandom_(OrgSpongycastleCryptoKemsRSAKeyEncapsulation *self, id<OrgSpongycastleCryptoDerivationFunction> kdf, JavaSecuritySecureRandom *rnd) {
  NSObject_init(self);
  self->kdf_ = kdf;
  self->rnd_ = rnd;
}

OrgSpongycastleCryptoKemsRSAKeyEncapsulation *new_OrgSpongycastleCryptoKemsRSAKeyEncapsulation_initWithOrgSpongycastleCryptoDerivationFunction_withJavaSecuritySecureRandom_(id<OrgSpongycastleCryptoDerivationFunction> kdf, JavaSecuritySecureRandom *rnd) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoKemsRSAKeyEncapsulation, initWithOrgSpongycastleCryptoDerivationFunction_withJavaSecuritySecureRandom_, kdf, rnd)
}

OrgSpongycastleCryptoKemsRSAKeyEncapsulation *create_OrgSpongycastleCryptoKemsRSAKeyEncapsulation_initWithOrgSpongycastleCryptoDerivationFunction_withJavaSecuritySecureRandom_(id<OrgSpongycastleCryptoDerivationFunction> kdf, JavaSecuritySecureRandom *rnd) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoKemsRSAKeyEncapsulation, initWithOrgSpongycastleCryptoDerivationFunction_withJavaSecuritySecureRandom_, kdf, rnd)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoKemsRSAKeyEncapsulation)