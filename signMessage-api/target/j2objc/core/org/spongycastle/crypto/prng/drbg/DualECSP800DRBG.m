//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/prng/drbg/DualECSP800DRBG.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/nist/NISTNamedCurves.h"
#include "org/spongycastle/asn1/x9/X9ECParameters.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/prng/EntropySource.h"
#include "org/spongycastle/crypto/prng/drbg/DualECPoints.h"
#include "org/spongycastle/crypto/prng/drbg/DualECSP800DRBG.h"
#include "org/spongycastle/crypto/prng/drbg/Utils.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/ECMultiplier.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/FixedPointCombMultiplier.h"
#include "org/spongycastle/util/Arrays.h"
#include "org/spongycastle/util/BigIntegers.h"

@interface OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG () {
 @public
  id<OrgSpongycastleCryptoDigest> _digest_;
  jlong _reseedCounter_;
  id<OrgSpongycastleCryptoPrngEntropySource> _entropySource_;
  jint _securityStrength_;
  jint _seedlen_;
  jint _outlen_;
  OrgSpongycastleMathEcECCurve_Fp *_curve_;
  OrgSpongycastleMathEcECPoint *_P_;
  OrgSpongycastleMathEcECPoint *_Q_;
  IOSByteArray *_s_;
  jint _sLength_;
  id<OrgSpongycastleMathEcECMultiplier> _fixedPointMultiplier_;
}

- (IOSByteArray *)getEntropy;

- (IOSByteArray *)xor__WithByteArray:(IOSByteArray *)a
                       withByteArray:(IOSByteArray *)b;

- (IOSByteArray *)pad8WithByteArray:(IOSByteArray *)s
                            withInt:(jint)seedlen;

- (JavaMathBigInteger *)getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)p
                                                         withJavaMathBigInteger:(JavaMathBigInteger *)s;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, _digest_, id<OrgSpongycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, _entropySource_, id<OrgSpongycastleCryptoPrngEntropySource>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, _curve_, OrgSpongycastleMathEcECCurve_Fp *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, _P_, OrgSpongycastleMathEcECPoint *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, _Q_, OrgSpongycastleMathEcECPoint *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, _s_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, _fixedPointMultiplier_, id<OrgSpongycastleMathEcECMultiplier>)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p256_Px(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Px;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p256_Px, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p256_Py(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Py;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p256_Py, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p256_Qx(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qx;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p256_Qx, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p256_Qy(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p256_Qy, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p384_Px(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Px;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p384_Px, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p384_Py(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Py;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p384_Py, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p384_Qx(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qx;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p384_Qx, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p384_Qy(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p384_Qy, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p521_Px(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Px;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p521_Px, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p521_Py(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Py;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p521_Py, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p521_Qx(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qx;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p521_Qx, JavaMathBigInteger *)

inline JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_p521_Qy(void);
static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qy;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, p521_Qy, JavaMathBigInteger *)

inline IOSObjectArray *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_nistPoints(void);
static IOSObjectArray *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, nistPoints, IOSObjectArray *)

inline jlong OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_RESEED_MAX(void);
#define OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_RESEED_MAX 2147483648LL
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, RESEED_MAX, jlong)

inline jint OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_MAX_ADDITIONAL_INPUT(void);
#define OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ADDITIONAL_INPUT 4096
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, MAX_ADDITIONAL_INPUT, jint)

inline jint OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_MAX_ENTROPY_LENGTH(void);
#define OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ENTROPY_LENGTH 4096
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, MAX_ENTROPY_LENGTH, jint)

inline jint OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_get_MAX_PERSONALIZATION_STRING(void);
#define OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_PERSONALIZATION_STRING 4096
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, MAX_PERSONALIZATION_STRING, jint)

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_xor__WithByteArray_withByteArray_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSByteArray *a, IOSByteArray *b);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_pad8WithByteArray_withInt_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSByteArray *s, jint seedlen);

__attribute__((unused)) static JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self, OrgSpongycastleMathEcECPoint *p, JavaMathBigInteger *s);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG)

@implementation OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                            withInt:(jint)securityStrength
         withOrgSpongycastleCryptoPrngEntropySource:(id<OrgSpongycastleCryptoPrngEntropySource>)entropySource
                                      withByteArray:(IOSByteArray *)personalizationString
                                      withByteArray:(IOSByteArray *)nonce {
  OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(self, digest, securityStrength, entropySource, personalizationString, nonce);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray:(IOSObjectArray *)pointSet
                                       withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                                               withInt:(jint)securityStrength
                            withOrgSpongycastleCryptoPrngEntropySource:(id<OrgSpongycastleCryptoPrngEntropySource>)entropySource
                                                         withByteArray:(IOSByteArray *)personalizationString
                                                         withByteArray:(IOSByteArray *)nonce {
  OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray_withOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(self, pointSet, digest, securityStrength, entropySource, personalizationString, nonce);
  return self;
}

- (jint)getBlockSize {
  return _outlen_ * 8;
}

- (jint)generateWithByteArray:(IOSByteArray *)output
                withByteArray:(IOSByteArray *)additionalInput
                  withBoolean:(jboolean)predictionResistant {
  jint numberOfBits = ((IOSByteArray *) nil_chk(output))->size_ * 8;
  jint m = output->size_ / _outlen_;
  if (OrgSpongycastleCryptoPrngDrbgUtils_isTooLargeWithByteArray_withInt_(additionalInput, OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ADDITIONAL_INPUT / 8)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Additional input too large");
  }
  if (_reseedCounter_ + m > OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_RESEED_MAX) {
    return -1;
  }
  if (predictionResistant) {
    [self reseedWithByteArray:additionalInput];
    additionalInput = nil;
  }
  JavaMathBigInteger *s;
  if (additionalInput != nil) {
    additionalInput = OrgSpongycastleCryptoPrngDrbgUtils_hash_dfWithOrgSpongycastleCryptoDigest_withByteArray_withInt_(_digest_, additionalInput, _seedlen_);
    s = new_JavaMathBigInteger_initWithInt_withByteArray_(1, OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_xor__WithByteArray_withByteArray_(self, _s_, additionalInput));
  }
  else {
    s = new_JavaMathBigInteger_initWithInt_withByteArray_(1, _s_);
  }
  OrgSpongycastleUtilArrays_fillWithByteArray_withByte_(output, (jbyte) 0);
  jint outOffset = 0;
  for (jint i = 0; i < m; i++) {
    s = OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(self, _P_, s);
    IOSByteArray *r = [((JavaMathBigInteger *) nil_chk(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(self, _Q_, s))) toByteArray];
    if (((IOSByteArray *) nil_chk(r))->size_ > _outlen_) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, r->size_ - _outlen_, output, outOffset, _outlen_);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, 0, output, outOffset + (_outlen_ - r->size_), r->size_);
    }
    outOffset += _outlen_;
    _reseedCounter_++;
  }
  if (outOffset < output->size_) {
    s = OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(self, _P_, s);
    IOSByteArray *r = [((JavaMathBigInteger *) nil_chk(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(self, _Q_, s))) toByteArray];
    jint required = output->size_ - outOffset;
    if (((IOSByteArray *) nil_chk(r))->size_ > _outlen_) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, r->size_ - _outlen_, output, outOffset, required);
    }
    else {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(r, 0, output, outOffset + (_outlen_ - r->size_), required);
    }
    _reseedCounter_++;
  }
  _s_ = OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(_sLength_, OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(self, _P_, s));
  return numberOfBits;
}

- (void)reseedWithByteArray:(IOSByteArray *)additionalInput {
  if (OrgSpongycastleCryptoPrngDrbgUtils_isTooLargeWithByteArray_withInt_(additionalInput, OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ADDITIONAL_INPUT / 8)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Additional input string too large");
  }
  IOSByteArray *entropy = OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(self);
  IOSByteArray *seedMaterial = OrgSpongycastleUtilArrays_concatenateWithByteArray_withByteArray_withByteArray_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_pad8WithByteArray_withInt_(self, _s_, _seedlen_), entropy, additionalInput);
  _s_ = OrgSpongycastleCryptoPrngDrbgUtils_hash_dfWithOrgSpongycastleCryptoDigest_withByteArray_withInt_(_digest_, seedMaterial, _seedlen_);
  _reseedCounter_ = 0;
}

- (IOSByteArray *)getEntropy {
  return OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(self);
}

- (IOSByteArray *)xor__WithByteArray:(IOSByteArray *)a
                       withByteArray:(IOSByteArray *)b {
  return OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_xor__WithByteArray_withByteArray_(self, a, b);
}

- (IOSByteArray *)pad8WithByteArray:(IOSByteArray *)s
                            withInt:(jint)seedlen {
  return OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_pad8WithByteArray_withInt_(self, s, seedlen);
}

- (JavaMathBigInteger *)getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)p
                                                         withJavaMathBigInteger:(JavaMathBigInteger *)s {
  return OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(self, p, s);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 10, 11, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoDigest:withInt:withOrgSpongycastleCryptoPrngEntropySource:withByteArray:withByteArray:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray:withOrgSpongycastleCryptoDigest:withInt:withOrgSpongycastleCryptoPrngEntropySource:withByteArray:withByteArray:);
  methods[2].selector = @selector(getBlockSize);
  methods[3].selector = @selector(generateWithByteArray:withByteArray:withBoolean:);
  methods[4].selector = @selector(reseedWithByteArray:);
  methods[5].selector = @selector(getEntropy);
  methods[6].selector = @selector(xor__WithByteArray:withByteArray:);
  methods[7].selector = @selector(pad8WithByteArray:withInt:);
  methods[8].selector = @selector(getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p256_Px", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 12, -1, -1 },
    { "p256_Py", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
    { "p256_Qx", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 14, -1, -1 },
    { "p256_Qy", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 15, -1, -1 },
    { "p384_Px", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 16, -1, -1 },
    { "p384_Py", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 17, -1, -1 },
    { "p384_Qx", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 18, -1, -1 },
    { "p384_Qy", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 19, -1, -1 },
    { "p521_Px", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 20, -1, -1 },
    { "p521_Py", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 21, -1, -1 },
    { "p521_Qx", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 22, -1, -1 },
    { "p521_Qy", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 23, -1, -1 },
    { "nistPoints", "[LOrgSpongycastleCryptoPrngDrbgDualECPoints;", .constantValue.asLong = 0, 0x1a, -1, 24, -1, -1 },
    { "RESEED_MAX", "J", .constantValue.asLong = OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_RESEED_MAX, 0x1a, -1, -1, -1, -1 },
    { "MAX_ADDITIONAL_INPUT", "I", .constantValue.asInt = OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ADDITIONAL_INPUT, 0x1a, -1, -1, -1, -1 },
    { "MAX_ENTROPY_LENGTH", "I", .constantValue.asInt = OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ENTROPY_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "MAX_PERSONALIZATION_STRING", "I", .constantValue.asInt = OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_PERSONALIZATION_STRING, 0x1a, -1, -1, -1, -1 },
    { "_digest_", "LOrgSpongycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_reseedCounter_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_entropySource_", "LOrgSpongycastleCryptoPrngEntropySource;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_securityStrength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_seedlen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_outlen_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_curve_", "LOrgSpongycastleMathEcECCurve_Fp;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_P_", "LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_Q_", "LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_s_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_sLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "_fixedPointMultiplier_", "LOrgSpongycastleMathEcECMultiplier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoDigest;ILOrgSpongycastleCryptoPrngEntropySource;[B[B", "[LOrgSpongycastleCryptoPrngDrbgDualECPoints;LOrgSpongycastleCryptoDigest;ILOrgSpongycastleCryptoPrngEntropySource;[B[B", "generate", "[B[BZ", "reseed", "[B", "xor", "[B[B", "pad8", "[BI", "getScalarMultipleXCoord", "LOrgSpongycastleMathEcECPoint;LJavaMathBigInteger;", &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Px, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Py, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qx, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qy, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Px, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Py, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qx, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qy, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Px, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Py, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qx, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qy, &OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG = { "DualECSP800DRBG", "org.spongycastle.crypto.prng.drbg", ptrTable, methods, fields, 7, 0x1, 9, 29, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG class]) {
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Px = new_JavaMathBigInteger_initWithNSString_withInt_(@"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Py = new_JavaMathBigInteger_initWithNSString_withInt_(@"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qx = new_JavaMathBigInteger_initWithNSString_withInt_(@"c97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qy = new_JavaMathBigInteger_initWithNSString_withInt_(@"b28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Px = new_JavaMathBigInteger_initWithNSString_withInt_(@"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Py = new_JavaMathBigInteger_initWithNSString_withInt_(@"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qx = new_JavaMathBigInteger_initWithNSString_withInt_(@"8e722de3125bddb05580164bfe20b8b432216a62926c57502ceede31c47816edd1e89769124179d0b695106428815065", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qy = new_JavaMathBigInteger_initWithNSString_withInt_(@"023b1660dd701d0839fd45eec36f9ee7b32e13b315dc02610aa1b636e346df671f790f84c5e09b05674dbb7e45c803dd", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Px = new_JavaMathBigInteger_initWithNSString_withInt_(@"c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Py = new_JavaMathBigInteger_initWithNSString_withInt_(@"11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qx = new_JavaMathBigInteger_initWithNSString_withInt_(@"1b9fa3e518d683c6b65763694ac8efbaec6fab44f2276171a42726507dd08add4c3b3f4c1ebc5b1222ddba077f722943b24c3edfa0f85fe24d0c8c01591f0be6f63", 16);
    OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qy = new_JavaMathBigInteger_initWithNSString_withInt_(@"1f3bdba585295d9a1110d1df1f9430ef8442c5018976ff3437ef91b81dc0b8132c8d5c39c32d0e004a3092b7d327c0e7a4d26d2c7b69b58f9066652911e457779de", 16);
    {
      OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints = [IOSObjectArray newArrayWithLength:3 type:OrgSpongycastleCryptoPrngDrbgDualECPoints_class_()];
      OrgSpongycastleMathEcECCurve_Fp *curve = (OrgSpongycastleMathEcECCurve_Fp *) cast_chk([((OrgSpongycastleAsn1X9X9ECParameters *) nil_chk(OrgSpongycastleAsn1NistNISTNamedCurves_getByNameWithNSString_(@"P-256"))) getCurve], [OrgSpongycastleMathEcECCurve_Fp class]);
      (void) IOSObjectArray_SetAndConsume(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints, 0, new_OrgSpongycastleCryptoPrngDrbgDualECPoints_initWithInt_withOrgSpongycastleMathEcECPoint_withOrgSpongycastleMathEcECPoint_withInt_(128, [((OrgSpongycastleMathEcECCurve_Fp *) nil_chk(curve)) createPointWithJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Px withJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Py], [curve createPointWithJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qx withJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p256_Qy], 1));
      curve = (OrgSpongycastleMathEcECCurve_Fp *) cast_chk([((OrgSpongycastleAsn1X9X9ECParameters *) nil_chk(OrgSpongycastleAsn1NistNISTNamedCurves_getByNameWithNSString_(@"P-384"))) getCurve], [OrgSpongycastleMathEcECCurve_Fp class]);
      (void) IOSObjectArray_SetAndConsume(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints, 1, new_OrgSpongycastleCryptoPrngDrbgDualECPoints_initWithInt_withOrgSpongycastleMathEcECPoint_withOrgSpongycastleMathEcECPoint_withInt_(192, [((OrgSpongycastleMathEcECCurve_Fp *) nil_chk(curve)) createPointWithJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Px withJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Py], [curve createPointWithJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qx withJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p384_Qy], 1));
      curve = (OrgSpongycastleMathEcECCurve_Fp *) cast_chk([((OrgSpongycastleAsn1X9X9ECParameters *) nil_chk(OrgSpongycastleAsn1NistNISTNamedCurves_getByNameWithNSString_(@"P-521"))) getCurve], [OrgSpongycastleMathEcECCurve_Fp class]);
      (void) IOSObjectArray_SetAndConsume(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints, 2, new_OrgSpongycastleCryptoPrngDrbgDualECPoints_initWithInt_withOrgSpongycastleMathEcECPoint_withOrgSpongycastleMathEcECPoint_withInt_(256, [((OrgSpongycastleMathEcECCurve_Fp *) nil_chk(curve)) createPointWithJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Px withJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Py], [curve createPointWithJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qx withJavaMathBigInteger:OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_p521_Qy], 1));
    }
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG)
  }
}

@end

void OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self, id<OrgSpongycastleCryptoDigest> digest, jint securityStrength, id<OrgSpongycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray_withOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(self, OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_nistPoints, digest, securityStrength, entropySource, personalizationString, nonce);
}

OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *new_OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(id<OrgSpongycastleCryptoDigest> digest, jint securityStrength, id<OrgSpongycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, initWithOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_, digest, securityStrength, entropySource, personalizationString, nonce)
}

OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *create_OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(id<OrgSpongycastleCryptoDigest> digest, jint securityStrength, id<OrgSpongycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, initWithOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_, digest, securityStrength, entropySource, personalizationString, nonce)
}

void OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray_withOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSObjectArray *pointSet, id<OrgSpongycastleCryptoDigest> digest, jint securityStrength, id<OrgSpongycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  NSObject_init(self);
  self->_fixedPointMultiplier_ = new_OrgSpongycastleMathEcFixedPointCombMultiplier_init();
  self->_digest_ = digest;
  self->_entropySource_ = entropySource;
  self->_securityStrength_ = securityStrength;
  if (OrgSpongycastleCryptoPrngDrbgUtils_isTooLargeWithByteArray_withInt_(personalizationString, OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_PERSONALIZATION_STRING / 8)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Personalization string too large");
  }
  if ([((id<OrgSpongycastleCryptoPrngEntropySource>) nil_chk(entropySource)) entropySize] < securityStrength || [entropySource entropySize] > OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ENTROPY_LENGTH) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I$I$", @"EntropySource must provide between ", securityStrength, @" and ", OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_MAX_ENTROPY_LENGTH, @" bits"));
  }
  IOSByteArray *entropy = OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(self);
  IOSByteArray *seedMaterial = OrgSpongycastleUtilArrays_concatenateWithByteArray_withByteArray_withByteArray_(entropy, nonce, personalizationString);
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(pointSet))->size_; i++) {
    if (securityStrength <= [((OrgSpongycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getSecurityStrength]) {
      if (OrgSpongycastleCryptoPrngDrbgUtils_getMaxSecurityStrengthWithOrgSpongycastleCryptoDigest_(digest) < [((OrgSpongycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getSecurityStrength]) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Requested security strength is not supported by digest");
      }
      self->_seedlen_ = [((OrgSpongycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getSeedLen];
      self->_outlen_ = [((OrgSpongycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getMaxOutlen] / 8;
      self->_P_ = [((OrgSpongycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getP];
      self->_Q_ = [((OrgSpongycastleCryptoPrngDrbgDualECPoints *) nil_chk(IOSObjectArray_Get(pointSet, i))) getQ];
      break;
    }
  }
  if (self->_P_ == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"security strength cannot be greater than 256 bits");
  }
  self->_s_ = OrgSpongycastleCryptoPrngDrbgUtils_hash_dfWithOrgSpongycastleCryptoDigest_withByteArray_withInt_(self->_digest_, seedMaterial, self->_seedlen_);
  self->_sLength_ = ((IOSByteArray *) nil_chk(self->_s_))->size_;
  self->_reseedCounter_ = 0;
}

OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *new_OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray_withOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(IOSObjectArray *pointSet, id<OrgSpongycastleCryptoDigest> digest, jint securityStrength, id<OrgSpongycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray_withOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_, pointSet, digest, securityStrength, entropySource, personalizationString, nonce)
}

OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *create_OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray_withOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_(IOSObjectArray *pointSet, id<OrgSpongycastleCryptoDigest> digest, jint securityStrength, id<OrgSpongycastleCryptoPrngEntropySource> entropySource, IOSByteArray *personalizationString, IOSByteArray *nonce) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG, initWithOrgSpongycastleCryptoPrngDrbgDualECPointsArray_withOrgSpongycastleCryptoDigest_withInt_withOrgSpongycastleCryptoPrngEntropySource_withByteArray_withByteArray_, pointSet, digest, securityStrength, entropySource, personalizationString, nonce)
}

IOSByteArray *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getEntropy(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self) {
  IOSByteArray *entropy = [((id<OrgSpongycastleCryptoPrngEntropySource>) nil_chk(self->_entropySource_)) getEntropy];
  if (((IOSByteArray *) nil_chk(entropy))->size_ < (self->_securityStrength_ + 7) / 8) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Insufficient entropy provided by entropy source");
  }
  return entropy;
}

IOSByteArray *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_xor__WithByteArray_withByteArray_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSByteArray *a, IOSByteArray *b) {
  if (b == nil) {
    return a;
  }
  IOSByteArray *rv = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(a))->size_];
  for (jint i = 0; i != rv->size_; i++) {
    *IOSByteArray_GetRef(rv, i) = (jbyte) (IOSByteArray_Get(a, i) ^ IOSByteArray_Get(b, i));
  }
  return rv;
}

IOSByteArray *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_pad8WithByteArray_withInt_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self, IOSByteArray *s, jint seedlen) {
  if (seedlen % 8 == 0) {
    return s;
  }
  jint shift = 8 - (seedlen % 8);
  jint carry = 0;
  for (jint i = ((IOSByteArray *) nil_chk(s))->size_ - 1; i >= 0; i--) {
    jint b = IOSByteArray_Get(s, i) & (jint) 0xff;
    *IOSByteArray_GetRef(s, i) = (jbyte) ((JreLShift32(b, shift)) | (JreRShift32(carry, (8 - shift))));
    carry = b;
  }
  return s;
}

JavaMathBigInteger *OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG_getScalarMultipleXCoordWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG *self, OrgSpongycastleMathEcECPoint *p, JavaMathBigInteger *s) {
  return [((OrgSpongycastleMathEcECFieldElement *) nil_chk([((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleMathEcECPoint *) nil_chk([((id<OrgSpongycastleMathEcECMultiplier>) nil_chk(self->_fixedPointMultiplier_)) multiplyWithOrgSpongycastleMathEcECPoint:p withJavaMathBigInteger:s])) normalize])) getAffineXCoord])) toBigInteger];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoPrngDrbgDualECSP800DRBG)
