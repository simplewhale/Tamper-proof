//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/signers/SM2Signer.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/digests/SM3Digest.h"
#include "org/spongycastle/crypto/params/ECDomainParameters.h"
#include "org/spongycastle/crypto/params/ECKeyParameters.h"
#include "org/spongycastle/crypto/params/ECPrivateKeyParameters.h"
#include "org/spongycastle/crypto/params/ECPublicKeyParameters.h"
#include "org/spongycastle/crypto/params/ParametersWithID.h"
#include "org/spongycastle/crypto/params/ParametersWithRandom.h"
#include "org/spongycastle/crypto/signers/DSAKCalculator.h"
#include "org/spongycastle/crypto/signers/RandomDSAKCalculator.h"
#include "org/spongycastle/crypto/signers/SM2Signer.h"
#include "org/spongycastle/math/ec/ECConstants.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/ECMultiplier.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/FixedPointCombMultiplier.h"
#include "org/spongycastle/util/BigIntegers.h"

@interface OrgSpongycastleCryptoSignersSM2Signer () {
 @public
  id<OrgSpongycastleCryptoSignersDSAKCalculator> kCalculator_;
  IOSByteArray *userID_;
  jint curveLength_;
  OrgSpongycastleCryptoParamsECDomainParameters *ecParams_;
  OrgSpongycastleMathEcECPoint *pubPoint_;
  OrgSpongycastleCryptoParamsECKeyParameters *ecKey_;
  JavaSecuritySecureRandom *random_;
}

- (IOSByteArray *)getZWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest;

- (void)addUserIDWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                   withByteArray:(IOSByteArray *)userID;

- (void)addFieldElementWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
               withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)v;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersSM2Signer, kCalculator_, id<OrgSpongycastleCryptoSignersDSAKCalculator>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersSM2Signer, userID_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersSM2Signer, ecParams_, OrgSpongycastleCryptoParamsECDomainParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersSM2Signer, pubPoint_, OrgSpongycastleMathEcECPoint *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersSM2Signer, ecKey_, OrgSpongycastleCryptoParamsECKeyParameters *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoSignersSM2Signer, random_, JavaSecuritySecureRandom *)

__attribute__((unused)) static IOSByteArray *OrgSpongycastleCryptoSignersSM2Signer_getZWithOrgSpongycastleCryptoDigest_(OrgSpongycastleCryptoSignersSM2Signer *self, id<OrgSpongycastleCryptoDigest> digest);

__attribute__((unused)) static void OrgSpongycastleCryptoSignersSM2Signer_addUserIDWithOrgSpongycastleCryptoDigest_withByteArray_(OrgSpongycastleCryptoSignersSM2Signer *self, id<OrgSpongycastleCryptoDigest> digest, IOSByteArray *userID);

__attribute__((unused)) static void OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleCryptoSignersSM2Signer *self, id<OrgSpongycastleCryptoDigest> digest, OrgSpongycastleMathEcECFieldElement *v);

@implementation OrgSpongycastleCryptoSignersSM2Signer

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoSignersSM2Signer_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forSigning
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param {
  id<OrgSpongycastleCryptoCipherParameters> baseParam;
  if ([param isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithID class]]) {
    baseParam = [((OrgSpongycastleCryptoParamsParametersWithID *) nil_chk(((OrgSpongycastleCryptoParamsParametersWithID *) param))) getParameters];
    userID_ = [((OrgSpongycastleCryptoParamsParametersWithID *) nil_chk(((OrgSpongycastleCryptoParamsParametersWithID *) param))) getID];
  }
  else {
    baseParam = param;
    userID_ = [IOSByteArray newArrayWithLength:0];
  }
  if (forSigning) {
    if ([baseParam isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithRandom class]]) {
      OrgSpongycastleCryptoParamsParametersWithRandom *rParam = (OrgSpongycastleCryptoParamsParametersWithRandom *) baseParam;
      ecKey_ = (OrgSpongycastleCryptoParamsECKeyParameters *) cast_chk([((OrgSpongycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getParameters], [OrgSpongycastleCryptoParamsECKeyParameters class]);
      ecParams_ = [((OrgSpongycastleCryptoParamsECKeyParameters *) nil_chk(ecKey_)) getParameters];
      [((id<OrgSpongycastleCryptoSignersDSAKCalculator>) nil_chk(kCalculator_)) init__WithJavaMathBigInteger:[((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ecParams_)) getN] withJavaSecuritySecureRandom:[rParam getRandom]];
    }
    else {
      ecKey_ = (OrgSpongycastleCryptoParamsECKeyParameters *) cast_chk(baseParam, [OrgSpongycastleCryptoParamsECKeyParameters class]);
      ecParams_ = [((OrgSpongycastleCryptoParamsECKeyParameters *) nil_chk(ecKey_)) getParameters];
      [((id<OrgSpongycastleCryptoSignersDSAKCalculator>) nil_chk(kCalculator_)) init__WithJavaMathBigInteger:[((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ecParams_)) getN] withJavaSecuritySecureRandom:new_JavaSecuritySecureRandom_init()];
    }
    pubPoint_ = [((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ecParams_)) getG])) multiplyWithJavaMathBigInteger:[((OrgSpongycastleCryptoParamsECPrivateKeyParameters *) nil_chk(((OrgSpongycastleCryptoParamsECPrivateKeyParameters *) cast_chk(ecKey_, [OrgSpongycastleCryptoParamsECPrivateKeyParameters class])))) getD]])) normalize];
  }
  else {
    ecKey_ = (OrgSpongycastleCryptoParamsECKeyParameters *) cast_chk(baseParam, [OrgSpongycastleCryptoParamsECKeyParameters class]);
    ecParams_ = [((OrgSpongycastleCryptoParamsECKeyParameters *) nil_chk(ecKey_)) getParameters];
    pubPoint_ = [((OrgSpongycastleCryptoParamsECPublicKeyParameters *) nil_chk(((OrgSpongycastleCryptoParamsECPublicKeyParameters *) cast_chk(ecKey_, [OrgSpongycastleCryptoParamsECPublicKeyParameters class])))) getQ];
  }
  curveLength_ = ([((OrgSpongycastleMathEcECCurve *) nil_chk([((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ecParams_)) getCurve])) getFieldSize] + 7) / 8;
}

- (IOSObjectArray *)generateSignatureWithByteArray:(IOSByteArray *)message {
  OrgSpongycastleCryptoDigestsSM3Digest *digest = new_OrgSpongycastleCryptoDigestsSM3Digest_init();
  IOSByteArray *z = OrgSpongycastleCryptoSignersSM2Signer_getZWithOrgSpongycastleCryptoDigest_(self, digest);
  [digest updateWithByteArray:z withInt:0 withInt:((IOSByteArray *) nil_chk(z))->size_];
  [digest updateWithByteArray:message withInt:0 withInt:((IOSByteArray *) nil_chk(message))->size_];
  IOSByteArray *eHash = [IOSByteArray newArrayWithLength:[digest getDigestSize]];
  [digest doFinalWithByteArray:eHash withInt:0];
  JavaMathBigInteger *n = [((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ecParams_)) getN];
  JavaMathBigInteger *e = [self calculateEWithByteArray:eHash];
  JavaMathBigInteger *d = [((OrgSpongycastleCryptoParamsECPrivateKeyParameters *) nil_chk(((OrgSpongycastleCryptoParamsECPrivateKeyParameters *) cast_chk(ecKey_, [OrgSpongycastleCryptoParamsECPrivateKeyParameters class])))) getD];
  JavaMathBigInteger *r;
  JavaMathBigInteger *s;
  id<OrgSpongycastleMathEcECMultiplier> basePointMultiplier = [self createBasePointMultiplier];
  do {
    JavaMathBigInteger *k;
    do {
      k = [((id<OrgSpongycastleCryptoSignersDSAKCalculator>) nil_chk(kCalculator_)) nextK];
      OrgSpongycastleMathEcECPoint *p = [((OrgSpongycastleMathEcECPoint *) nil_chk([((id<OrgSpongycastleMathEcECMultiplier>) nil_chk(basePointMultiplier)) multiplyWithOrgSpongycastleMathEcECPoint:[((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ecParams_)) getG] withJavaMathBigInteger:k])) normalize];
      r = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(e)) addWithJavaMathBigInteger:[((OrgSpongycastleMathEcECFieldElement *) nil_chk([((OrgSpongycastleMathEcECPoint *) nil_chk(p)) getAffineXCoord])) toBigInteger]])) modWithJavaMathBigInteger:n];
    }
    while ([((JavaMathBigInteger *) nil_chk(r)) isEqual:JreLoadStatic(OrgSpongycastleMathEcECConstants, ZERO)] || [((JavaMathBigInteger *) nil_chk([r addWithJavaMathBigInteger:k])) isEqual:n]);
    JavaMathBigInteger *dPlus1ModN = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(d)) addWithJavaMathBigInteger:JreLoadStatic(OrgSpongycastleMathEcECConstants, ONE)])) modInverseWithJavaMathBigInteger:n];
    s = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(k)) subtractWithJavaMathBigInteger:[r multiplyWithJavaMathBigInteger:d]])) modWithJavaMathBigInteger:n];
    s = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(dPlus1ModN)) multiplyWithJavaMathBigInteger:s])) modWithJavaMathBigInteger:n];
  }
  while ([((JavaMathBigInteger *) nil_chk(s)) isEqual:JreLoadStatic(OrgSpongycastleMathEcECConstants, ZERO)]);
  return [IOSObjectArray newArrayWithObjects:(id[]){ r, s } count:2 type:JavaMathBigInteger_class_()];
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                  withJavaMathBigInteger:(JavaMathBigInteger *)r
                  withJavaMathBigInteger:(JavaMathBigInteger *)s {
  JavaMathBigInteger *n = [((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ecParams_)) getN];
  if ([((JavaMathBigInteger *) nil_chk(r)) compareToWithId:JreLoadStatic(OrgSpongycastleMathEcECConstants, ONE)] < 0 || [r compareToWithId:n] >= 0) {
    return false;
  }
  if ([((JavaMathBigInteger *) nil_chk(s)) compareToWithId:JreLoadStatic(OrgSpongycastleMathEcECConstants, ONE)] < 0 || [s compareToWithId:n] >= 0) {
    return false;
  }
  OrgSpongycastleMathEcECPoint *q = [((OrgSpongycastleCryptoParamsECPublicKeyParameters *) nil_chk(((OrgSpongycastleCryptoParamsECPublicKeyParameters *) cast_chk(ecKey_, [OrgSpongycastleCryptoParamsECPublicKeyParameters class])))) getQ];
  OrgSpongycastleCryptoDigestsSM3Digest *digest = new_OrgSpongycastleCryptoDigestsSM3Digest_init();
  IOSByteArray *z = OrgSpongycastleCryptoSignersSM2Signer_getZWithOrgSpongycastleCryptoDigest_(self, digest);
  [digest updateWithByteArray:z withInt:0 withInt:((IOSByteArray *) nil_chk(z))->size_];
  [digest updateWithByteArray:message withInt:0 withInt:((IOSByteArray *) nil_chk(message))->size_];
  IOSByteArray *eHash = [IOSByteArray newArrayWithLength:[digest getDigestSize]];
  [digest doFinalWithByteArray:eHash withInt:0];
  JavaMathBigInteger *e = [self calculateEWithByteArray:eHash];
  JavaMathBigInteger *t = [((JavaMathBigInteger *) nil_chk([r addWithJavaMathBigInteger:s])) modWithJavaMathBigInteger:n];
  if ([((JavaMathBigInteger *) nil_chk(t)) isEqual:JreLoadStatic(OrgSpongycastleMathEcECConstants, ZERO)]) {
    return false;
  }
  else {
    OrgSpongycastleMathEcECPoint *x1y1 = [((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ecParams_)) getG])) multiplyWithJavaMathBigInteger:s];
    x1y1 = [((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleMathEcECPoint *) nil_chk(x1y1)) addWithOrgSpongycastleMathEcECPoint:[((OrgSpongycastleMathEcECPoint *) nil_chk(q)) multiplyWithJavaMathBigInteger:t]])) normalize];
    return [r isEqual:[((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(e)) addWithJavaMathBigInteger:[((OrgSpongycastleMathEcECFieldElement *) nil_chk([((OrgSpongycastleMathEcECPoint *) nil_chk(x1y1)) getAffineXCoord])) toBigInteger]])) modWithJavaMathBigInteger:n]];
  }
}

- (IOSByteArray *)getZWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest {
  return OrgSpongycastleCryptoSignersSM2Signer_getZWithOrgSpongycastleCryptoDigest_(self, digest);
}

- (void)addUserIDWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
                                   withByteArray:(IOSByteArray *)userID {
  OrgSpongycastleCryptoSignersSM2Signer_addUserIDWithOrgSpongycastleCryptoDigest_withByteArray_(self, digest, userID);
}

- (void)addFieldElementWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest
               withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)v {
  OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(self, digest, v);
}

- (id<OrgSpongycastleMathEcECMultiplier>)createBasePointMultiplier {
  return new_OrgSpongycastleMathEcFixedPointCombMultiplier_init();
}

- (JavaMathBigInteger *)calculateEWithByteArray:(IOSByteArray *)message {
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, message);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[LJavaMathBigInteger;", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 10, 11, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECMultiplier;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x4, 12, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(generateSignatureWithByteArray:);
  methods[3].selector = @selector(verifySignatureWithByteArray:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[4].selector = @selector(getZWithOrgSpongycastleCryptoDigest:);
  methods[5].selector = @selector(addUserIDWithOrgSpongycastleCryptoDigest:withByteArray:);
  methods[6].selector = @selector(addFieldElementWithOrgSpongycastleCryptoDigest:withOrgSpongycastleMathEcECFieldElement:);
  methods[7].selector = @selector(createBasePointMultiplier);
  methods[8].selector = @selector(calculateEWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "kCalculator_", "LOrgSpongycastleCryptoSignersDSAKCalculator;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "userID_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "curveLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ecParams_", "LOrgSpongycastleCryptoParamsECDomainParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pubPoint_", "LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ecKey_", "LOrgSpongycastleCryptoParamsECKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLOrgSpongycastleCryptoCipherParameters;", "generateSignature", "[B", "verifySignature", "[BLJavaMathBigInteger;LJavaMathBigInteger;", "getZ", "LOrgSpongycastleCryptoDigest;", "addUserID", "LOrgSpongycastleCryptoDigest;[B", "addFieldElement", "LOrgSpongycastleCryptoDigest;LOrgSpongycastleMathEcECFieldElement;", "calculateE" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoSignersSM2Signer = { "SM2Signer", "org.spongycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 9, 7, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoSignersSM2Signer;
}

@end

void OrgSpongycastleCryptoSignersSM2Signer_init(OrgSpongycastleCryptoSignersSM2Signer *self) {
  NSObject_init(self);
  self->kCalculator_ = new_OrgSpongycastleCryptoSignersRandomDSAKCalculator_init();
}

OrgSpongycastleCryptoSignersSM2Signer *new_OrgSpongycastleCryptoSignersSM2Signer_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoSignersSM2Signer, init)
}

OrgSpongycastleCryptoSignersSM2Signer *create_OrgSpongycastleCryptoSignersSM2Signer_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoSignersSM2Signer, init)
}

IOSByteArray *OrgSpongycastleCryptoSignersSM2Signer_getZWithOrgSpongycastleCryptoDigest_(OrgSpongycastleCryptoSignersSM2Signer *self, id<OrgSpongycastleCryptoDigest> digest) {
  OrgSpongycastleCryptoSignersSM2Signer_addUserIDWithOrgSpongycastleCryptoDigest_withByteArray_(self, digest, self->userID_);
  OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(self, digest, [((OrgSpongycastleMathEcECCurve *) nil_chk([((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(self->ecParams_)) getCurve])) getA]);
  OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(self, digest, [((OrgSpongycastleMathEcECCurve *) nil_chk([((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(self->ecParams_)) getCurve])) getB]);
  OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(self, digest, [((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(self->ecParams_)) getG])) getAffineXCoord]);
  OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(self, digest, [((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(self->ecParams_)) getG])) getAffineYCoord]);
  OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(self, digest, [((OrgSpongycastleMathEcECPoint *) nil_chk(self->pubPoint_)) getAffineXCoord]);
  OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(self, digest, [((OrgSpongycastleMathEcECPoint *) nil_chk(self->pubPoint_)) getAffineYCoord]);
  IOSByteArray *rv = [IOSByteArray newArrayWithLength:[((id<OrgSpongycastleCryptoDigest>) nil_chk(digest)) getDigestSize]];
  [digest doFinalWithByteArray:rv withInt:0];
  return rv;
}

void OrgSpongycastleCryptoSignersSM2Signer_addUserIDWithOrgSpongycastleCryptoDigest_withByteArray_(OrgSpongycastleCryptoSignersSM2Signer *self, id<OrgSpongycastleCryptoDigest> digest, IOSByteArray *userID) {
  jint len = ((IOSByteArray *) nil_chk(userID))->size_ * 8;
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest)) updateWithByte:(jbyte) ((JreRShift32(len, 8)) & (jint) 0xFF)];
  [digest updateWithByte:(jbyte) (len & (jint) 0xFF)];
  [digest updateWithByteArray:userID withInt:0 withInt:userID->size_];
}

void OrgSpongycastleCryptoSignersSM2Signer_addFieldElementWithOrgSpongycastleCryptoDigest_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleCryptoSignersSM2Signer *self, id<OrgSpongycastleCryptoDigest> digest, OrgSpongycastleMathEcECFieldElement *v) {
  IOSByteArray *p = OrgSpongycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(self->curveLength_, [((OrgSpongycastleMathEcECFieldElement *) nil_chk(v)) toBigInteger]);
  [((id<OrgSpongycastleCryptoDigest>) nil_chk(digest)) updateWithByteArray:p withInt:0 withInt:((IOSByteArray *) nil_chk(p))->size_];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoSignersSM2Signer)
