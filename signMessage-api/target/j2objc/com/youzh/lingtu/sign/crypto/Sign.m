//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/Sign.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/ECDSASignature.h"
#include "com/youzh/lingtu/sign/crypto/ECKeyPair.h"
#include "com/youzh/lingtu/sign/crypto/Hash.h"
#include "com/youzh/lingtu/sign/crypto/Sign.h"
#include "com/youzh/lingtu/sign/crypto/utils/Assertions.h"
#include "com/youzh/lingtu/sign/crypto/utils/Numeric.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "java/security/SignatureException.h"
#include "java/util/Arrays.h"
#include "org/spongycastle/asn1/x9/X9ECParameters.h"
#include "org/spongycastle/asn1/x9/X9IntegerConverter.h"
#include "org/spongycastle/crypto/ec/CustomNamedCurves.h"
#include "org/spongycastle/crypto/params/ECDomainParameters.h"
#include "org/spongycastle/math/ec/ECAlgorithms.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/FixedPointCombMultiplier.h"
#include "org/spongycastle/math/ec/custom/sec/SecP256K1Curve.h"

@interface ComYouzhLingtuSignCryptoSign ()

+ (JavaMathBigInteger *)recoverFromSignatureWithInt:(jint)recId
         withComYouzhLingtuSignCryptoECDSASignature:(ComYouzhLingtuSignCryptoECDSASignature *)sig
                                      withByteArray:(IOSByteArray *)message;

+ (OrgSpongycastleMathEcECPoint *)decompressKeyWithJavaMathBigInteger:(JavaMathBigInteger *)xBN
                                                          withBoolean:(jboolean)yBit;

+ (OrgSpongycastleMathEcECPoint *)publicPointFromPrivateWithJavaMathBigInteger:(JavaMathBigInteger *)privKey;

@end

inline OrgSpongycastleAsn1X9X9ECParameters *ComYouzhLingtuSignCryptoSign_get_CURVE_PARAMS(void);
static OrgSpongycastleAsn1X9X9ECParameters *ComYouzhLingtuSignCryptoSign_CURVE_PARAMS;
J2OBJC_STATIC_FIELD_OBJ_FINAL(ComYouzhLingtuSignCryptoSign, CURVE_PARAMS, OrgSpongycastleAsn1X9X9ECParameters *)

__attribute__((unused)) static JavaMathBigInteger *ComYouzhLingtuSignCryptoSign_recoverFromSignatureWithInt_withComYouzhLingtuSignCryptoECDSASignature_withByteArray_(jint recId, ComYouzhLingtuSignCryptoECDSASignature *sig, IOSByteArray *message);

__attribute__((unused)) static OrgSpongycastleMathEcECPoint *ComYouzhLingtuSignCryptoSign_decompressKeyWithJavaMathBigInteger_withBoolean_(JavaMathBigInteger *xBN, jboolean yBit);

__attribute__((unused)) static OrgSpongycastleMathEcECPoint *ComYouzhLingtuSignCryptoSign_publicPointFromPrivateWithJavaMathBigInteger_(JavaMathBigInteger *privKey);

@interface ComYouzhLingtuSignCryptoSign_SignatureData () {
 @public
  jbyte v_;
  IOSByteArray *r_;
  IOSByteArray *s_;
}

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoSign_SignatureData, r_, IOSByteArray *)
J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoSign_SignatureData, s_, IOSByteArray *)

J2OBJC_INITIALIZED_DEFN(ComYouzhLingtuSignCryptoSign)

OrgSpongycastleCryptoParamsECDomainParameters *ComYouzhLingtuSignCryptoSign_CURVE;
JavaMathBigInteger *ComYouzhLingtuSignCryptoSign_HALF_CURVE_ORDER;

@implementation ComYouzhLingtuSignCryptoSign

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  ComYouzhLingtuSignCryptoSign_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (ComYouzhLingtuSignCryptoSign_SignatureData *)signMessageWithByteArray:(IOSByteArray *)message
                                   withComYouzhLingtuSignCryptoECKeyPair:(ComYouzhLingtuSignCryptoECKeyPair *)keyPair {
  return ComYouzhLingtuSignCryptoSign_signMessageWithByteArray_withComYouzhLingtuSignCryptoECKeyPair_(message, keyPair);
}

+ (ComYouzhLingtuSignCryptoSign_SignatureData *)signMessageWithByteArray:(IOSByteArray *)message
                                   withComYouzhLingtuSignCryptoECKeyPair:(ComYouzhLingtuSignCryptoECKeyPair *)keyPair
                                                             withBoolean:(jboolean)isHashed {
  return ComYouzhLingtuSignCryptoSign_signMessageWithByteArray_withComYouzhLingtuSignCryptoECKeyPair_withBoolean_(message, keyPair, isHashed);
}

+ (JavaMathBigInteger *)recoverFromSignatureWithInt:(jint)recId
         withComYouzhLingtuSignCryptoECDSASignature:(ComYouzhLingtuSignCryptoECDSASignature *)sig
                                      withByteArray:(IOSByteArray *)message {
  return ComYouzhLingtuSignCryptoSign_recoverFromSignatureWithInt_withComYouzhLingtuSignCryptoECDSASignature_withByteArray_(recId, sig, message);
}

+ (OrgSpongycastleMathEcECPoint *)decompressKeyWithJavaMathBigInteger:(JavaMathBigInteger *)xBN
                                                          withBoolean:(jboolean)yBit {
  return ComYouzhLingtuSignCryptoSign_decompressKeyWithJavaMathBigInteger_withBoolean_(xBN, yBit);
}

+ (JavaMathBigInteger *)signedMessageToKeyWithByteArray:(IOSByteArray *)message
         withComYouzhLingtuSignCryptoSign_SignatureData:(ComYouzhLingtuSignCryptoSign_SignatureData *)signatureData {
  return ComYouzhLingtuSignCryptoSign_signedMessageToKeyWithByteArray_withComYouzhLingtuSignCryptoSign_SignatureData_(message, signatureData);
}

+ (JavaMathBigInteger *)publicKeyFromPrivateWithJavaMathBigInteger:(JavaMathBigInteger *)privKey {
  return ComYouzhLingtuSignCryptoSign_publicKeyFromPrivateWithJavaMathBigInteger_(privKey);
}

+ (OrgSpongycastleMathEcECPoint *)publicPointFromPrivateWithJavaMathBigInteger:(JavaMathBigInteger *)privKey {
  return ComYouzhLingtuSignCryptoSign_publicPointFromPrivateWithJavaMathBigInteger_(privKey);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LComYouzhLingtuSignCryptoSign_SignatureData;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LComYouzhLingtuSignCryptoSign_SignatureData;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0xa, 3, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0xa, 5, 6, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 7, 8, 9, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 10, 11, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0xa, 12, 11, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(signMessageWithByteArray:withComYouzhLingtuSignCryptoECKeyPair:);
  methods[2].selector = @selector(signMessageWithByteArray:withComYouzhLingtuSignCryptoECKeyPair:withBoolean:);
  methods[3].selector = @selector(recoverFromSignatureWithInt:withComYouzhLingtuSignCryptoECDSASignature:withByteArray:);
  methods[4].selector = @selector(decompressKeyWithJavaMathBigInteger:withBoolean:);
  methods[5].selector = @selector(signedMessageToKeyWithByteArray:withComYouzhLingtuSignCryptoSign_SignatureData:);
  methods[6].selector = @selector(publicKeyFromPrivateWithJavaMathBigInteger:);
  methods[7].selector = @selector(publicPointFromPrivateWithJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "CURVE_PARAMS", "LOrgSpongycastleAsn1X9X9ECParameters;", .constantValue.asLong = 0, 0x1a, -1, 13, -1, -1 },
    { "CURVE", "LOrgSpongycastleCryptoParamsECDomainParameters;", .constantValue.asLong = 0, 0x18, -1, 14, -1, -1 },
    { "HALF_CURVE_ORDER", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x18, -1, 15, -1, -1 },
  };
  static const void *ptrTable[] = { "signMessage", "[BLComYouzhLingtuSignCryptoECKeyPair;", "[BLComYouzhLingtuSignCryptoECKeyPair;Z", "recoverFromSignature", "ILComYouzhLingtuSignCryptoECDSASignature;[B", "decompressKey", "LJavaMathBigInteger;Z", "signedMessageToKey", "[BLComYouzhLingtuSignCryptoSign_SignatureData;", "LJavaSecuritySignatureException;", "publicKeyFromPrivate", "LJavaMathBigInteger;", "publicPointFromPrivate", &ComYouzhLingtuSignCryptoSign_CURVE_PARAMS, &ComYouzhLingtuSignCryptoSign_CURVE, &ComYouzhLingtuSignCryptoSign_HALF_CURVE_ORDER, "LComYouzhLingtuSignCryptoSign_SignatureData;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoSign = { "Sign", "com.youzh.lingtu.sign.crypto", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, 16, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoSign;
}

+ (void)initialize {
  if (self == [ComYouzhLingtuSignCryptoSign class]) {
    ComYouzhLingtuSignCryptoSign_CURVE_PARAMS = OrgSpongycastleCryptoEcCustomNamedCurves_getByNameWithNSString_(@"secp256k1");
    ComYouzhLingtuSignCryptoSign_CURVE = new_OrgSpongycastleCryptoParamsECDomainParameters_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_([((OrgSpongycastleAsn1X9X9ECParameters *) nil_chk(ComYouzhLingtuSignCryptoSign_CURVE_PARAMS)) getCurve], [ComYouzhLingtuSignCryptoSign_CURVE_PARAMS getG], [ComYouzhLingtuSignCryptoSign_CURVE_PARAMS getN], [ComYouzhLingtuSignCryptoSign_CURVE_PARAMS getH]);
    ComYouzhLingtuSignCryptoSign_HALF_CURVE_ORDER = [((JavaMathBigInteger *) nil_chk([ComYouzhLingtuSignCryptoSign_CURVE_PARAMS getN])) shiftRightWithInt:1];
    J2OBJC_SET_INITIALIZED(ComYouzhLingtuSignCryptoSign)
  }
}

@end

void ComYouzhLingtuSignCryptoSign_init(ComYouzhLingtuSignCryptoSign *self) {
  NSObject_init(self);
}

ComYouzhLingtuSignCryptoSign *new_ComYouzhLingtuSignCryptoSign_init() {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoSign, init)
}

ComYouzhLingtuSignCryptoSign *create_ComYouzhLingtuSignCryptoSign_init() {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoSign, init)
}

ComYouzhLingtuSignCryptoSign_SignatureData *ComYouzhLingtuSignCryptoSign_signMessageWithByteArray_withComYouzhLingtuSignCryptoECKeyPair_(IOSByteArray *message, ComYouzhLingtuSignCryptoECKeyPair *keyPair) {
  ComYouzhLingtuSignCryptoSign_initialize();
  return ComYouzhLingtuSignCryptoSign_signMessageWithByteArray_withComYouzhLingtuSignCryptoECKeyPair_withBoolean_(message, keyPair, true);
}

ComYouzhLingtuSignCryptoSign_SignatureData *ComYouzhLingtuSignCryptoSign_signMessageWithByteArray_withComYouzhLingtuSignCryptoECKeyPair_withBoolean_(IOSByteArray *message, ComYouzhLingtuSignCryptoECKeyPair *keyPair, jboolean isHashed) {
  ComYouzhLingtuSignCryptoSign_initialize();
  JavaMathBigInteger *publicKey = [((ComYouzhLingtuSignCryptoECKeyPair *) nil_chk(keyPair)) getPublicKey];
  IOSByteArray *messageHash;
  if (isHashed) {
    messageHash = ComYouzhLingtuSignCryptoHash_sha3WithByteArray_(message);
  }
  else {
    messageHash = message;
  }
  ComYouzhLingtuSignCryptoECDSASignature *sig = [keyPair signWithByteArray:messageHash];
  jint recId = -1;
  for (jint i = 0; i < 4; i++) {
    JavaMathBigInteger *k = ComYouzhLingtuSignCryptoSign_recoverFromSignatureWithInt_withComYouzhLingtuSignCryptoECDSASignature_withByteArray_(i, sig, messageHash);
    if (k != nil && [k isEqual:publicKey]) {
      recId = i;
      break;
    }
  }
  if (recId == -1) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"Could not construct a recoverable key. This should never happen.");
  }
  jint headerByte = recId + 27;
  jbyte v = (jbyte) headerByte;
  IOSByteArray *r = ComYouzhLingtuSignCryptoUtilsNumeric_toBytesPaddedWithJavaMathBigInteger_withInt_(((ComYouzhLingtuSignCryptoECDSASignature *) nil_chk(sig))->r_, 32);
  IOSByteArray *s = ComYouzhLingtuSignCryptoUtilsNumeric_toBytesPaddedWithJavaMathBigInteger_withInt_(sig->s_, 32);
  return new_ComYouzhLingtuSignCryptoSign_SignatureData_initWithByte_withByteArray_withByteArray_(v, r, s);
}

JavaMathBigInteger *ComYouzhLingtuSignCryptoSign_recoverFromSignatureWithInt_withComYouzhLingtuSignCryptoECDSASignature_withByteArray_(jint recId, ComYouzhLingtuSignCryptoECDSASignature *sig, IOSByteArray *message) {
  ComYouzhLingtuSignCryptoSign_initialize();
  ComYouzhLingtuSignCryptoUtilsAssertions_verifyPreconditionWithBoolean_withNSString_(recId >= 0, @"recId must be positive");
  ComYouzhLingtuSignCryptoUtilsAssertions_verifyPreconditionWithBoolean_withNSString_([((JavaMathBigInteger *) nil_chk(((ComYouzhLingtuSignCryptoECDSASignature *) nil_chk(sig))->r_)) signum] >= 0, @"r must be positive");
  ComYouzhLingtuSignCryptoUtilsAssertions_verifyPreconditionWithBoolean_withNSString_([((JavaMathBigInteger *) nil_chk(sig->s_)) signum] >= 0, @"s must be positive");
  ComYouzhLingtuSignCryptoUtilsAssertions_verifyPreconditionWithBoolean_withNSString_(message != nil, @"message cannot be null");
  JavaMathBigInteger *n = [((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ComYouzhLingtuSignCryptoSign_CURVE)) getN];
  JavaMathBigInteger *i = JavaMathBigInteger_valueOfWithLong_((jlong) recId / 2);
  JavaMathBigInteger *x = [sig->r_ addWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(i)) multiplyWithJavaMathBigInteger:n]];
  JavaMathBigInteger *prime = JreLoadStatic(OrgSpongycastleMathEcCustomSecSecP256K1Curve, q);
  if ([((JavaMathBigInteger *) nil_chk(x)) compareToWithId:prime] >= 0) {
    return nil;
  }
  OrgSpongycastleMathEcECPoint *R = ComYouzhLingtuSignCryptoSign_decompressKeyWithJavaMathBigInteger_withBoolean_(x, (recId & 1) == 1);
  if (![((OrgSpongycastleMathEcECPoint *) nil_chk([((OrgSpongycastleMathEcECPoint *) nil_chk(R)) multiplyWithJavaMathBigInteger:n])) isInfinity]) {
    return nil;
  }
  JavaMathBigInteger *e = new_JavaMathBigInteger_initWithInt_withByteArray_(1, message);
  JavaMathBigInteger *eInv = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(JreLoadStatic(JavaMathBigInteger, ZERO))) subtractWithJavaMathBigInteger:e])) modWithJavaMathBigInteger:n];
  JavaMathBigInteger *rInv = [sig->r_ modInverseWithJavaMathBigInteger:n];
  JavaMathBigInteger *srInv = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(rInv)) multiplyWithJavaMathBigInteger:sig->s_])) modWithJavaMathBigInteger:n];
  JavaMathBigInteger *eInvrInv = [((JavaMathBigInteger *) nil_chk([rInv multiplyWithJavaMathBigInteger:eInv])) modWithJavaMathBigInteger:n];
  OrgSpongycastleMathEcECPoint *q = OrgSpongycastleMathEcECAlgorithms_sumOfTwoMultipliesWithOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_([ComYouzhLingtuSignCryptoSign_CURVE getG], eInvrInv, R, srInv);
  IOSByteArray *qBytes = [((OrgSpongycastleMathEcECPoint *) nil_chk(q)) getEncodedWithBoolean:false];
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, JavaUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(qBytes, 1, ((IOSByteArray *) nil_chk(qBytes))->size_));
}

OrgSpongycastleMathEcECPoint *ComYouzhLingtuSignCryptoSign_decompressKeyWithJavaMathBigInteger_withBoolean_(JavaMathBigInteger *xBN, jboolean yBit) {
  ComYouzhLingtuSignCryptoSign_initialize();
  OrgSpongycastleAsn1X9X9IntegerConverter *x9 = new_OrgSpongycastleAsn1X9X9IntegerConverter_init();
  IOSByteArray *compEnc = [x9 integerToBytesWithJavaMathBigInteger:xBN withInt:1 + [x9 getByteLengthWithOrgSpongycastleMathEcECCurve:[((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ComYouzhLingtuSignCryptoSign_CURVE)) getCurve]]];
  *IOSByteArray_GetRef(nil_chk(compEnc), 0) = (jbyte) (yBit ? (jint) 0x03 : (jint) 0x02);
  return [((OrgSpongycastleMathEcECCurve *) nil_chk([ComYouzhLingtuSignCryptoSign_CURVE getCurve])) decodePointWithByteArray:compEnc];
}

JavaMathBigInteger *ComYouzhLingtuSignCryptoSign_signedMessageToKeyWithByteArray_withComYouzhLingtuSignCryptoSign_SignatureData_(IOSByteArray *message, ComYouzhLingtuSignCryptoSign_SignatureData *signatureData) {
  ComYouzhLingtuSignCryptoSign_initialize();
  IOSByteArray *r = [((ComYouzhLingtuSignCryptoSign_SignatureData *) nil_chk(signatureData)) getR];
  IOSByteArray *s = [signatureData getS];
  ComYouzhLingtuSignCryptoUtilsAssertions_verifyPreconditionWithBoolean_withNSString_(r != nil && r->size_ == 32, @"r must be 32 bytes");
  ComYouzhLingtuSignCryptoUtilsAssertions_verifyPreconditionWithBoolean_withNSString_(s != nil && s->size_ == 32, @"s must be 32 bytes");
  jint header = [signatureData getV] & (jint) 0xFF;
  if (header < 27 || header > 34) {
    @throw new_JavaSecuritySignatureException_initWithNSString_(JreStrcat("$I", @"Header byte out of range: ", header));
  }
  ComYouzhLingtuSignCryptoECDSASignature *sig = new_ComYouzhLingtuSignCryptoECDSASignature_initWithJavaMathBigInteger_withJavaMathBigInteger_(new_JavaMathBigInteger_initWithInt_withByteArray_(1, [signatureData getR]), new_JavaMathBigInteger_initWithInt_withByteArray_(1, [signatureData getS]));
  IOSByteArray *messageHash = ComYouzhLingtuSignCryptoHash_sha3WithByteArray_(message);
  jint recId = header - 27;
  JavaMathBigInteger *key = ComYouzhLingtuSignCryptoSign_recoverFromSignatureWithInt_withComYouzhLingtuSignCryptoECDSASignature_withByteArray_(recId, sig, messageHash);
  if (key == nil) {
    @throw new_JavaSecuritySignatureException_initWithNSString_(@"Could not recover public key from signature");
  }
  return key;
}

JavaMathBigInteger *ComYouzhLingtuSignCryptoSign_publicKeyFromPrivateWithJavaMathBigInteger_(JavaMathBigInteger *privKey) {
  ComYouzhLingtuSignCryptoSign_initialize();
  OrgSpongycastleMathEcECPoint *point = ComYouzhLingtuSignCryptoSign_publicPointFromPrivateWithJavaMathBigInteger_(privKey);
  IOSByteArray *encoded = [((OrgSpongycastleMathEcECPoint *) nil_chk(point)) getEncodedWithBoolean:false];
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, JavaUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(encoded, 1, ((IOSByteArray *) nil_chk(encoded))->size_));
}

OrgSpongycastleMathEcECPoint *ComYouzhLingtuSignCryptoSign_publicPointFromPrivateWithJavaMathBigInteger_(JavaMathBigInteger *privKey) {
  ComYouzhLingtuSignCryptoSign_initialize();
  if ([((JavaMathBigInteger *) nil_chk(privKey)) bitLength] > [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleCryptoParamsECDomainParameters *) nil_chk(ComYouzhLingtuSignCryptoSign_CURVE)) getN])) bitLength]) {
    privKey = [privKey modWithJavaMathBigInteger:[ComYouzhLingtuSignCryptoSign_CURVE getN]];
  }
  return [new_OrgSpongycastleMathEcFixedPointCombMultiplier_init() multiplyWithOrgSpongycastleMathEcECPoint:[ComYouzhLingtuSignCryptoSign_CURVE getG] withJavaMathBigInteger:privKey];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoSign)

@implementation ComYouzhLingtuSignCryptoSign_SignatureData

- (instancetype)initWithByte:(jbyte)v
               withByteArray:(IOSByteArray *)r
               withByteArray:(IOSByteArray *)s {
  ComYouzhLingtuSignCryptoSign_SignatureData_initWithByte_withByteArray_withByteArray_(self, v, r, s);
  return self;
}

- (jbyte)getV {
  return v_;
}

- (IOSByteArray *)getR {
  return r_;
}

- (IOSByteArray *)getS {
  return s_;
}

- (jboolean)isEqual:(id)o {
  if (self == o) {
    return true;
  }
  if (o == nil || [self java_getClass] != [o java_getClass]) {
    return false;
  }
  ComYouzhLingtuSignCryptoSign_SignatureData *that = (ComYouzhLingtuSignCryptoSign_SignatureData *) cast_chk(o, [ComYouzhLingtuSignCryptoSign_SignatureData class]);
  if (v_ != that->v_) {
    return false;
  }
  if (!JavaUtilArrays_equalsWithByteArray_withByteArray_(r_, that->r_)) {
    return false;
  }
  return JavaUtilArrays_equalsWithByteArray_withByteArray_(s_, that->s_);
}

- (NSUInteger)hash {
  jint result = (jint) v_;
  result = 31 * result + JavaUtilArrays_hashCodeWithByteArray_(r_);
  result = 31 * result + JavaUtilArrays_hashCodeWithByteArray_(s_);
  return result;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByte:withByteArray:withByteArray:);
  methods[1].selector = @selector(getV);
  methods[2].selector = @selector(getR);
  methods[3].selector = @selector(getS);
  methods[4].selector = @selector(isEqual:);
  methods[5].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "v_", "B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "r_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "s_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "B[B[B", "equals", "LNSObject;", "hashCode", "LComYouzhLingtuSignCryptoSign;" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoSign_SignatureData = { "SignatureData", "com.youzh.lingtu.sign.crypto", ptrTable, methods, fields, 7, 0x9, 6, 3, 4, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoSign_SignatureData;
}

@end

void ComYouzhLingtuSignCryptoSign_SignatureData_initWithByte_withByteArray_withByteArray_(ComYouzhLingtuSignCryptoSign_SignatureData *self, jbyte v, IOSByteArray *r, IOSByteArray *s) {
  NSObject_init(self);
  self->v_ = v;
  self->r_ = r;
  self->s_ = s;
}

ComYouzhLingtuSignCryptoSign_SignatureData *new_ComYouzhLingtuSignCryptoSign_SignatureData_initWithByte_withByteArray_withByteArray_(jbyte v, IOSByteArray *r, IOSByteArray *s) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoSign_SignatureData, initWithByte_withByteArray_withByteArray_, v, r, s)
}

ComYouzhLingtuSignCryptoSign_SignatureData *create_ComYouzhLingtuSignCryptoSign_SignatureData_initWithByte_withByteArray_withByteArray_(jbyte v, IOSByteArray *r, IOSByteArray *s) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoSign_SignatureData, initWithByte_withByteArray_withByteArray_, v, r, s)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoSign_SignatureData)