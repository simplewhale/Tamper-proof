//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/rainbow/RainbowSigner.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalStateException.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/params/ParametersWithRandom.h"
#include "org/spongycastle/pqc/crypto/rainbow/Layer.h"
#include "org/spongycastle/pqc/crypto/rainbow/RainbowKeyParameters.h"
#include "org/spongycastle/pqc/crypto/rainbow/RainbowPrivateKeyParameters.h"
#include "org/spongycastle/pqc/crypto/rainbow/RainbowPublicKeyParameters.h"
#include "org/spongycastle/pqc/crypto/rainbow/RainbowSigner.h"
#include "org/spongycastle/pqc/crypto/rainbow/util/ComputeInField.h"
#include "org/spongycastle/pqc/crypto/rainbow/util/GF2Field.h"

@interface OrgSpongycastlePqcCryptoRainbowRainbowSigner () {
 @public
  JavaSecuritySecureRandom *random_;
  IOSShortArray *x_;
  OrgSpongycastlePqcCryptoRainbowUtilComputeInField *cf_;
}

- (IOSShortArray *)initSignWithOrgSpongycastlePqcCryptoRainbowLayerArray:(IOSObjectArray *)layer
                                                          withShortArray:(IOSShortArray *)msg OBJC_METHOD_FAMILY_NONE;

- (IOSShortArray *)verifySignatureInternWithShortArray:(IOSShortArray *)signature;

- (IOSShortArray *)makeMessageRepresentativeWithByteArray:(IOSByteArray *)message;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoRainbowRainbowSigner, random_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoRainbowRainbowSigner, x_, IOSShortArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoRainbowRainbowSigner, cf_, OrgSpongycastlePqcCryptoRainbowUtilComputeInField *)

inline jint OrgSpongycastlePqcCryptoRainbowRainbowSigner_get_MAXITS(void);
#define OrgSpongycastlePqcCryptoRainbowRainbowSigner_MAXITS 65536
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastlePqcCryptoRainbowRainbowSigner, MAXITS, jint)

__attribute__((unused)) static IOSShortArray *OrgSpongycastlePqcCryptoRainbowRainbowSigner_initSignWithOrgSpongycastlePqcCryptoRainbowLayerArray_withShortArray_(OrgSpongycastlePqcCryptoRainbowRainbowSigner *self, IOSObjectArray *layer, IOSShortArray *msg);

__attribute__((unused)) static IOSShortArray *OrgSpongycastlePqcCryptoRainbowRainbowSigner_verifySignatureInternWithShortArray_(OrgSpongycastlePqcCryptoRainbowRainbowSigner *self, IOSShortArray *signature);

__attribute__((unused)) static IOSShortArray *OrgSpongycastlePqcCryptoRainbowRainbowSigner_makeMessageRepresentativeWithByteArray_(OrgSpongycastlePqcCryptoRainbowRainbowSigner *self, IOSByteArray *message);

@implementation OrgSpongycastlePqcCryptoRainbowRainbowSigner

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastlePqcCryptoRainbowRainbowSigner_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forSigning
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param {
  if (forSigning) {
    if ([param isKindOfClass:[OrgSpongycastleCryptoParamsParametersWithRandom class]]) {
      OrgSpongycastleCryptoParamsParametersWithRandom *rParam = (OrgSpongycastleCryptoParamsParametersWithRandom *) param;
      self->random_ = [((OrgSpongycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getRandom];
      self->key_ = (OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk([rParam getParameters], [OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters class]);
    }
    else {
      self->random_ = new_JavaSecuritySecureRandom_init();
      self->key_ = (OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk(param, [OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters class]);
    }
  }
  else {
    self->key_ = (OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters *) cast_chk(param, [OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters class]);
  }
  self->signableDocumentLength_ = [((OrgSpongycastlePqcCryptoRainbowRainbowKeyParameters *) nil_chk(self->key_)) getDocLength];
}

- (IOSShortArray *)initSignWithOrgSpongycastlePqcCryptoRainbowLayerArray:(IOSObjectArray *)layer
                                                          withShortArray:(IOSShortArray *)msg {
  return OrgSpongycastlePqcCryptoRainbowRainbowSigner_initSignWithOrgSpongycastlePqcCryptoRainbowLayerArray_withShortArray_(self, layer, msg);
}

- (IOSByteArray *)generateSignatureWithByteArray:(IOSByteArray *)message {
  IOSObjectArray *layer = [((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters class])))) getLayers];
  jint numberOfLayers = ((IOSObjectArray *) nil_chk(layer))->size_;
  x_ = [IOSShortArray newArrayWithLength:((IOSObjectArray *) nil_chk([((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters class])))) getInvA2]))->size_];
  IOSShortArray *Y_;
  IOSShortArray *y_i;
  jint counter;
  IOSShortArray *solVec;
  IOSShortArray *tmpVec;
  IOSShortArray *signature;
  IOSByteArray *S = [IOSByteArray newArrayWithLength:[((OrgSpongycastlePqcCryptoRainbowLayer *) nil_chk(IOSObjectArray_Get(layer, numberOfLayers - 1))) getViNext]];
  IOSShortArray *msgHashVals = OrgSpongycastlePqcCryptoRainbowRainbowSigner_makeMessageRepresentativeWithByteArray_(self, message);
  jint itCount = 0;
  jboolean ok;
  do {
    ok = true;
    counter = 0;
    @try {
      Y_ = OrgSpongycastlePqcCryptoRainbowRainbowSigner_initSignWithOrgSpongycastlePqcCryptoRainbowLayerArray_withShortArray_(self, layer, msgHashVals);
      for (jint i = 0; i < numberOfLayers; i++) {
        y_i = [IOSShortArray newArrayWithLength:[((OrgSpongycastlePqcCryptoRainbowLayer *) nil_chk(IOSObjectArray_Get(layer, i))) getOi]];
        solVec = [IOSShortArray newArrayWithLength:[((OrgSpongycastlePqcCryptoRainbowLayer *) nil_chk(IOSObjectArray_Get(layer, i))) getOi]];
        for (jint k = 0; k < [((OrgSpongycastlePqcCryptoRainbowLayer *) nil_chk(IOSObjectArray_Get(layer, i))) getOi]; k++) {
          *IOSShortArray_GetRef(y_i, k) = IOSShortArray_Get(nil_chk(Y_), counter);
          counter++;
        }
        solVec = [((OrgSpongycastlePqcCryptoRainbowUtilComputeInField *) nil_chk(cf_)) solveEquationWithShortArray2:[((OrgSpongycastlePqcCryptoRainbowLayer *) nil_chk(IOSObjectArray_Get(layer, i))) plugInVinegarsWithShortArray:x_] withShortArray:y_i];
        if (solVec == nil) {
          @throw new_JavaLangException_initWithNSString_(@"LES is not solveable!");
        }
        for (jint j = 0; j < solVec->size_; j++) {
          *IOSShortArray_GetRef(nil_chk(x_), [((OrgSpongycastlePqcCryptoRainbowLayer *) nil_chk(IOSObjectArray_Get(layer, i))) getVi] + j) = IOSShortArray_Get(solVec, j);
        }
      }
      tmpVec = [((OrgSpongycastlePqcCryptoRainbowUtilComputeInField *) nil_chk(cf_)) addVectWithShortArray:[((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters class])))) getB2] withShortArray:x_];
      signature = [((OrgSpongycastlePqcCryptoRainbowUtilComputeInField *) nil_chk(cf_)) multiplyMatrixWithShortArray2:[((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters class])))) getInvA2] withShortArray:tmpVec];
      for (jint i = 0; i < S->size_; i++) {
        *IOSByteArray_GetRef(S, i) = ((jbyte) IOSShortArray_Get(nil_chk(signature), i));
      }
    }
    @catch (JavaLangException *se) {
      ok = false;
    }
  }
  while (!ok && ++itCount < OrgSpongycastlePqcCryptoRainbowRainbowSigner_MAXITS);
  if (itCount == OrgSpongycastlePqcCryptoRainbowRainbowSigner_MAXITS) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"unable to generate signature - LES not solvable");
  }
  return S;
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature {
  IOSShortArray *sigInt = [IOSShortArray newArrayWithLength:((IOSByteArray *) nil_chk(signature))->size_];
  jshort tmp;
  for (jint i = 0; i < signature->size_; i++) {
    tmp = (jshort) IOSByteArray_Get(signature, i);
    tmp &= (jshort) (jint) 0xff;
    *IOSShortArray_GetRef(sigInt, i) = tmp;
  }
  IOSShortArray *msgHashVal = OrgSpongycastlePqcCryptoRainbowRainbowSigner_makeMessageRepresentativeWithByteArray_(self, message);
  IOSShortArray *verificationResult = OrgSpongycastlePqcCryptoRainbowRainbowSigner_verifySignatureInternWithShortArray_(self, sigInt);
  jboolean verified = true;
  if (((IOSShortArray *) nil_chk(msgHashVal))->size_ != ((IOSShortArray *) nil_chk(verificationResult))->size_) {
    return false;
  }
  for (jint i = 0; i < msgHashVal->size_; i++) {
    verified = (verified && IOSShortArray_Get(msgHashVal, i) == IOSShortArray_Get(verificationResult, i));
  }
  return verified;
}

- (IOSShortArray *)verifySignatureInternWithShortArray:(IOSShortArray *)signature {
  return OrgSpongycastlePqcCryptoRainbowRainbowSigner_verifySignatureInternWithShortArray_(self, signature);
}

- (IOSShortArray *)makeMessageRepresentativeWithByteArray:(IOSByteArray *)message {
  return OrgSpongycastlePqcCryptoRainbowRainbowSigner_makeMessageRepresentativeWithByteArray_(self, message);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[S", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "[S", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "[S", 0x2, 10, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withOrgSpongycastleCryptoCipherParameters:);
  methods[2].selector = @selector(initSignWithOrgSpongycastlePqcCryptoRainbowLayerArray:withShortArray:);
  methods[3].selector = @selector(generateSignatureWithByteArray:);
  methods[4].selector = @selector(verifySignatureWithByteArray:withByteArray:);
  methods[5].selector = @selector(verifySignatureInternWithShortArray:);
  methods[6].selector = @selector(makeMessageRepresentativeWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "MAXITS", "I", .constantValue.asInt = OrgSpongycastlePqcCryptoRainbowRainbowSigner_MAXITS, 0x1a, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signableDocumentLength_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "x_", "[S", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "cf_", "LOrgSpongycastlePqcCryptoRainbowUtilComputeInField;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "key_", "LOrgSpongycastlePqcCryptoRainbowRainbowKeyParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLOrgSpongycastleCryptoCipherParameters;", "initSign", "[LOrgSpongycastlePqcCryptoRainbowLayer;[S", "generateSignature", "[B", "verifySignature", "[B[B", "verifySignatureIntern", "[S", "makeMessageRepresentative" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoRainbowRainbowSigner = { "RainbowSigner", "org.spongycastle.pqc.crypto.rainbow", ptrTable, methods, fields, 7, 0x1, 7, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoRainbowRainbowSigner;
}

@end

void OrgSpongycastlePqcCryptoRainbowRainbowSigner_init(OrgSpongycastlePqcCryptoRainbowRainbowSigner *self) {
  NSObject_init(self);
  self->cf_ = new_OrgSpongycastlePqcCryptoRainbowUtilComputeInField_init();
}

OrgSpongycastlePqcCryptoRainbowRainbowSigner *new_OrgSpongycastlePqcCryptoRainbowRainbowSigner_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoRainbowRainbowSigner, init)
}

OrgSpongycastlePqcCryptoRainbowRainbowSigner *create_OrgSpongycastlePqcCryptoRainbowRainbowSigner_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoRainbowRainbowSigner, init)
}

IOSShortArray *OrgSpongycastlePqcCryptoRainbowRainbowSigner_initSignWithOrgSpongycastlePqcCryptoRainbowLayerArray_withShortArray_(OrgSpongycastlePqcCryptoRainbowRainbowSigner *self, IOSObjectArray *layer, IOSShortArray *msg) {
  IOSShortArray *tmpVec = [IOSShortArray newArrayWithLength:((IOSShortArray *) nil_chk(msg))->size_];
  tmpVec = [((OrgSpongycastlePqcCryptoRainbowUtilComputeInField *) nil_chk(self->cf_)) addVectWithShortArray:[((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters class])))) getB1] withShortArray:msg];
  IOSShortArray *Y_ = [((OrgSpongycastlePqcCryptoRainbowUtilComputeInField *) nil_chk(self->cf_)) multiplyMatrixWithShortArray2:[((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPrivateKeyParameters class])))) getInvA1] withShortArray:tmpVec];
  for (jint i = 0; i < [((OrgSpongycastlePqcCryptoRainbowLayer *) nil_chk(IOSObjectArray_Get(nil_chk(layer), 0))) getVi]; i++) {
    *IOSShortArray_GetRef(nil_chk(self->x_), i) = (jshort) [((JavaSecuritySecureRandom *) nil_chk(self->random_)) nextInt];
    *IOSShortArray_GetRef(nil_chk(self->x_), i) = (jshort) (IOSShortArray_Get(self->x_, i) & OrgSpongycastlePqcCryptoRainbowUtilGF2Field_MASK);
  }
  return Y_;
}

IOSShortArray *OrgSpongycastlePqcCryptoRainbowRainbowSigner_verifySignatureInternWithShortArray_(OrgSpongycastlePqcCryptoRainbowRainbowSigner *self, IOSShortArray *signature) {
  IOSObjectArray *coeff_quadratic = [((OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters class])))) getCoeffQuadratic];
  IOSObjectArray *coeff_singular = [((OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters class])))) getCoeffSingular];
  IOSShortArray *coeff_scalar = [((OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters *) nil_chk(((OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters *) cast_chk(self->key_, [OrgSpongycastlePqcCryptoRainbowRainbowPublicKeyParameters class])))) getCoeffScalar];
  IOSShortArray *rslt = [IOSShortArray newArrayWithLength:((IOSObjectArray *) nil_chk(coeff_quadratic))->size_];
  jint n = ((IOSShortArray *) nil_chk(IOSObjectArray_Get(nil_chk(coeff_singular), 0)))->size_;
  jint offset = 0;
  jshort tmp = 0;
  for (jint p = 0; p < coeff_quadratic->size_; p++) {
    offset = 0;
    for (jint x = 0; x < n; x++) {
      for (jint y = x; y < n; y++) {
        tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(coeff_quadratic, p)), offset), OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(signature), x), IOSShortArray_Get(signature, y)));
        *IOSShortArray_GetRef(rslt, p) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(rslt, p), tmp);
        offset++;
      }
      tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(coeff_singular, p)), x), IOSShortArray_Get(nil_chk(signature), x));
      *IOSShortArray_GetRef(rslt, p) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(rslt, p), tmp);
    }
    *IOSShortArray_GetRef(rslt, p) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(rslt, p), IOSShortArray_Get(nil_chk(coeff_scalar), p));
  }
  return rslt;
}

IOSShortArray *OrgSpongycastlePqcCryptoRainbowRainbowSigner_makeMessageRepresentativeWithByteArray_(OrgSpongycastlePqcCryptoRainbowRainbowSigner *self, IOSByteArray *message) {
  IOSShortArray *output = [IOSShortArray newArrayWithLength:self->signableDocumentLength_];
  jint h = 0;
  jint i = 0;
  do {
    if (i >= ((IOSByteArray *) nil_chk(message))->size_) {
      break;
    }
    *IOSShortArray_GetRef(output, i) = (jshort) IOSByteArray_Get(message, h);
    *IOSShortArray_GetRef(output, i) &= (jshort) (jint) 0xff;
    h++;
    i++;
  }
  while (i < output->size_);
  return output;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoRainbowRainbowSigner)
