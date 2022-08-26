//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/ntru/NTRUEncryptionPrivateKeyParameters.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/System.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUEncryptionKeyParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUEncryptionParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUEncryptionPrivateKeyParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUParameters.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/DenseTernaryPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/IntegerPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/Polynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/ProductFormPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/SparseTernaryPolynomial.h"

@interface OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters ()

- (void)init__ OBJC_METHOD_FAMILY_NONE;

@end

__attribute__((unused)) static void OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_init__(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self);

@implementation OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters

- (instancetype)initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)h
                           withOrgSpongycastlePqcMathNtruPolynomialPolynomial:(id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>)t
                    withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)fp
                     withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters:(OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *)params {
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(self, h, t, fp, params);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)b
withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters:(OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *)params {
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(self, b, params);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)is
withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters:(OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *)params {
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(self, is, params);
  return self;
}

- (void)init__ {
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_init__(self);
}

- (IOSByteArray *)getEncoded {
  IOSByteArray *hBytes = [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(h_)) toBinaryWithInt:((OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *) nil_chk(params_))->q_];
  IOSByteArray *tBytes;
  if ([t_ isKindOfClass:[OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial class]]) {
    tBytes = [((OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *) nil_chk(((OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial *) t_))) toBinary];
  }
  else {
    tBytes = [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk([((id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>) nil_chk(t_)) toIntegerPolynomial])) toBinary3Tight];
  }
  IOSByteArray *res = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(hBytes))->size_ + ((IOSByteArray *) nil_chk(tBytes))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(hBytes, 0, res, 0, hBytes->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(tBytes, 0, res, hBytes->size_, tBytes->size_);
  return res;
}

- (void)writeToWithJavaIoOutputStream:(JavaIoOutputStream *)os {
  [((JavaIoOutputStream *) nil_chk(os)) writeWithByteArray:[self getEncoded]];
}

- (NSUInteger)hash {
  jint prime = 31;
  jint result = 1;
  result = prime * result + ((params_ == nil) ? 0 : ((jint) [((OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *) nil_chk(params_)) hash]));
  result = prime * result + ((t_ == nil) ? 0 : ((jint) [((id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>) nil_chk(t_)) hash]));
  result = prime * result + ((h_ == nil) ? 0 : ((jint) [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(h_)) hash]));
  return result;
}

- (jboolean)isEqual:(id)obj {
  if (self == obj) {
    return true;
  }
  if (obj == nil) {
    return false;
  }
  if (!([obj isKindOfClass:[OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters class]])) {
    return false;
  }
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *other = (OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *) cast_chk(obj, [OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters class]);
  if (params_ == nil) {
    if (other->params_ != nil) {
      return false;
    }
  }
  else if (![params_ isEqual:other->params_]) {
    return false;
  }
  if (t_ == nil) {
    if (other->t_ != nil) {
      return false;
    }
  }
  else if (![t_ isEqual:other->t_]) {
    return false;
  }
  if (![((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(h_)) isEqual:other->h_]) {
    return false;
  }
  return true;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, 2, -1, -1, -1 },
    { NULL, "V", 0x2, 4, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 6, 2, -1, -1, -1 },
    { NULL, "I", 0x1, 7, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withOrgSpongycastlePqcMathNtruPolynomialPolynomial:withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters:);
  methods[1].selector = @selector(initWithByteArray:withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters:);
  methods[2].selector = @selector(initWithJavaIoInputStream:withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters:);
  methods[3].selector = @selector(init__);
  methods[4].selector = @selector(getEncoded);
  methods[5].selector = @selector(writeToWithJavaIoOutputStream:);
  methods[6].selector = @selector(hash);
  methods[7].selector = @selector(isEqual:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "t_", "LOrgSpongycastlePqcMathNtruPolynomialPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
    { "fp_", "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
    { "h_", "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;LOrgSpongycastlePqcMathNtruPolynomialPolynomial;LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;LOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters;", "[BLOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters;", "LJavaIoIOException;", "LJavaIoInputStream;LOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters;", "init", "writeTo", "LJavaIoOutputStream;", "hashCode", "equals", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters = { "NTRUEncryptionPrivateKeyParameters", "org.spongycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters;
}

@end

void OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> t, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *fp, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(self, true, params);
  self->h_ = h;
  self->t_ = t;
  self->fp_ = fp;
}

OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> t, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *fp, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_, h, t, fp, params)
}

OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> t, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *fp, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_, h, t, fp, params)
}

void OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, IOSByteArray *b, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(self, new_JavaIoByteArrayInputStream_initWithByteArray_(b), params);
}

OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(IOSByteArray *b, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithByteArray_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_, b, params)
}

OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(IOSByteArray *b, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithByteArray_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_, b, params)
}

void OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, JavaIoInputStream *is, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(self, true, params);
  if (((OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *) nil_chk(params))->polyType_ == OrgSpongycastlePqcCryptoNtruNTRUParameters_TERNARY_POLYNOMIAL_TYPE_PRODUCT) {
    jint N = params->N_;
    jint df1 = params->df1_;
    jint df2 = params->df2_;
    jint df3Ones = params->df3_;
    jint df3NegOnes = params->fastFp_ ? params->df3_ : params->df3_ - 1;
    self->h_ = OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_(is, params->N_, params->q_);
    self->t_ = OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_withInt_withInt_withInt_(is, N, df1, df2, df3Ones, df3NegOnes);
  }
  else {
    self->h_ = OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_fromBinaryWithJavaIoInputStream_withInt_withInt_(is, params->N_, params->q_);
    OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *fInt = OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_fromBinary3TightWithJavaIoInputStream_withInt_(is, params->N_);
    self->t_ = params->sparse_ ? new_OrgSpongycastlePqcMathNtruPolynomialSparseTernaryPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_(fInt) : (id) new_OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_(fInt);
  }
  OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_init__(self);
}

OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(JavaIoInputStream *is, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithJavaIoInputStream_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_, is, params)
}

OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_(JavaIoInputStream *is, OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, initWithJavaIoInputStream_withOrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters_, is, params)
}

void OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_init__(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self) {
  if (((OrgSpongycastlePqcCryptoNtruNTRUEncryptionParameters *) nil_chk(self->params_))->fastFp_) {
    self->fp_ = new_OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_initWithInt_(self->params_->N_);
    *IOSIntArray_GetRef(nil_chk(self->fp_->coeffs_), 0) = 1;
  }
  else {
    self->fp_ = [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk([((id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>) nil_chk(self->t_)) toIntegerPolynomial])) invertF3];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters)
