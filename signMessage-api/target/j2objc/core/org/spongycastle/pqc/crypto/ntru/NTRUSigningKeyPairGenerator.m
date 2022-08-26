//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/ntru/NTRUSigningKeyPairGenerator.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigDecimal.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"
#include "java/util/ArrayList.h"
#include "java/util/List.h"
#include "java/util/concurrent/Callable.h"
#include "java/util/concurrent/ExecutorService.h"
#include "java/util/concurrent/Executors.h"
#include "java/util/concurrent/Future.h"
#include "org/spongycastle/crypto/AsymmetricCipherKeyPair.h"
#include "org/spongycastle/crypto/KeyGenerationParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUSigningKeyGenerationParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUSigningKeyPairGenerator.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUSigningParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUSigningPrivateKeyParameters.h"
#include "org/spongycastle/pqc/crypto/ntru/NTRUSigningPublicKeyParameters.h"
#include "org/spongycastle/pqc/math/ntru/euclid/BigIntEuclidean.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/BigDecimalPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/BigIntPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/DenseTernaryPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/IntegerPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/ModularResultant.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/Polynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/ProductFormPolynomial.h"
#include "org/spongycastle/pqc/math/ntru/polynomial/Resultant.h"

@interface OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator () {
 @public
  OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params_;
}

- (void)minimizeFGWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)f
                  withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)g
                  withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)F
                  withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)G
                                                                    withInt:(jint)N;

- (OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *)generateBasis;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator, params_, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_minimizeFGWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withInt_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *self, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *f, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *g, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G, jint N);

__attribute__((unused)) static OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_generateBasis(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *self);

@interface OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask : NSObject < JavaUtilConcurrentCallable > {
 @public
  OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *this$0_;
}

- (instancetype)initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator:(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *)outer$;

- (OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *)call;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask *self, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$);

__attribute__((unused)) static OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask *new_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask *create_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask)

@implementation OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithOrgSpongycastleCryptoKeyGenerationParameters:(OrgSpongycastleCryptoKeyGenerationParameters *)param {
  self->params_ = (OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) cast_chk(param, [OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters class]);
}

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPair {
  OrgSpongycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *pub = nil;
  id<JavaUtilConcurrentExecutorService> executor = JavaUtilConcurrentExecutors_newCachedThreadPool();
  id<JavaUtilList> bases = new_JavaUtilArrayList_init();
  for (jint k = ((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(params_))->B_; k >= 0; k--) {
    [bases addWithId:[((id<JavaUtilConcurrentExecutorService>) nil_chk(executor)) submitWithJavaUtilConcurrentCallable:new_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_(self)]];
  }
  [((id<JavaUtilConcurrentExecutorService>) nil_chk(executor)) shutdown];
  id<JavaUtilList> basises = new_JavaUtilArrayList_init();
  for (jint k = ((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(params_))->B_; k >= 0; k--) {
    id<JavaUtilConcurrentFuture> basis = [bases getWithInt:k];
    @try {
      [basises addWithId:[((id<JavaUtilConcurrentFuture>) nil_chk(basis)) get]];
      if (k == ((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(params_))->B_) {
        pub = new_OrgSpongycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningParameters_(((OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *) nil_chk([basis get]))->h_, [((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(params_)) getSigningParameters]);
      }
    }
    @catch (JavaLangException *e) {
      @throw new_JavaLangIllegalStateException_initWithJavaLangThrowable_(e);
    }
  }
  OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *priv = new_OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithJavaUtilList_withOrgSpongycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(basises, pub);
  OrgSpongycastleCryptoAsymmetricCipherKeyPair *kp = new_OrgSpongycastleCryptoAsymmetricCipherKeyPair_initWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter_withOrgSpongycastleCryptoParamsAsymmetricKeyParameter_(pub, priv);
  return kp;
}

- (OrgSpongycastleCryptoAsymmetricCipherKeyPair *)generateKeyPairSingleThread {
  id<JavaUtilList> basises = new_JavaUtilArrayList_init();
  OrgSpongycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *pub = nil;
  for (jint k = ((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(params_))->B_; k >= 0; k--) {
    OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *basis = [self generateBoundedBasis];
    [basises addWithId:basis];
    if (k == 0) {
      pub = new_OrgSpongycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_initWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningParameters_(((OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *) nil_chk(basis))->h_, [((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(params_)) getSigningParameters]);
    }
  }
  OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *priv = new_OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_initWithJavaUtilList_withOrgSpongycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(basises, pub);
  return new_OrgSpongycastleCryptoAsymmetricCipherKeyPair_initWithOrgSpongycastleCryptoParamsAsymmetricKeyParameter_withOrgSpongycastleCryptoParamsAsymmetricKeyParameter_(pub, priv);
}

- (void)minimizeFGWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)f
                  withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)g
                  withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)F
                  withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)G
                                                                    withInt:(jint)N {
  OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_minimizeFGWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withInt_(self, f, g, F, G, N);
}

- (OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *)generateBasis {
  return OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_generateBasis(self);
}

- (OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *)generateBoundedBasis {
  while (true) {
    OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *basis = OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_generateBasis(self);
    if ([((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *) nil_chk(basis)) isNormOk]) {
      return basis;
    }
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoAsymmetricCipherKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis;", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithOrgSpongycastleCryptoKeyGenerationParameters:);
  methods[2].selector = @selector(generateKeyPair);
  methods[3].selector = @selector(generateKeyPairSingleThread);
  methods[4].selector = @selector(minimizeFGWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withInt:);
  methods[5].selector = @selector(generateBasis);
  methods[6].selector = @selector(generateBoundedBasis);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LOrgSpongycastleCryptoKeyGenerationParameters;", "minimizeFG", "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;I", "LOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask;LOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator = { "NTRUSigningKeyPairGenerator", "org.spongycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x1, 7, 1, -1, 4, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator;
}

@end

void OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_init(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *self) {
  NSObject_init(self);
}

OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *new_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator, init)
}

OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *create_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator, init)
}

void OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_minimizeFGWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withInt_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *self, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *f, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *g, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G, jint N) {
  jint E = 0;
  for (jint j = 0; j < N; j++) {
    E += 2 * N * (IOSIntArray_Get(nil_chk(((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(f))->coeffs_), j) * IOSIntArray_Get(f->coeffs_, j) + IOSIntArray_Get(((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(g))->coeffs_, j) * IOSIntArray_Get(g->coeffs_, j));
  }
  E -= 4;
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *u = (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) cast_chk([((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(f)) java_clone], [OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial class]);
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *v = (OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) cast_chk([((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(g)) java_clone], [OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial class]);
  jint j = 0;
  jint k = 0;
  jint maxAdjustment = N;
  while (k < maxAdjustment && j < N) {
    jint D = 0;
    jint i = 0;
    while (i < N) {
      jint D1 = IOSIntArray_Get(nil_chk(((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(F))->coeffs_), i) * IOSIntArray_Get(f->coeffs_, i);
      jint D2 = IOSIntArray_Get(((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(G))->coeffs_, i) * IOSIntArray_Get(g->coeffs_, i);
      jint D3 = 4 * N * (D1 + D2);
      D += D3;
      i++;
    }
    jint D1 = 4 * ([((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(F)) sumCoeffs] + [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(G)) sumCoeffs]);
    D -= D1;
    if (D > E) {
      [F subWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:u];
      [G subWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:v];
      k++;
      j = 0;
    }
    else if (D < -E) {
      [F addWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:u];
      [G addWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:v];
      k++;
      j = 0;
    }
    j++;
    [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(u)) rotate1];
    [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(v)) rotate1];
  }
}

OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_generateBasis(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *self) {
  jint N = ((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(self->params_))->N_;
  jint q = self->params_->q_;
  jint d = self->params_->d_;
  jint d1 = self->params_->d1_;
  jint d2 = self->params_->d2_;
  jint d3 = self->params_->d3_;
  jint basisType = self->params_->basisType_;
  id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> f;
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *fInt;
  id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> g;
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *gInt;
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *fq;
  OrgSpongycastlePqcMathNtruPolynomialResultant *rf;
  OrgSpongycastlePqcMathNtruPolynomialResultant *rg;
  OrgSpongycastlePqcMathNtruEuclidBigIntEuclidean *r;
  jint _2n1 = 2 * N + 1;
  jboolean primeCheck = self->params_->primeCheck_;
  do {
    do {
      f = ((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(self->params_))->polyType_ == OrgSpongycastlePqcCryptoNtruNTRUParameters_TERNARY_POLYNOMIAL_TYPE_SIMPLE ? OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, d + 1, d, new_JavaSecuritySecureRandom_init()) : (id) OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_generateRandomWithInt_withInt_withInt_withInt_withInt_withJavaSecuritySecureRandom_(N, d1, d2, d3 + 1, d3, new_JavaSecuritySecureRandom_init());
      fInt = [f toIntegerPolynomial];
    }
    while (primeCheck && [((JavaMathBigInteger *) nil_chk(((OrgSpongycastlePqcMathNtruPolynomialModularResultant *) nil_chk([((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(fInt)) resultantWithInt:_2n1]))->res_)) isEqual:JreLoadStatic(JavaMathBigInteger, ZERO)]);
    fq = [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(fInt)) invertFqWithInt:q];
  }
  while (fq == nil);
  rf = [fInt resultant];
  do {
    do {
      do {
        g = ((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(self->params_))->polyType_ == OrgSpongycastlePqcCryptoNtruNTRUParameters_TERNARY_POLYNOMIAL_TYPE_SIMPLE ? OrgSpongycastlePqcMathNtruPolynomialDenseTernaryPolynomial_generateRandomWithInt_withInt_withInt_withJavaSecuritySecureRandom_(N, d + 1, d, new_JavaSecuritySecureRandom_init()) : (id) OrgSpongycastlePqcMathNtruPolynomialProductFormPolynomial_generateRandomWithInt_withInt_withInt_withInt_withInt_withJavaSecuritySecureRandom_(N, d1, d2, d3 + 1, d3, new_JavaSecuritySecureRandom_init());
        gInt = [g toIntegerPolynomial];
      }
      while (primeCheck && [((JavaMathBigInteger *) nil_chk(((OrgSpongycastlePqcMathNtruPolynomialModularResultant *) nil_chk([((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(gInt)) resultantWithInt:_2n1]))->res_)) isEqual:JreLoadStatic(JavaMathBigInteger, ZERO)]);
    }
    while ([((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(gInt)) invertFqWithInt:q] == nil);
    rg = [gInt resultant];
    r = OrgSpongycastlePqcMathNtruEuclidBigIntEuclidean_calculateWithJavaMathBigInteger_withJavaMathBigInteger_(((OrgSpongycastlePqcMathNtruPolynomialResultant *) nil_chk(rf))->res_, ((OrgSpongycastlePqcMathNtruPolynomialResultant *) nil_chk(rg))->res_);
  }
  while (![((JavaMathBigInteger *) nil_chk(((OrgSpongycastlePqcMathNtruEuclidBigIntEuclidean *) nil_chk(r))->gcd_)) isEqual:JreLoadStatic(JavaMathBigInteger, ONE)]);
  OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *A = (OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) cast_chk([((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(rf->rho_)) java_clone], [OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial class]);
  [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(A)) multWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(r->x_)) multiplyWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(q)]];
  OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *B = (OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) cast_chk([((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(rg->rho_)) java_clone], [OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial class]);
  [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(B)) multWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(r->y_)) multiplyWithJavaMathBigInteger:JavaMathBigInteger_valueOfWithLong_(-q)]];
  OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *C;
  if (((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(self->params_))->keyGenAlg_ == OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_KEY_GEN_ALG_RESULTANT) {
    IOSIntArray *fRevCoeffs = [IOSIntArray newArrayWithLength:N];
    IOSIntArray *gRevCoeffs = [IOSIntArray newArrayWithLength:N];
    *IOSIntArray_GetRef(fRevCoeffs, 0) = IOSIntArray_Get(nil_chk(fInt->coeffs_), 0);
    *IOSIntArray_GetRef(gRevCoeffs, 0) = IOSIntArray_Get(gInt->coeffs_, 0);
    for (jint i = 1; i < N; i++) {
      *IOSIntArray_GetRef(fRevCoeffs, i) = IOSIntArray_Get(fInt->coeffs_, N - i);
      *IOSIntArray_GetRef(gRevCoeffs, i) = IOSIntArray_Get(gInt->coeffs_, N - i);
    }
    OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *fRev = new_OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_initWithIntArray_(fRevCoeffs);
    OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *gRev = new_OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_initWithIntArray_(gRevCoeffs);
    OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *t = [f multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:fRev];
    [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(t)) addWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:[g multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:gRev]];
    OrgSpongycastlePqcMathNtruPolynomialResultant *rt = [t resultant];
    C = [fRev multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:B];
    [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(C)) addWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:[gRev multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:A]];
    C = [C multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:((OrgSpongycastlePqcMathNtruPolynomialResultant *) nil_chk(rt))->rho_];
    [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(C)) divWithJavaMathBigInteger:rt->res_];
  }
  else {
    jint log10N = 0;
    for (jint i = 1; i < N; i *= 10) {
      log10N++;
    }
    OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *fInv = [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(rf->rho_)) divWithJavaMathBigDecimal:new_JavaMathBigDecimal_initWithJavaMathBigInteger_(rf->res_) withInt:[B getMaxCoeffLength] + 1 + log10N];
    OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *gInv = [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(rg->rho_)) divWithJavaMathBigDecimal:new_JavaMathBigDecimal_initWithJavaMathBigInteger_(rg->res_) withInt:[A getMaxCoeffLength] + 1 + log10N];
    OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *Cdec = [((OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(fInv)) multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:B];
    [((OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(Cdec)) addWithOrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial:[((OrgSpongycastlePqcMathNtruPolynomialBigDecimalPolynomial *) nil_chk(gInv)) multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:A]];
    [Cdec halve];
    C = [Cdec round];
  }
  OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *F = (OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) cast_chk([B java_clone], [OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial class]);
  [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(F)) subWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:[f multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:C]];
  OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *G = (OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) cast_chk([A java_clone], [OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial class]);
  [((OrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial *) nil_chk(G)) subWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:[g multWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial:C]];
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *FInt = new_OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial_(F);
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *GInt = new_OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_initWithOrgSpongycastlePqcMathNtruPolynomialBigIntPolynomial_(G);
  OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_minimizeFGWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withInt_(self, fInt, gInt, FInt, GInt, N);
  id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> fPrime;
  OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h;
  if (basisType == OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_BASIS_TYPE_STANDARD) {
    fPrime = FInt;
    h = [g multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:fq withInt:q];
  }
  else {
    fPrime = g;
    h = [FInt multWithOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:fq withInt:q];
  }
  [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(h)) modPositiveWithInt:q];
  return new_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(self, f, fPrime, h, FInt, GInt, self->params_);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator)

@implementation OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask

- (instancetype)initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator:(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *)outer$ {
  OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_(self, outer$);
  return self;
}

- (OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *)call {
  return [this$0_ generateBoundedBasis];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis;", 0x1, -1, -1, 0, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator:);
  methods[1].selector = @selector(call);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "this$0_", "LOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaLangException;", "LOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator;", "Ljava/lang/Object;Ljava/util/concurrent/Callable<Lorg/spongycastle/pqc/crypto/ntru/NTRUSigningPrivateKeyParameters$Basis;>;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask = { "BasisGenerationTask", "org.spongycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x2, 2, 1, 1, -1, -1, 2, -1 };
  return &_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask;
}

@end

void OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask *self, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$) {
  self->this$0_ = outer$;
  NSObject_init(self);
}

OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask *new_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask, initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_, outer$)
}

OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask *create_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask, initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_, outer$)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_BasisGenerationTask)

@implementation OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis

- (instancetype)initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator:(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *)outer$
                             withOrgSpongycastlePqcMathNtruPolynomialPolynomial:(id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>)f
                             withOrgSpongycastlePqcMathNtruPolynomialPolynomial:(id<OrgSpongycastlePqcMathNtruPolynomialPolynomial>)fPrime
                      withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)h
                      withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)F
                      withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:(OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *)G
             withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *)params {
  OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(self, outer$, f, fPrime, h, F, G, params);
  return self;
}

- (jboolean)isNormOk {
  jdouble keyNormBoundSq = ((OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *) nil_chk(params_))->keyNormBoundSq_;
  jint q = params_->q_;
  return ([((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(F_)) centeredNormSqWithInt:q] < keyNormBoundSq && [((OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(G_)) centeredNormSqWithInt:q] < keyNormBoundSq);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator:withOrgSpongycastlePqcMathNtruPolynomialPolynomial:withOrgSpongycastlePqcMathNtruPolynomialPolynomial:withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial:withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters:);
  methods[1].selector = @selector(isNormOk);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "F_", "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
    { "G_", "LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;", .constantValue.asLong = 0, 0x1, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastlePqcMathNtruPolynomialPolynomial;LOrgSpongycastlePqcMathNtruPolynomialPolynomial;LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;LOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial;LOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters;", "LOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis = { "FGBasis", "org.spongycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x1, 2, 2, 1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis;
}

@end

void OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *self, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> f, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> fPrime, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params) {
  OrgSpongycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis_initWithOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(self, f, fPrime, h, params);
  self->F_ = F;
  self->G_ = G;
}

OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *new_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> f, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> fPrime, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis, initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_, outer$, f, fPrime, h, F, G, params)
}

OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis *create_OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis_initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator *outer$, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> f, id<OrgSpongycastlePqcMathNtruPolynomialPolynomial> fPrime, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *h, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *F, OrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial *G, OrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters *params) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis, initWithOrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcMathNtruPolynomialIntegerPolynomial_withOrgSpongycastlePqcCryptoNtruNTRUSigningKeyGenerationParameters_, outer$, f, fPrime, h, F, G, params)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoNtruNTRUSigningKeyPairGenerator_FGBasis)
