//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/linearalgebra/GF2nONBField.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/RuntimeException.h"
#include "java/security/SecureRandom.h"
#include "java/util/Random.h"
#include "java/util/Vector.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2Polynomial.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nElement.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nField.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nONBElement.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nONBField.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nPolynomial.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nPolynomialElement.h"
#include "org/spongycastle/pqc/math/linearalgebra/IntegerFunctions.h"

@interface OrgSpongycastlePqcMathLinearalgebraGF2nONBField () {
 @public
  jint mLength_;
  jint mBit_;
  jint mType_;
}

- (void)computeType;

- (void)computeMultMatrix;

- (jint)elementOfOrderWithInt:(jint)k
                      withInt:(jint)p;

@end

inline jint OrgSpongycastlePqcMathLinearalgebraGF2nONBField_get_MAXLONG(void);
#define OrgSpongycastlePqcMathLinearalgebraGF2nONBField_MAXLONG 64
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastlePqcMathLinearalgebraGF2nONBField, MAXLONG, jint)

__attribute__((unused)) static void OrgSpongycastlePqcMathLinearalgebraGF2nONBField_computeType(OrgSpongycastlePqcMathLinearalgebraGF2nONBField *self);

__attribute__((unused)) static void OrgSpongycastlePqcMathLinearalgebraGF2nONBField_computeMultMatrix(OrgSpongycastlePqcMathLinearalgebraGF2nONBField *self);

__attribute__((unused)) static jint OrgSpongycastlePqcMathLinearalgebraGF2nONBField_elementOfOrderWithInt_withInt_(OrgSpongycastlePqcMathLinearalgebraGF2nONBField *self, jint k, jint p);

@implementation OrgSpongycastlePqcMathLinearalgebraGF2nONBField

- (instancetype)initWithInt:(jint)deg
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  OrgSpongycastlePqcMathLinearalgebraGF2nONBField_initWithInt_withJavaSecuritySecureRandom_(self, deg, random);
  return self;
}

- (jint)getONBLength {
  return mLength_;
}

- (jint)getONBBit {
  return mBit_;
}

- (OrgSpongycastlePqcMathLinearalgebraGF2nElement *)getRandomRootWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:(OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *)polynomial {
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *c;
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *ut;
  OrgSpongycastlePqcMathLinearalgebraGF2nElement *u;
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *h;
  jint hDegree;
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *g = new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial_initWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial_withOrgSpongycastlePqcMathLinearalgebraGF2nField_(polynomial, self);
  jint gDegree = [g getDegree];
  jint i;
  while (gDegree > 1) {
    do {
      u = new_OrgSpongycastlePqcMathLinearalgebraGF2nONBElement_initWithOrgSpongycastlePqcMathLinearalgebraGF2nONBField_withJavaSecuritySecureRandom_(self, random_);
      ut = new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial_initWithInt_withOrgSpongycastlePqcMathLinearalgebraGF2nElement_(2, OrgSpongycastlePqcMathLinearalgebraGF2nONBElement_ZEROWithOrgSpongycastlePqcMathLinearalgebraGF2nONBField_(self));
      [ut setWithInt:1 withOrgSpongycastlePqcMathLinearalgebraGF2nElement:u];
      c = new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial_initWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomial_(ut);
      for (i = 1; i <= mDegree_ - 1; i++) {
        c = [((OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *) nil_chk(c)) multiplyAndReduceWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomial:c withOrgSpongycastlePqcMathLinearalgebraGF2nPolynomial:g];
        c = [((OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *) nil_chk(c)) addWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomial:ut];
      }
      h = [((OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *) nil_chk(c)) gcdWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomial:g];
      hDegree = [((OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *) nil_chk(h)) getDegree];
      gDegree = [g getDegree];
    }
    while ((hDegree == 0) || (hDegree == gDegree));
    if ((JreLShift32(hDegree, 1)) > gDegree) {
      g = [g quotientWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomial:h];
    }
    else {
      g = new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial_initWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomial_(h);
    }
    gDegree = [((OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial *) nil_chk(g)) getDegree];
  }
  return [g atWithInt:0];
}

- (void)computeCOBMatrixWithOrgSpongycastlePqcMathLinearalgebraGF2nField:(OrgSpongycastlePqcMathLinearalgebraGF2nField *)B1 {
  if (mDegree_ != ((OrgSpongycastlePqcMathLinearalgebraGF2nField *) nil_chk(B1))->mDegree_) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"GF2nField.computeCOBMatrix: B1 has a different degree and thus cannot be coverted to!");
  }
  jint i;
  jint j;
  IOSObjectArray *gamma;
  OrgSpongycastlePqcMathLinearalgebraGF2nElement *u;
  IOSObjectArray *COBMatrix = [IOSObjectArray newArrayWithLength:mDegree_ type:OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_class_()];
  for (i = 0; i < mDegree_; i++) {
    (void) IOSObjectArray_SetAndConsume(COBMatrix, i, new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_(mDegree_));
  }
  do {
    u = [B1 getRandomRootWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:fieldPolynomial_];
  }
  while ([((OrgSpongycastlePqcMathLinearalgebraGF2nElement *) nil_chk(u)) isZero]);
  gamma = [IOSObjectArray newArrayWithLength:mDegree_ type:OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialElement_class_()];
  (void) IOSObjectArray_Set(gamma, 0, (OrgSpongycastlePqcMathLinearalgebraGF2nElement *) cast_chk([u java_clone], [OrgSpongycastlePqcMathLinearalgebraGF2nElement class]));
  for (i = 1; i < mDegree_; i++) {
    (void) IOSObjectArray_Set(gamma, i, [((OrgSpongycastlePqcMathLinearalgebraGF2nElement *) nil_chk(IOSObjectArray_Get(gamma, i - 1))) square]);
  }
  for (i = 0; i < mDegree_; i++) {
    for (j = 0; j < mDegree_; j++) {
      if ([((OrgSpongycastlePqcMathLinearalgebraGF2nElement *) nil_chk(IOSObjectArray_Get(gamma, i))) testBitWithInt:j]) {
        [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(IOSObjectArray_Get(COBMatrix, mDegree_ - j - 1))) setBitWithInt:mDegree_ - i - 1];
      }
    }
  }
  [((JavaUtilVector *) nil_chk(fields_)) addElementWithId:B1];
  [((JavaUtilVector *) nil_chk(matrices_)) addElementWithId:COBMatrix];
  [((JavaUtilVector *) nil_chk(B1->fields_)) addElementWithId:self];
  [((JavaUtilVector *) nil_chk(B1->matrices_)) addElementWithId:[self invertMatrixWithOrgSpongycastlePqcMathLinearalgebraGF2PolynomialArray:COBMatrix]];
}

- (void)computeFieldPolynomial {
  if (mType_ == 1) {
    fieldPolynomial_ = new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_withNSString_(mDegree_ + 1, @"ALL");
  }
  else if (mType_ == 2) {
    OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *q = new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_withNSString_(mDegree_ + 1, @"ONE");
    OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *p = new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_withNSString_(mDegree_ + 1, @"X");
    [p addToThisWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:q];
    OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *r;
    jint i;
    for (i = 1; i < mDegree_; i++) {
      r = q;
      q = p;
      p = [q shiftLeft];
      [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(p)) addToThisWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:r];
    }
    fieldPolynomial_ = p;
  }
}

- (IOSObjectArray *)invMatrixWithIntArray2:(IOSObjectArray *)a {
  IOSObjectArray *A = [IOSIntArray newArrayWithDimensions:2 lengths:(jint[]){ mDegree_, mDegree_ }];
  A = a;
  IOSObjectArray *inv = [IOSIntArray newArrayWithDimensions:2 lengths:(jint[]){ mDegree_, mDegree_ }];
  for (jint i = 0; i < mDegree_; i++) {
    *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(inv, i)), i) = 1;
  }
  for (jint i = 0; i < mDegree_; i++) {
    for (jint j = i; j < mDegree_; j++) {
      *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(nil_chk(A), mDegree_ - 1 - i)), j) = IOSIntArray_Get(nil_chk(IOSObjectArray_Get(A, i)), i);
    }
  }
  return nil;
}

- (void)computeType {
  OrgSpongycastlePqcMathLinearalgebraGF2nONBField_computeType(self);
}

- (void)computeMultMatrix {
  OrgSpongycastlePqcMathLinearalgebraGF2nONBField_computeMultMatrix(self);
}

- (jint)elementOfOrderWithInt:(jint)k
                      withInt:(jint)p {
  return OrgSpongycastlePqcMathLinearalgebraGF2nONBField_elementOfOrderWithInt_withInt_(self, k, p);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathLinearalgebraGF2nElement;", 0x4, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[[I", 0x0, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, 1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(getONBLength);
  methods[2].selector = @selector(getONBBit);
  methods[3].selector = @selector(getRandomRootWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:);
  methods[4].selector = @selector(computeCOBMatrixWithOrgSpongycastlePqcMathLinearalgebraGF2nField:);
  methods[5].selector = @selector(computeFieldPolynomial);
  methods[6].selector = @selector(invMatrixWithIntArray2:);
  methods[7].selector = @selector(computeType);
  methods[8].selector = @selector(computeMultMatrix);
  methods[9].selector = @selector(elementOfOrderWithInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "MAXLONG", "I", .constantValue.asInt = OrgSpongycastlePqcMathLinearalgebraGF2nONBField_MAXLONG, 0x1a, -1, -1, -1, -1 },
    { "mLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mBit_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mType_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mMult_", "[[I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILJavaSecuritySecureRandom;", "LJavaLangRuntimeException;", "getRandomRoot", "LOrgSpongycastlePqcMathLinearalgebraGF2Polynomial;", "computeCOBMatrix", "LOrgSpongycastlePqcMathLinearalgebraGF2nField;", "invMatrix", "[[I", "elementOfOrder", "II" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcMathLinearalgebraGF2nONBField = { "GF2nONBField", "org.spongycastle.pqc.math.linearalgebra", ptrTable, methods, fields, 7, 0x1, 10, 5, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcMathLinearalgebraGF2nONBField;
}

@end

void OrgSpongycastlePqcMathLinearalgebraGF2nONBField_initWithInt_withJavaSecuritySecureRandom_(OrgSpongycastlePqcMathLinearalgebraGF2nONBField *self, jint deg, JavaSecuritySecureRandom *random) {
  OrgSpongycastlePqcMathLinearalgebraGF2nField_initWithJavaSecuritySecureRandom_(self, random);
  if (deg < 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"k must be at least 3");
  }
  self->mDegree_ = deg;
  self->mLength_ = self->mDegree_ / OrgSpongycastlePqcMathLinearalgebraGF2nONBField_MAXLONG;
  self->mBit_ = self->mDegree_ & (OrgSpongycastlePqcMathLinearalgebraGF2nONBField_MAXLONG - 1);
  if (self->mBit_ == 0) {
    self->mBit_ = OrgSpongycastlePqcMathLinearalgebraGF2nONBField_MAXLONG;
  }
  else {
    self->mLength_++;
  }
  OrgSpongycastlePqcMathLinearalgebraGF2nONBField_computeType(self);
  if (self->mType_ < 3) {
    self->mMult_ = [IOSIntArray newArrayWithDimensions:2 lengths:(jint[]){ self->mDegree_, 2 }];
    for (jint i = 0; i < self->mDegree_; i++) {
      *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, i)), 0) = -1;
      *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, i)), 1) = -1;
    }
    OrgSpongycastlePqcMathLinearalgebraGF2nONBField_computeMultMatrix(self);
  }
  else {
    @throw new_JavaLangRuntimeException_initWithNSString_(JreStrcat("$I", @"\nThe type of this field is ", self->mType_));
  }
  [self computeFieldPolynomial];
  self->fields_ = new_JavaUtilVector_init();
  self->matrices_ = new_JavaUtilVector_init();
}

OrgSpongycastlePqcMathLinearalgebraGF2nONBField *new_OrgSpongycastlePqcMathLinearalgebraGF2nONBField_initWithInt_withJavaSecuritySecureRandom_(jint deg, JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcMathLinearalgebraGF2nONBField, initWithInt_withJavaSecuritySecureRandom_, deg, random)
}

OrgSpongycastlePqcMathLinearalgebraGF2nONBField *create_OrgSpongycastlePqcMathLinearalgebraGF2nONBField_initWithInt_withJavaSecuritySecureRandom_(jint deg, JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcMathLinearalgebraGF2nONBField, initWithInt_withJavaSecuritySecureRandom_, deg, random)
}

void OrgSpongycastlePqcMathLinearalgebraGF2nONBField_computeType(OrgSpongycastlePqcMathLinearalgebraGF2nONBField *self) {
  if ((self->mDegree_ & 7) == 0) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"The extension degree is divisible by 8!");
  }
  jint s = 0;
  jint k = 0;
  self->mType_ = 1;
  for (jint d = 0; d != 1; self->mType_++) {
    s = self->mType_ * self->mDegree_ + 1;
    if (OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_isPrimeWithInt_(s)) {
      k = OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_orderWithInt_withInt_(2, s);
      d = OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_gcdWithInt_withInt_(self->mType_ * self->mDegree_ / k, self->mDegree_);
    }
  }
  self->mType_--;
  if (self->mType_ == 1) {
    s = (JreLShift32(self->mDegree_, 1)) + 1;
    if (OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_isPrimeWithInt_(s)) {
      k = OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_orderWithInt_withInt_(2, s);
      jint d = OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_gcdWithInt_withInt_((JreLShift32(self->mDegree_, 1)) / k, self->mDegree_);
      if (d == 1) {
        self->mType_++;
      }
    }
  }
}

void OrgSpongycastlePqcMathLinearalgebraGF2nONBField_computeMultMatrix(OrgSpongycastlePqcMathLinearalgebraGF2nONBField *self) {
  if ((self->mType_ & 7) != 0) {
    jint p = self->mType_ * self->mDegree_ + 1;
    IOSIntArray *F = [IOSIntArray newArrayWithLength:p];
    jint u;
    if (self->mType_ == 1) {
      u = 1;
    }
    else if (self->mType_ == 2) {
      u = p - 1;
    }
    else {
      u = OrgSpongycastlePqcMathLinearalgebraGF2nONBField_elementOfOrderWithInt_withInt_(self, self->mType_, p);
    }
    jint w = 1;
    jint n;
    for (jint j = 0; j < self->mType_; j++) {
      n = w;
      for (jint i = 0; i < self->mDegree_; i++) {
        *IOSIntArray_GetRef(F, n) = i;
        n = (JreLShift32(n, 1)) % p;
        if (n < 0) {
          n += p;
        }
      }
      w = u * w % p;
      if (w < 0) {
        w += p;
      }
    }
    if (self->mType_ == 1) {
      for (jint k = 1; k < p - 1; k++) {
        if (IOSIntArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(self->mMult_), IOSIntArray_Get(F, k + 1))), 0) == -1) {
          *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, IOSIntArray_Get(F, k + 1))), 0) = IOSIntArray_Get(F, p - k);
        }
        else {
          *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, IOSIntArray_Get(F, k + 1))), 1) = IOSIntArray_Get(F, p - k);
        }
      }
      jint m_2 = JreRShift32(self->mDegree_, 1);
      for (jint k = 1; k <= m_2; k++) {
        if (IOSIntArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(self->mMult_), k - 1)), 0) == -1) {
          *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, k - 1)), 0) = m_2 + k - 1;
        }
        else {
          *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, k - 1)), 1) = m_2 + k - 1;
        }
        if (IOSIntArray_Get(nil_chk(IOSObjectArray_Get(self->mMult_, m_2 + k - 1)), 0) == -1) {
          *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, m_2 + k - 1)), 0) = k - 1;
        }
        else {
          *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, m_2 + k - 1)), 1) = k - 1;
        }
      }
    }
    else if (self->mType_ == 2) {
      for (jint k = 1; k < p - 1; k++) {
        if (IOSIntArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(self->mMult_), IOSIntArray_Get(F, k + 1))), 0) == -1) {
          *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, IOSIntArray_Get(F, k + 1))), 0) = IOSIntArray_Get(F, p - k);
        }
        else {
          *IOSIntArray_GetRef(nil_chk(IOSObjectArray_Get(self->mMult_, IOSIntArray_Get(F, k + 1))), 1) = IOSIntArray_Get(F, p - k);
        }
      }
    }
    else {
      @throw new_JavaLangRuntimeException_initWithNSString_(@"only type 1 or type 2 implemented");
    }
  }
  else {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"bisher nur fuer Gausssche Normalbasen implementiert");
  }
}

jint OrgSpongycastlePqcMathLinearalgebraGF2nONBField_elementOfOrderWithInt_withInt_(OrgSpongycastlePqcMathLinearalgebraGF2nONBField *self, jint k, jint p) {
  JavaUtilRandom *random = new_JavaUtilRandom_init();
  jint m = 0;
  while (m == 0) {
    m = [random nextInt];
    m %= p - 1;
    if (m < 0) {
      m += p - 1;
    }
  }
  jint l = OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_orderWithInt_withInt_(m, p);
  while (l % k != 0 || l == 0) {
    while (m == 0) {
      m = [random nextInt];
      m %= p - 1;
      if (m < 0) {
        m += p - 1;
      }
    }
    l = OrgSpongycastlePqcMathLinearalgebraIntegerFunctions_orderWithInt_withInt_(m, p);
  }
  jint r = m;
  l = k / l;
  for (jint i = 2; i <= l; i++) {
    r *= m;
  }
  return r;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcMathLinearalgebraGF2nONBField)