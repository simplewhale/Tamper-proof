//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/math/linearalgebra/GF2nPolynomialField.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Math.h"
#include "java/lang/RuntimeException.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"
#include "java/util/Vector.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2Polynomial.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nElement.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nField.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nONBElement.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nONBField.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nPolynomial.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nPolynomialElement.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2nPolynomialField.h"
#include "org/spongycastle/pqc/math/linearalgebra/GFElement.h"

@interface OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField () {
 @public
  jboolean isTrinomial_;
  jboolean isPentanomial_;
  jint tc_;
  IOSIntArray *pc_;
}

- (void)computeSquaringMatrix;

- (jboolean)testTrinomials;

- (jboolean)testPentanomials;

- (jboolean)testRandom;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField, pc_, IOSIntArray *)

__attribute__((unused)) static void OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_computeSquaringMatrix(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self);

__attribute__((unused)) static jboolean OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testTrinomials(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self);

__attribute__((unused)) static jboolean OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testPentanomials(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self);

__attribute__((unused)) static jboolean OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testRandom(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self);

@implementation OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField

- (instancetype)initWithInt:(jint)deg
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_(self, deg, random);
  return self;
}

- (instancetype)initWithInt:(jint)deg
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                withBoolean:(jboolean)file {
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withBoolean_(self, deg, random, file);
  return self;
}

- (instancetype)initWithInt:(jint)deg
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
withOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:(OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *)polynomial {
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withOrgSpongycastlePqcMathLinearalgebraGF2Polynomial_(self, deg, random, polynomial);
  return self;
}

- (jboolean)isTrinomial {
  return isTrinomial_;
}

- (jboolean)isPentanomial {
  return isPentanomial_;
}

- (jint)getTc {
  if (!isTrinomial_) {
    @throw new_JavaLangRuntimeException_init();
  }
  return tc_;
}

- (IOSIntArray *)getPc {
  if (!isPentanomial_) {
    @throw new_JavaLangRuntimeException_init();
  }
  IOSIntArray *result = [IOSIntArray newArrayWithLength:3];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(pc_, 0, result, 0, 3);
  return result;
}

- (OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *)getSquaringVectorWithInt:(jint)i {
  return new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial_(IOSObjectArray_Get(nil_chk(squaringMatrix_), i));
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
      u = new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialElement_initWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_withJavaUtilRandom_(self, random_);
      ut = new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomial_initWithInt_withOrgSpongycastlePqcMathLinearalgebraGF2nElement_(2, OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialElement_ZEROWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_(self));
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
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"GF2nPolynomialField.computeCOBMatrix: B1 has a different degree and thus cannot be coverted to!");
  }
  if ([B1 isKindOfClass:[OrgSpongycastlePqcMathLinearalgebraGF2nONBField class]]) {
    [B1 computeCOBMatrixWithOrgSpongycastlePqcMathLinearalgebraGF2nField:self];
    return;
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
  if ([u isKindOfClass:[OrgSpongycastlePqcMathLinearalgebraGF2nONBElement class]]) {
    gamma = [IOSObjectArray newArrayWithLength:mDegree_ type:OrgSpongycastlePqcMathLinearalgebraGF2nONBElement_class_()];
    (void) IOSObjectArray_Set(gamma, mDegree_ - 1, OrgSpongycastlePqcMathLinearalgebraGF2nONBElement_ONEWithOrgSpongycastlePqcMathLinearalgebraGF2nONBField_((OrgSpongycastlePqcMathLinearalgebraGF2nONBField *) cast_chk(B1, [OrgSpongycastlePqcMathLinearalgebraGF2nONBField class])));
  }
  else {
    gamma = [IOSObjectArray newArrayWithLength:mDegree_ type:OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialElement_class_()];
    (void) IOSObjectArray_Set(gamma, mDegree_ - 1, OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialElement_ONEWithOrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_((OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *) cast_chk(B1, [OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField class])));
  }
  (void) IOSObjectArray_Set(gamma, mDegree_ - 2, u);
  for (i = mDegree_ - 3; i >= 0; i--) {
    (void) IOSObjectArray_Set(gamma, i, (OrgSpongycastlePqcMathLinearalgebraGF2nElement *) cast_chk([((OrgSpongycastlePqcMathLinearalgebraGF2nElement *) nil_chk(IOSObjectArray_Get(gamma, i + 1))) multiplyWithOrgSpongycastlePqcMathLinearalgebraGFElement:u], [OrgSpongycastlePqcMathLinearalgebraGF2nElement class]));
  }
  if ([B1 isKindOfClass:[OrgSpongycastlePqcMathLinearalgebraGF2nONBField class]]) {
    for (i = 0; i < mDegree_; i++) {
      for (j = 0; j < mDegree_; j++) {
        if ([((OrgSpongycastlePqcMathLinearalgebraGF2nElement *) nil_chk(IOSObjectArray_Get(gamma, i))) testBitWithInt:mDegree_ - j - 1]) {
          [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(IOSObjectArray_Get(COBMatrix, mDegree_ - j - 1))) setBitWithInt:mDegree_ - i - 1];
        }
      }
    }
  }
  else {
    for (i = 0; i < mDegree_; i++) {
      for (j = 0; j < mDegree_; j++) {
        if ([((OrgSpongycastlePqcMathLinearalgebraGF2nElement *) nil_chk(IOSObjectArray_Get(gamma, i))) testBitWithInt:j]) {
          [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(IOSObjectArray_Get(COBMatrix, mDegree_ - j - 1))) setBitWithInt:mDegree_ - i - 1];
        }
      }
    }
  }
  [((JavaUtilVector *) nil_chk(fields_)) addElementWithId:B1];
  [((JavaUtilVector *) nil_chk(matrices_)) addElementWithId:COBMatrix];
  [((JavaUtilVector *) nil_chk(B1->fields_)) addElementWithId:self];
  [((JavaUtilVector *) nil_chk(B1->matrices_)) addElementWithId:[self invertMatrixWithOrgSpongycastlePqcMathLinearalgebraGF2PolynomialArray:COBMatrix]];
}

- (void)computeSquaringMatrix {
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_computeSquaringMatrix(self);
}

- (void)computeFieldPolynomial {
  if (OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testTrinomials(self)) {
    return;
  }
  if (OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testPentanomials(self)) {
    return;
  }
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testRandom(self);
}

- (void)computeFieldPolynomial2 {
  if (OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testTrinomials(self)) {
    return;
  }
  if (OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testPentanomials(self)) {
    return;
  }
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testRandom(self);
}

- (jboolean)testTrinomials {
  return OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testTrinomials(self);
}

- (jboolean)testPentanomials {
  return OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testPentanomials(self);
}

- (jboolean)testRandom {
  return OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testRandom(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 3, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "[I", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathLinearalgebraGF2Polynomial;", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathLinearalgebraGF2nElement;", 0x4, 6, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 8, 9, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withJavaSecuritySecureRandom:);
  methods[1].selector = @selector(initWithInt:withJavaSecuritySecureRandom:withBoolean:);
  methods[2].selector = @selector(initWithInt:withJavaSecuritySecureRandom:withOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:);
  methods[3].selector = @selector(isTrinomial);
  methods[4].selector = @selector(isPentanomial);
  methods[5].selector = @selector(getTc);
  methods[6].selector = @selector(getPc);
  methods[7].selector = @selector(getSquaringVectorWithInt:);
  methods[8].selector = @selector(getRandomRootWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:);
  methods[9].selector = @selector(computeCOBMatrixWithOrgSpongycastlePqcMathLinearalgebraGF2nField:);
  methods[10].selector = @selector(computeSquaringMatrix);
  methods[11].selector = @selector(computeFieldPolynomial);
  methods[12].selector = @selector(computeFieldPolynomial2);
  methods[13].selector = @selector(testTrinomials);
  methods[14].selector = @selector(testPentanomials);
  methods[15].selector = @selector(testRandom);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "squaringMatrix_", "[LOrgSpongycastlePqcMathLinearalgebraGF2Polynomial;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "isTrinomial_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "isPentanomial_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "tc_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pc_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILJavaSecuritySecureRandom;", "ILJavaSecuritySecureRandom;Z", "ILJavaSecuritySecureRandom;LOrgSpongycastlePqcMathLinearalgebraGF2Polynomial;", "LJavaLangRuntimeException;", "getSquaringVector", "I", "getRandomRoot", "LOrgSpongycastlePqcMathLinearalgebraGF2Polynomial;", "computeCOBMatrix", "LOrgSpongycastlePqcMathLinearalgebraGF2nField;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField = { "GF2nPolynomialField", "org.spongycastle.pqc.math.linearalgebra", ptrTable, methods, fields, 7, 0x1, 16, 5, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField;
}

@end

void OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self, jint deg, JavaSecuritySecureRandom *random) {
  OrgSpongycastlePqcMathLinearalgebraGF2nField_initWithJavaSecuritySecureRandom_(self, random);
  self->isTrinomial_ = false;
  self->isPentanomial_ = false;
  self->pc_ = [IOSIntArray newArrayWithLength:3];
  if (deg < 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"k must be at least 3");
  }
  self->mDegree_ = deg;
  [self computeFieldPolynomial];
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_computeSquaringMatrix(self);
  self->fields_ = new_JavaUtilVector_init();
  self->matrices_ = new_JavaUtilVector_init();
}

OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_(jint deg, JavaSecuritySecureRandom *random) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField, initWithInt_withJavaSecuritySecureRandom_, deg, random)
}

OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *create_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_(jint deg, JavaSecuritySecureRandom *random) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField, initWithInt_withJavaSecuritySecureRandom_, deg, random)
}

void OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withBoolean_(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self, jint deg, JavaSecuritySecureRandom *random, jboolean file) {
  OrgSpongycastlePqcMathLinearalgebraGF2nField_initWithJavaSecuritySecureRandom_(self, random);
  self->isTrinomial_ = false;
  self->isPentanomial_ = false;
  self->pc_ = [IOSIntArray newArrayWithLength:3];
  if (deg < 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"k must be at least 3");
  }
  self->mDegree_ = deg;
  if (file) {
    [self computeFieldPolynomial];
  }
  else {
    [self computeFieldPolynomial2];
  }
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_computeSquaringMatrix(self);
  self->fields_ = new_JavaUtilVector_init();
  self->matrices_ = new_JavaUtilVector_init();
}

OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withBoolean_(jint deg, JavaSecuritySecureRandom *random, jboolean file) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField, initWithInt_withJavaSecuritySecureRandom_withBoolean_, deg, random, file)
}

OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *create_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withBoolean_(jint deg, JavaSecuritySecureRandom *random, jboolean file) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField, initWithInt_withJavaSecuritySecureRandom_withBoolean_, deg, random, file)
}

void OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withOrgSpongycastlePqcMathLinearalgebraGF2Polynomial_(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self, jint deg, JavaSecuritySecureRandom *random, OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *polynomial) {
  OrgSpongycastlePqcMathLinearalgebraGF2nField_initWithJavaSecuritySecureRandom_(self, random);
  self->isTrinomial_ = false;
  self->isPentanomial_ = false;
  self->pc_ = [IOSIntArray newArrayWithLength:3];
  if (deg < 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"degree must be at least 3");
  }
  if ([((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(polynomial)) getLength] != deg + 1) {
    @throw new_JavaLangRuntimeException_init();
  }
  if (![polynomial isIrreducible]) {
    @throw new_JavaLangRuntimeException_init();
  }
  self->mDegree_ = deg;
  self->fieldPolynomial_ = polynomial;
  OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_computeSquaringMatrix(self);
  jint k = 2;
  for (jint j = 1; j < [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) getLength] - 1; j++) {
    if ([((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) testBitWithInt:j]) {
      k++;
      if (k == 3) {
        self->tc_ = j;
      }
      if (k <= 5) {
        *IOSIntArray_GetRef(nil_chk(self->pc_), k - 3) = j;
      }
    }
  }
  if (k == 3) {
    self->isTrinomial_ = true;
  }
  if (k == 5) {
    self->isPentanomial_ = true;
  }
  self->fields_ = new_JavaUtilVector_init();
  self->matrices_ = new_JavaUtilVector_init();
}

OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *new_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withOrgSpongycastlePqcMathLinearalgebraGF2Polynomial_(jint deg, JavaSecuritySecureRandom *random, OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *polynomial) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField, initWithInt_withJavaSecuritySecureRandom_withOrgSpongycastlePqcMathLinearalgebraGF2Polynomial_, deg, random, polynomial)
}

OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *create_OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_initWithInt_withJavaSecuritySecureRandom_withOrgSpongycastlePqcMathLinearalgebraGF2Polynomial_(jint deg, JavaSecuritySecureRandom *random, OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *polynomial) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField, initWithInt_withJavaSecuritySecureRandom_withOrgSpongycastlePqcMathLinearalgebraGF2Polynomial_, deg, random, polynomial)
}

void OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_computeSquaringMatrix(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self) {
  IOSObjectArray *d = [IOSObjectArray newArrayWithLength:self->mDegree_ - 1 type:OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_class_()];
  jint i;
  jint j;
  self->squaringMatrix_ = [IOSObjectArray newArrayWithLength:self->mDegree_ type:OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_class_()];
  for (i = 0; i < ((IOSObjectArray *) nil_chk(self->squaringMatrix_))->size_; i++) {
    (void) IOSObjectArray_SetAndConsume(self->squaringMatrix_, i, new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_withNSString_(self->mDegree_, @"ZERO"));
  }
  for (i = 0; i < self->mDegree_ - 1; i++) {
    (void) IOSObjectArray_Set(d, i, [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk([new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_withNSString_(1, @"ONE") shiftLeftWithInt:self->mDegree_ + i])) remainderWithOrgSpongycastlePqcMathLinearalgebraGF2Polynomial:self->fieldPolynomial_]);
  }
  for (i = 1; i <= JavaLangMath_absWithInt_(JreRShift32(self->mDegree_, 1)); i++) {
    for (j = 1; j <= self->mDegree_; j++) {
      if ([((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(IOSObjectArray_Get(d, self->mDegree_ - (JreLShift32(i, 1))))) testBitWithInt:self->mDegree_ - j]) {
        [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(IOSObjectArray_Get(nil_chk(self->squaringMatrix_), j - 1))) setBitWithInt:self->mDegree_ - i];
      }
    }
  }
  for (i = JavaLangMath_absWithInt_(JreRShift32(self->mDegree_, 1)) + 1; i <= self->mDegree_; i++) {
    [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(IOSObjectArray_Get(nil_chk(self->squaringMatrix_), (JreLShift32(i, 1)) - self->mDegree_ - 1))) setBitWithInt:self->mDegree_ - i];
  }
}

jboolean OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testTrinomials(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self) {
  jint i;
  jint l;
  jboolean done = false;
  l = 0;
  self->fieldPolynomial_ = new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_(self->mDegree_ + 1);
  [self->fieldPolynomial_ setBitWithInt:0];
  [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) setBitWithInt:self->mDegree_];
  for (i = 1; (i < self->mDegree_) && !done; i++) {
    [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) setBitWithInt:i];
    done = [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) isIrreducible];
    l++;
    if (done) {
      self->isTrinomial_ = true;
      self->tc_ = i;
      return done;
    }
    [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) resetBitWithInt:i];
    done = [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) isIrreducible];
  }
  return done;
}

jboolean OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testPentanomials(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self) {
  jint i;
  jint j;
  jint k;
  jint l;
  jboolean done = false;
  l = 0;
  self->fieldPolynomial_ = new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_(self->mDegree_ + 1);
  [self->fieldPolynomial_ setBitWithInt:0];
  [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) setBitWithInt:self->mDegree_];
  for (i = 1; (i <= (self->mDegree_ - 3)) && !done; i++) {
    [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) setBitWithInt:i];
    for (j = i + 1; (j <= (self->mDegree_ - 2)) && !done; j++) {
      [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) setBitWithInt:j];
      for (k = j + 1; (k <= (self->mDegree_ - 1)) && !done; k++) {
        [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) setBitWithInt:k];
        if (((self->mDegree_ & 1) != 0) | ((i & 1) != 0) | ((j & 1) != 0) | ((k & 1) != 0)) {
          done = [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) isIrreducible];
          l++;
          if (done) {
            self->isPentanomial_ = true;
            *IOSIntArray_GetRef(nil_chk(self->pc_), 0) = i;
            *IOSIntArray_GetRef(self->pc_, 1) = j;
            *IOSIntArray_GetRef(self->pc_, 2) = k;
            return done;
          }
        }
        [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) resetBitWithInt:k];
      }
      [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) resetBitWithInt:j];
    }
    [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) resetBitWithInt:i];
  }
  return done;
}

jboolean OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField_testRandom(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField *self) {
  jint l;
  jboolean done = false;
  self->fieldPolynomial_ = new_OrgSpongycastlePqcMathLinearalgebraGF2Polynomial_initWithInt_(self->mDegree_ + 1);
  l = 0;
  while (!done) {
    l++;
    [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) randomize];
    [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) setBitWithInt:self->mDegree_];
    [((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) setBitWithInt:0];
    if ([((OrgSpongycastlePqcMathLinearalgebraGF2Polynomial *) nil_chk(self->fieldPolynomial_)) isIrreducible]) {
      done = true;
      return done;
    }
  }
  return done;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcMathLinearalgebraGF2nPolynomialField)