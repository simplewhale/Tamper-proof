//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/rainbow/util/ComputeInField.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/RuntimeException.h"
#include "org/spongycastle/pqc/crypto/rainbow/util/ComputeInField.h"
#include "org/spongycastle/pqc/crypto/rainbow/util/GF2Field.h"

@interface OrgSpongycastlePqcCryptoRainbowUtilComputeInField () {
 @public
  IOSObjectArray *A_;
}

- (void)computeZerosUnderWithBoolean:(jboolean)usedForInverse;

- (void)computeZerosAbove;

- (void)substitute;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoRainbowUtilComputeInField, A_, IOSObjectArray *)

__attribute__((unused)) static void OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosUnderWithBoolean_(OrgSpongycastlePqcCryptoRainbowUtilComputeInField *self, jboolean usedForInverse);

__attribute__((unused)) static void OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosAbove(OrgSpongycastlePqcCryptoRainbowUtilComputeInField *self);

__attribute__((unused)) static void OrgSpongycastlePqcCryptoRainbowUtilComputeInField_substitute(OrgSpongycastlePqcCryptoRainbowUtilComputeInField *self);

@implementation OrgSpongycastlePqcCryptoRainbowUtilComputeInField

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastlePqcCryptoRainbowUtilComputeInField_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSShortArray *)solveEquationWithShortArray2:(IOSObjectArray *)B
                                 withShortArray:(IOSShortArray *)b {
  if (((IOSObjectArray *) nil_chk(B))->size_ != ((IOSShortArray *) nil_chk(b))->size_) {
    return nil;
  }
  @try {
    A_ = [IOSShortArray newArrayWithDimensions:2 lengths:(jint[]){ B->size_, B->size_ + 1 }];
    x_ = [IOSShortArray newArrayWithLength:B->size_];
    for (jint i = 0; i < B->size_; i++) {
      for (jint j = 0; j < ((IOSShortArray *) nil_chk(IOSObjectArray_Get(B, 0)))->size_; j++) {
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(A_, i)), j) = IOSShortArray_Get(nil_chk(IOSObjectArray_Get(B, i)), j);
      }
    }
    for (jint i = 0; i < b->size_; i++) {
      *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(nil_chk(A_), i)), b->size_) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(b, i), IOSShortArray_Get(nil_chk(IOSObjectArray_Get(A_, i)), b->size_));
    }
    OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosUnderWithBoolean_(self, false);
    OrgSpongycastlePqcCryptoRainbowUtilComputeInField_substitute(self);
    return x_;
  }
  @catch (JavaLangRuntimeException *rte) {
    return nil;
  }
}

- (IOSObjectArray *)inverseWithShortArray2:(IOSObjectArray *)coef {
  @try {
    jshort factor;
    IOSObjectArray *inverse;
    A_ = [IOSShortArray newArrayWithDimensions:2 lengths:(jint[]){ ((IOSObjectArray *) nil_chk(coef))->size_, 2 * coef->size_ }];
    if (coef->size_ != ((IOSShortArray *) nil_chk(IOSObjectArray_Get(coef, 0)))->size_) {
      @throw new_JavaLangRuntimeException_initWithNSString_(@"The matrix is not invertible. Please choose another one!");
    }
    for (jint i = 0; i < coef->size_; i++) {
      for (jint j = 0; j < coef->size_; j++) {
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(A_, i)), j) = IOSShortArray_Get(nil_chk(IOSObjectArray_Get(coef, i)), j);
      }
      for (jint j = coef->size_; j < 2 * coef->size_; j++) {
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(A_, i)), j) = 0;
      }
      *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(A_, i)), i + A_->size_) = 1;
    }
    OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosUnderWithBoolean_(self, true);
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(A_))->size_; i++) {
      factor = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_invElemWithShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(A_, i)), i));
      for (jint j = i; j < 2 * ((IOSObjectArray *) nil_chk(A_))->size_; j++) {
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(A_, i)), j) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(A_, i)), j), factor);
      }
    }
    OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosAbove(self);
    inverse = [IOSShortArray newArrayWithDimensions:2 lengths:(jint[]){ ((IOSObjectArray *) nil_chk(A_))->size_, A_->size_ }];
    for (jint i = 0; i < A_->size_; i++) {
      for (jint j = A_->size_; j < 2 * A_->size_; j++) {
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(inverse, i)), j - A_->size_) = IOSShortArray_Get(nil_chk(IOSObjectArray_Get(A_, i)), j);
      }
    }
    return inverse;
  }
  @catch (JavaLangRuntimeException *rte) {
    return nil;
  }
}

- (void)computeZerosUnderWithBoolean:(jboolean)usedForInverse {
  OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosUnderWithBoolean_(self, usedForInverse);
}

- (void)computeZerosAbove {
  OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosAbove(self);
}

- (void)substitute {
  OrgSpongycastlePqcCryptoRainbowUtilComputeInField_substitute(self);
}

- (IOSObjectArray *)multiplyMatrixWithShortArray2:(IOSObjectArray *)M1
                                  withShortArray2:(IOSObjectArray *)M2 {
  if (((IOSShortArray *) nil_chk(IOSObjectArray_Get(nil_chk(M1), 0)))->size_ != ((IOSObjectArray *) nil_chk(M2))->size_) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"Multiplication is not possible!");
  }
  jshort tmp = 0;
  A_ = [IOSShortArray newArrayWithDimensions:2 lengths:(jint[]){ M1->size_, ((IOSShortArray *) nil_chk(IOSObjectArray_Get(M2, 0)))->size_ }];
  for (jint i = 0; i < M1->size_; i++) {
    for (jint j = 0; j < M2->size_; j++) {
      for (jint k = 0; k < ((IOSShortArray *) nil_chk(IOSObjectArray_Get(M2, 0)))->size_; k++) {
        tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(M1, i)), j), IOSShortArray_Get(nil_chk(IOSObjectArray_Get(M2, j)), k));
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(nil_chk(A_), i)), k) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(A_, i)), k), tmp);
      }
    }
  }
  return A_;
}

- (IOSShortArray *)multiplyMatrixWithShortArray2:(IOSObjectArray *)M1
                                  withShortArray:(IOSShortArray *)m {
  if (((IOSShortArray *) nil_chk(IOSObjectArray_Get(nil_chk(M1), 0)))->size_ != ((IOSShortArray *) nil_chk(m))->size_) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"Multiplication is not possible!");
  }
  jshort tmp = 0;
  IOSShortArray *B = [IOSShortArray newArrayWithLength:M1->size_];
  for (jint i = 0; i < M1->size_; i++) {
    for (jint j = 0; j < m->size_; j++) {
      tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(M1, i)), j), IOSShortArray_Get(m, j));
      *IOSShortArray_GetRef(B, i) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(B, i), tmp);
    }
  }
  return B;
}

- (IOSShortArray *)addVectWithShortArray:(IOSShortArray *)vector1
                          withShortArray:(IOSShortArray *)vector2 {
  if (((IOSShortArray *) nil_chk(vector1))->size_ != ((IOSShortArray *) nil_chk(vector2))->size_) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"Multiplication is not possible!");
  }
  IOSShortArray *rslt = [IOSShortArray newArrayWithLength:vector1->size_];
  for (jint n = 0; n < rslt->size_; n++) {
    *IOSShortArray_GetRef(rslt, n) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(vector1, n), IOSShortArray_Get(vector2, n));
  }
  return rslt;
}

- (IOSObjectArray *)multVectsWithShortArray:(IOSShortArray *)vector1
                             withShortArray:(IOSShortArray *)vector2 {
  if (((IOSShortArray *) nil_chk(vector1))->size_ != ((IOSShortArray *) nil_chk(vector2))->size_) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"Multiplication is not possible!");
  }
  IOSObjectArray *rslt = [IOSShortArray newArrayWithDimensions:2 lengths:(jint[]){ vector1->size_, vector2->size_ }];
  for (jint i = 0; i < vector1->size_; i++) {
    for (jint j = 0; j < vector2->size_; j++) {
      *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(rslt, i)), j) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(vector1, i), IOSShortArray_Get(vector2, j));
    }
  }
  return rslt;
}

- (IOSShortArray *)multVectWithShort:(jshort)scalar
                      withShortArray:(IOSShortArray *)vector {
  IOSShortArray *rslt = [IOSShortArray newArrayWithLength:((IOSShortArray *) nil_chk(vector))->size_];
  for (jint n = 0; n < rslt->size_; n++) {
    *IOSShortArray_GetRef(rslt, n) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(scalar, IOSShortArray_Get(vector, n));
  }
  return rslt;
}

- (IOSObjectArray *)multMatrixWithShort:(jshort)scalar
                        withShortArray2:(IOSObjectArray *)matrix {
  IOSObjectArray *rslt = [IOSShortArray newArrayWithDimensions:2 lengths:(jint[]){ ((IOSObjectArray *) nil_chk(matrix))->size_, ((IOSShortArray *) nil_chk(IOSObjectArray_Get(matrix, 0)))->size_ }];
  for (jint i = 0; i < matrix->size_; i++) {
    for (jint j = 0; j < ((IOSShortArray *) nil_chk(IOSObjectArray_Get(matrix, 0)))->size_; j++) {
      *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(rslt, i)), j) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(scalar, IOSShortArray_Get(nil_chk(IOSObjectArray_Get(matrix, i)), j));
    }
  }
  return rslt;
}

- (IOSObjectArray *)addSquareMatrixWithShortArray2:(IOSObjectArray *)matrix1
                                   withShortArray2:(IOSObjectArray *)matrix2 {
  if (((IOSObjectArray *) nil_chk(matrix1))->size_ != ((IOSObjectArray *) nil_chk(matrix2))->size_ || ((IOSShortArray *) nil_chk(IOSObjectArray_Get(matrix1, 0)))->size_ != ((IOSShortArray *) nil_chk(IOSObjectArray_Get(matrix2, 0)))->size_) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"Addition is not possible!");
  }
  IOSObjectArray *rslt = [IOSShortArray newArrayWithDimensions:2 lengths:(jint[]){ matrix1->size_, matrix1->size_ }];
  for (jint i = 0; i < matrix1->size_; i++) {
    for (jint j = 0; j < matrix2->size_; j++) {
      *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(rslt, i)), j) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(matrix1, i)), j), IOSShortArray_Get(nil_chk(IOSObjectArray_Get(matrix2, i)), j));
    }
  }
  return rslt;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[S", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[[S", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 4, 5, 6, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, 6, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, 7, -1, -1, -1 },
    { NULL, "[[S", 0x1, 8, 9, 6, -1, -1, -1 },
    { NULL, "[S", 0x1, 8, 1, 6, -1, -1, -1 },
    { NULL, "[S", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "[[S", 0x1, 12, 11, -1, -1, -1, -1 },
    { NULL, "[S", 0x1, 13, 14, -1, -1, -1, -1 },
    { NULL, "[[S", 0x1, 15, 16, -1, -1, -1, -1 },
    { NULL, "[[S", 0x1, 17, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(solveEquationWithShortArray2:withShortArray:);
  methods[2].selector = @selector(inverseWithShortArray2:);
  methods[3].selector = @selector(computeZerosUnderWithBoolean:);
  methods[4].selector = @selector(computeZerosAbove);
  methods[5].selector = @selector(substitute);
  methods[6].selector = @selector(multiplyMatrixWithShortArray2:withShortArray2:);
  methods[7].selector = @selector(multiplyMatrixWithShortArray2:withShortArray:);
  methods[8].selector = @selector(addVectWithShortArray:withShortArray:);
  methods[9].selector = @selector(multVectsWithShortArray:withShortArray:);
  methods[10].selector = @selector(multVectWithShort:withShortArray:);
  methods[11].selector = @selector(multMatrixWithShort:withShortArray2:);
  methods[12].selector = @selector(addSquareMatrixWithShortArray2:withShortArray2:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "A_", "[[S", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "x_", "[S", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "solveEquation", "[[S[S", "inverse", "[[S", "computeZerosUnder", "Z", "LJavaLangRuntimeException;", "LJavaLangIllegalStateException;", "multiplyMatrix", "[[S[[S", "addVect", "[S[S", "multVects", "multVect", "S[S", "multMatrix", "S[[S", "addSquareMatrix" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoRainbowUtilComputeInField = { "ComputeInField", "org.spongycastle.pqc.crypto.rainbow.util", ptrTable, methods, fields, 7, 0x1, 13, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoRainbowUtilComputeInField;
}

@end

void OrgSpongycastlePqcCryptoRainbowUtilComputeInField_init(OrgSpongycastlePqcCryptoRainbowUtilComputeInField *self) {
  NSObject_init(self);
}

OrgSpongycastlePqcCryptoRainbowUtilComputeInField *new_OrgSpongycastlePqcCryptoRainbowUtilComputeInField_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoRainbowUtilComputeInField, init)
}

OrgSpongycastlePqcCryptoRainbowUtilComputeInField *create_OrgSpongycastlePqcCryptoRainbowUtilComputeInField_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoRainbowUtilComputeInField, init)
}

void OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosUnderWithBoolean_(OrgSpongycastlePqcCryptoRainbowUtilComputeInField *self, jboolean usedForInverse) {
  jint length;
  jshort tmp = 0;
  if (usedForInverse) {
    length = 2 * ((IOSObjectArray *) nil_chk(self->A_))->size_;
  }
  else {
    length = ((IOSObjectArray *) nil_chk(self->A_))->size_ + 1;
  }
  for (jint k = 0; k < self->A_->size_ - 1; k++) {
    for (jint i = k + 1; i < ((IOSObjectArray *) nil_chk(self->A_))->size_; i++) {
      jshort factor1 = IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, i)), k);
      jshort factor2 = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_invElemWithShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, k)), k));
      if (factor2 == 0) {
        @throw new_JavaLangIllegalStateException_initWithNSString_(@"Matrix not invertible! We have to choose another one!");
      }
      for (jint j = k; j < length; j++) {
        tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(self->A_), k)), j), factor2);
        tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(factor1, tmp);
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(nil_chk(self->A_), i)), j) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, i)), j), tmp);
      }
    }
  }
}

void OrgSpongycastlePqcCryptoRainbowUtilComputeInField_computeZerosAbove(OrgSpongycastlePqcCryptoRainbowUtilComputeInField *self) {
  jshort tmp = 0;
  for (jint k = ((IOSObjectArray *) nil_chk(self->A_))->size_ - 1; k > 0; k--) {
    for (jint i = k - 1; i >= 0; i--) {
      jshort factor1 = IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, i)), k);
      jshort factor2 = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_invElemWithShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, k)), k));
      if (factor2 == 0) {
        @throw new_JavaLangRuntimeException_initWithNSString_(@"The matrix is not invertible");
      }
      for (jint j = k; j < 2 * ((IOSObjectArray *) nil_chk(self->A_))->size_; j++) {
        tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, k)), j), factor2);
        tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(factor1, tmp);
        *IOSShortArray_GetRef(nil_chk(IOSObjectArray_Get(nil_chk(self->A_), i)), j) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, i)), j), tmp);
      }
    }
  }
}

void OrgSpongycastlePqcCryptoRainbowUtilComputeInField_substitute(OrgSpongycastlePqcCryptoRainbowUtilComputeInField *self) {
  jshort tmp;
  jshort temp;
  temp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_invElemWithShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, ((IOSObjectArray *) nil_chk(self->A_))->size_ - 1)), self->A_->size_ - 1));
  if (temp == 0) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"The equation system is not solvable");
  }
  *IOSShortArray_GetRef(nil_chk(self->x_), ((IOSObjectArray *) nil_chk(self->A_))->size_ - 1) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(self->A_, self->A_->size_ - 1)), self->A_->size_), temp);
  for (jint i = ((IOSObjectArray *) nil_chk(self->A_))->size_ - 2; i >= 0; i--) {
    tmp = IOSShortArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(self->A_), i)), self->A_->size_);
    for (jint j = self->A_->size_ - 1; j > i; j--) {
      temp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(self->A_), i)), j), IOSShortArray_Get(nil_chk(self->x_), j));
      tmp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_addElemWithShort_withShort_(tmp, temp);
    }
    temp = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_invElemWithShort_(IOSShortArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(self->A_), i)), i));
    if (temp == 0) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"Not solvable equation system");
    }
    *IOSShortArray_GetRef(nil_chk(self->x_), i) = OrgSpongycastlePqcCryptoRainbowUtilGF2Field_multElemWithShort_withShort_(tmp, temp);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoRainbowUtilComputeInField)
