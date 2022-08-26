//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/djb/Curve25519Point.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/custom/djb/Curve25519Field.h"
#include "org/spongycastle/math/ec/custom/djb/Curve25519FieldElement.h"
#include "org/spongycastle/math/ec/custom/djb/Curve25519Point.h"
#include "org/spongycastle/math/raw/Nat256.h"

@implementation OrgSpongycastleMathEcCustomDjbCurve25519Point

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y {
  OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(self, curve, x, y);
  return self;
}

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                         withBoolean:(jboolean)withCompression {
  OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(self, curve, x, y, withCompression);
  return self;
}

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
        withOrgSpongycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                         withBoolean:(jboolean)withCompression {
  OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(self, curve, x, y, zs, withCompression);
  return self;
}

- (OrgSpongycastleMathEcECPoint *)detach {
  return new_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(nil, [self getAffineXCoord], [self getAffineYCoord]);
}

- (OrgSpongycastleMathEcECFieldElement *)getZCoordWithInt:(jint)index {
  if (index == 1) {
    return [self getJacobianModifiedW];
  }
  return [super getZCoordWithInt:index];
}

- (OrgSpongycastleMathEcECPoint *)addWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)b {
  if ([self isInfinity]) {
    return b;
  }
  if ([((OrgSpongycastleMathEcECPoint *) nil_chk(b)) isInfinity]) {
    return self;
  }
  if (self == b) {
    return [self twice];
  }
  OrgSpongycastleMathEcECCurve *curve = [self getCurve];
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *X1 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk(self->x_, [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Y1 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk(self->y_, [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Z1 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk(IOSObjectArray_Get(nil_chk(self->zs_), 0), [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *X2 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk([b getXCoord], [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Y2 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk([b getYCoord], [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Z2 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk([b getZCoordWithInt:0], [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  jint c;
  IOSIntArray *tt1 = OrgSpongycastleMathRawNat256_createExt();
  IOSIntArray *t2 = OrgSpongycastleMathRawNat256_create();
  IOSIntArray *t3 = OrgSpongycastleMathRawNat256_create();
  IOSIntArray *t4 = OrgSpongycastleMathRawNat256_create();
  jboolean Z1IsOne = [((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Z1)) isOne];
  IOSIntArray *U2;
  IOSIntArray *S2;
  if (Z1IsOne) {
    U2 = ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(X2))->x_;
    S2 = ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Y2))->x_;
  }
  else {
    S2 = t3;
    OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(Z1->x_, S2);
    U2 = t2;
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(S2, ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(X2))->x_, U2);
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(S2, Z1->x_, S2);
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(S2, ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Y2))->x_, S2);
  }
  jboolean Z2IsOne = [((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Z2)) isOne];
  IOSIntArray *U1;
  IOSIntArray *S1;
  if (Z2IsOne) {
    U1 = ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(X1))->x_;
    S1 = ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Y1))->x_;
  }
  else {
    S1 = t4;
    OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(Z2->x_, S1);
    U1 = tt1;
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(S1, ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(X1))->x_, U1);
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(S1, Z2->x_, S1);
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(S1, ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Y1))->x_, S1);
  }
  IOSIntArray *H = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomDjbCurve25519Field_subtractWithIntArray_withIntArray_withIntArray_(U1, U2, H);
  IOSIntArray *R = t2;
  OrgSpongycastleMathEcCustomDjbCurve25519Field_subtractWithIntArray_withIntArray_withIntArray_(S1, S2, R);
  if (OrgSpongycastleMathRawNat256_isZeroWithIntArray_(H)) {
    if (OrgSpongycastleMathRawNat256_isZeroWithIntArray_(R)) {
      return [self twice];
    }
    return [((OrgSpongycastleMathEcECCurve *) nil_chk(curve)) getInfinity];
  }
  IOSIntArray *HSquared = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(H, HSquared);
  IOSIntArray *G = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(HSquared, H, G);
  IOSIntArray *V = t3;
  OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(HSquared, U1, V);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_negateWithIntArray_withIntArray_(G, G);
  OrgSpongycastleMathRawNat256_mulWithIntArray_withIntArray_withIntArray_(S1, G, tt1);
  c = OrgSpongycastleMathRawNat256_addBothToWithIntArray_withIntArray_withIntArray_(V, V, G);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_reduce27WithInt_withIntArray_(c, G);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *X3 = new_OrgSpongycastleMathEcCustomDjbCurve25519FieldElement_initWithIntArray_(t4);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(R, X3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_subtractWithIntArray_withIntArray_withIntArray_(X3->x_, G, X3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Y3 = new_OrgSpongycastleMathEcCustomDjbCurve25519FieldElement_initWithIntArray_(G);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_subtractWithIntArray_withIntArray_withIntArray_(V, X3->x_, Y3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyAddToExtWithIntArray_withIntArray_withIntArray_(Y3->x_, R, tt1);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_reduceWithIntArray_withIntArray_(tt1, Y3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Z3 = new_OrgSpongycastleMathEcCustomDjbCurve25519FieldElement_initWithIntArray_(H);
  if (!Z1IsOne) {
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(Z3->x_, Z1->x_, Z3->x_);
  }
  if (!Z2IsOne) {
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(Z3->x_, Z2->x_, Z3->x_);
  }
  IOSIntArray *Z3Squared = (Z1IsOne && Z2IsOne) ? HSquared : nil;
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *W3 = [self calculateJacobianModifiedWWithOrgSpongycastleMathEcCustomDjbCurve25519FieldElement:Z3 withIntArray:Z3Squared];
  IOSObjectArray *zs = [IOSObjectArray newArrayWithObjects:(id[]){ Z3, W3 } count:2 type:OrgSpongycastleMathEcECFieldElement_class_()];
  return new_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(curve, X3, Y3, zs, self->withCompression_);
}

- (OrgSpongycastleMathEcECPoint *)twice {
  if ([self isInfinity]) {
    return self;
  }
  OrgSpongycastleMathEcECCurve *curve = [self getCurve];
  OrgSpongycastleMathEcECFieldElement *Y1 = self->y_;
  if ([((OrgSpongycastleMathEcECFieldElement *) nil_chk(Y1)) isZero]) {
    return [((OrgSpongycastleMathEcECCurve *) nil_chk(curve)) getInfinity];
  }
  return [self twiceJacobianModifiedWithBoolean:true];
}

- (OrgSpongycastleMathEcECPoint *)twicePlusWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)b {
  if (self == b) {
    return [self threeTimes];
  }
  if ([self isInfinity]) {
    return b;
  }
  if ([((OrgSpongycastleMathEcECPoint *) nil_chk(b)) isInfinity]) {
    return [self twice];
  }
  OrgSpongycastleMathEcECFieldElement *Y1 = self->y_;
  if ([((OrgSpongycastleMathEcECFieldElement *) nil_chk(Y1)) isZero]) {
    return b;
  }
  return [((OrgSpongycastleMathEcCustomDjbCurve25519Point *) nil_chk([self twiceJacobianModifiedWithBoolean:false])) addWithOrgSpongycastleMathEcECPoint:b];
}

- (OrgSpongycastleMathEcECPoint *)threeTimes {
  if ([self isInfinity]) {
    return self;
  }
  OrgSpongycastleMathEcECFieldElement *Y1 = self->y_;
  if ([((OrgSpongycastleMathEcECFieldElement *) nil_chk(Y1)) isZero]) {
    return self;
  }
  return [((OrgSpongycastleMathEcCustomDjbCurve25519Point *) nil_chk([self twiceJacobianModifiedWithBoolean:false])) addWithOrgSpongycastleMathEcECPoint:self];
}

- (OrgSpongycastleMathEcECPoint *)negate {
  if ([self isInfinity]) {
    return self;
  }
  return new_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_([self getCurve], self->x_, [((OrgSpongycastleMathEcECFieldElement *) nil_chk(self->y_)) negate], self->zs_, self->withCompression_);
}

- (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *)calculateJacobianModifiedWWithOrgSpongycastleMathEcCustomDjbCurve25519FieldElement:(OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *)Z
                                                                                                                                withIntArray:(IOSIntArray *)ZSquared {
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *a4 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk([((OrgSpongycastleMathEcECCurve *) nil_chk([self getCurve])) getA], [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  if ([((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Z)) isOne]) {
    return a4;
  }
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *W = new_OrgSpongycastleMathEcCustomDjbCurve25519FieldElement_init();
  if (ZSquared == nil) {
    ZSquared = W->x_;
    OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(Z->x_, ZSquared);
  }
  OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(ZSquared, W->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(W->x_, ((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(a4))->x_, W->x_);
  return W;
}

- (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *)getJacobianModifiedW {
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *W = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk(IOSObjectArray_Get(nil_chk(self->zs_), 1), [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  if (W == nil) {
    (void) IOSObjectArray_Set(self->zs_, 1, W = [self calculateJacobianModifiedWWithOrgSpongycastleMathEcCustomDjbCurve25519FieldElement:(OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk(IOSObjectArray_Get(self->zs_, 0), [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]) withIntArray:nil]);
  }
  return W;
}

- (OrgSpongycastleMathEcCustomDjbCurve25519Point *)twiceJacobianModifiedWithBoolean:(jboolean)calculateW {
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *X1 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk(self->x_, [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Y1 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk(self->y_, [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Z1 = (OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) cast_chk(IOSObjectArray_Get(nil_chk(self->zs_), 0), [OrgSpongycastleMathEcCustomDjbCurve25519FieldElement class]);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *W1 = [self getJacobianModifiedW];
  jint c;
  IOSIntArray *M = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(X1))->x_, M);
  c = OrgSpongycastleMathRawNat256_addBothToWithIntArray_withIntArray_withIntArray_(M, M, M);
  c += OrgSpongycastleMathRawNat256_addToWithIntArray_withIntArray_(((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(W1))->x_, M);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_reduce27WithInt_withIntArray_(c, M);
  IOSIntArray *_2Y1 = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomDjbCurve25519Field_twiceWithIntArray_withIntArray_(((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Y1))->x_, _2Y1);
  IOSIntArray *_2Y1Squared = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(_2Y1, Y1->x_, _2Y1Squared);
  IOSIntArray *S = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(_2Y1Squared, X1->x_, S);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_twiceWithIntArray_withIntArray_(S, S);
  IOSIntArray *_8T = OrgSpongycastleMathRawNat256_create();
  OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(_2Y1Squared, _8T);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_twiceWithIntArray_withIntArray_(_8T, _8T);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *X3 = new_OrgSpongycastleMathEcCustomDjbCurve25519FieldElement_initWithIntArray_(_2Y1Squared);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_squareWithIntArray_withIntArray_(M, X3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_subtractWithIntArray_withIntArray_withIntArray_(X3->x_, S, X3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_subtractWithIntArray_withIntArray_withIntArray_(X3->x_, S, X3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Y3 = new_OrgSpongycastleMathEcCustomDjbCurve25519FieldElement_initWithIntArray_(S);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_subtractWithIntArray_withIntArray_withIntArray_(S, X3->x_, Y3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(Y3->x_, M, Y3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519Field_subtractWithIntArray_withIntArray_withIntArray_(Y3->x_, _8T, Y3->x_);
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *Z3 = new_OrgSpongycastleMathEcCustomDjbCurve25519FieldElement_initWithIntArray_(_2Y1);
  if (!OrgSpongycastleMathRawNat256_isOneWithIntArray_(((OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *) nil_chk(Z1))->x_)) {
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(Z3->x_, Z1->x_, Z3->x_);
  }
  OrgSpongycastleMathEcCustomDjbCurve25519FieldElement *W3 = nil;
  if (calculateW) {
    W3 = new_OrgSpongycastleMathEcCustomDjbCurve25519FieldElement_initWithIntArray_(_8T);
    OrgSpongycastleMathEcCustomDjbCurve25519Field_multiplyWithIntArray_withIntArray_withIntArray_(W3->x_, W1->x_, W3->x_);
    OrgSpongycastleMathEcCustomDjbCurve25519Field_twiceWithIntArray_withIntArray_(W3->x_, W3->x_);
  }
  return new_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_([self getCurve], X3, Y3, [IOSObjectArray newArrayWithObjects:(id[]){ Z3, W3 } count:2 type:OrgSpongycastleMathEcECFieldElement_class_()], self->withCompression_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECFieldElement;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, 7, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcCustomDjbCurve25519FieldElement;", 0x4, 8, 9, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcCustomDjbCurve25519FieldElement;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcCustomDjbCurve25519Point;", 0x4, 10, 11, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:);
  methods[1].selector = @selector(initWithOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withBoolean:);
  methods[2].selector = @selector(initWithOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElementArray:withBoolean:);
  methods[3].selector = @selector(detach);
  methods[4].selector = @selector(getZCoordWithInt:);
  methods[5].selector = @selector(addWithOrgSpongycastleMathEcECPoint:);
  methods[6].selector = @selector(twice);
  methods[7].selector = @selector(twicePlusWithOrgSpongycastleMathEcECPoint:);
  methods[8].selector = @selector(threeTimes);
  methods[9].selector = @selector(negate);
  methods[10].selector = @selector(calculateJacobianModifiedWWithOrgSpongycastleMathEcCustomDjbCurve25519FieldElement:withIntArray:);
  methods[11].selector = @selector(getJacobianModifiedW);
  methods[12].selector = @selector(twiceJacobianModifiedWithBoolean:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;", "LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;Z", "LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;[LOrgSpongycastleMathEcECFieldElement;Z", "getZCoord", "I", "add", "LOrgSpongycastleMathEcECPoint;", "twicePlus", "calculateJacobianModifiedW", "LOrgSpongycastleMathEcCustomDjbCurve25519FieldElement;[I", "twiceJacobianModified", "Z" };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomDjbCurve25519Point = { "Curve25519Point", "org.spongycastle.math.ec.custom.djb", ptrTable, methods, NULL, 7, 0x1, 13, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomDjbCurve25519Point;
}

@end

void OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcCustomDjbCurve25519Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y) {
  OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(self, curve, x, y, false);
}

OrgSpongycastleMathEcCustomDjbCurve25519Point *new_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomDjbCurve25519Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_, curve, x, y)
}

OrgSpongycastleMathEcCustomDjbCurve25519Point *create_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomDjbCurve25519Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_, curve, x, y)
}

void OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcCustomDjbCurve25519Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression) {
  OrgSpongycastleMathEcECPoint_AbstractFp_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(self, curve, x, y);
  if ((x == nil) != (y == nil)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Exactly one of the field elements is null");
  }
  self->withCompression_ = withCompression;
}

OrgSpongycastleMathEcCustomDjbCurve25519Point *new_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomDjbCurve25519Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_, curve, x, y, withCompression)
}

OrgSpongycastleMathEcCustomDjbCurve25519Point *create_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomDjbCurve25519Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_, curve, x, y, withCompression)
}

void OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcCustomDjbCurve25519Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  OrgSpongycastleMathEcECPoint_AbstractFp_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_(self, curve, x, y, zs);
  self->withCompression_ = withCompression;
}

OrgSpongycastleMathEcCustomDjbCurve25519Point *new_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomDjbCurve25519Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_, curve, x, y, zs, withCompression)
}

OrgSpongycastleMathEcCustomDjbCurve25519Point *create_OrgSpongycastleMathEcCustomDjbCurve25519Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomDjbCurve25519Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_, curve, x, y, zs, withCompression)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomDjbCurve25519Point)
