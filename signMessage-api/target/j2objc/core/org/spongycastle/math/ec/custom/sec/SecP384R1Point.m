//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/custom/sec/SecP384R1Point.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECFieldElement.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/custom/sec/SecP384R1Field.h"
#include "org/spongycastle/math/ec/custom/sec/SecP384R1FieldElement.h"
#include "org/spongycastle/math/ec/custom/sec/SecP384R1Point.h"
#include "org/spongycastle/math/raw/Nat.h"
#include "org/spongycastle/math/raw/Nat384.h"

@implementation OrgSpongycastleMathEcCustomSecSecP384R1Point

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y {
  OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(self, curve, x, y);
  return self;
}

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
                                         withBoolean:(jboolean)withCompression {
  OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(self, curve, x, y, withCompression);
  return self;
}

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)x
             withOrgSpongycastleMathEcECFieldElement:(OrgSpongycastleMathEcECFieldElement *)y
        withOrgSpongycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                         withBoolean:(jboolean)withCompression {
  OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(self, curve, x, y, zs, withCompression);
  return self;
}

- (OrgSpongycastleMathEcECPoint *)detach {
  return new_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(nil, [self getAffineXCoord], [self getAffineYCoord]);
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
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *X1 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk(self->x_, [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Y1 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk(self->y_, [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *X2 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk([b getXCoord], [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Y2 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk([b getYCoord], [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Z1 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk(IOSObjectArray_Get(nil_chk(self->zs_), 0), [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Z2 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk([b getZCoordWithInt:0], [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  jint c;
  IOSIntArray *tt1 = OrgSpongycastleMathRawNat_createWithInt_(24);
  IOSIntArray *tt2 = OrgSpongycastleMathRawNat_createWithInt_(24);
  IOSIntArray *t3 = OrgSpongycastleMathRawNat_createWithInt_(12);
  IOSIntArray *t4 = OrgSpongycastleMathRawNat_createWithInt_(12);
  jboolean Z1IsOne = [((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(Z1)) isOne];
  IOSIntArray *U2;
  IOSIntArray *S2;
  if (Z1IsOne) {
    U2 = ((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(X2))->x_;
    S2 = ((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(Y2))->x_;
  }
  else {
    S2 = t3;
    OrgSpongycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(Z1->x_, S2);
    U2 = tt2;
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(S2, ((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(X2))->x_, U2);
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(S2, Z1->x_, S2);
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(S2, ((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(Y2))->x_, S2);
  }
  jboolean Z2IsOne = [((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(Z2)) isOne];
  IOSIntArray *U1;
  IOSIntArray *S1;
  if (Z2IsOne) {
    U1 = ((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(X1))->x_;
    S1 = ((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(Y1))->x_;
  }
  else {
    S1 = t4;
    OrgSpongycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(Z2->x_, S1);
    U1 = tt1;
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(S1, ((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(X1))->x_, U1);
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(S1, Z2->x_, S1);
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(S1, ((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(Y1))->x_, S1);
  }
  IOSIntArray *H = OrgSpongycastleMathRawNat_createWithInt_(12);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(U1, U2, H);
  IOSIntArray *R = OrgSpongycastleMathRawNat_createWithInt_(12);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(S1, S2, R);
  if (OrgSpongycastleMathRawNat_isZeroWithInt_withIntArray_(12, H)) {
    if (OrgSpongycastleMathRawNat_isZeroWithInt_withIntArray_(12, R)) {
      return [self twice];
    }
    return [((OrgSpongycastleMathEcECCurve *) nil_chk(curve)) getInfinity];
  }
  IOSIntArray *HSquared = t3;
  OrgSpongycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(H, HSquared);
  IOSIntArray *G = OrgSpongycastleMathRawNat_createWithInt_(12);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(HSquared, H, G);
  IOSIntArray *V = t3;
  OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(HSquared, U1, V);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_negateWithIntArray_withIntArray_(G, G);
  OrgSpongycastleMathRawNat384_mulWithIntArray_withIntArray_withIntArray_(S1, G, tt1);
  c = OrgSpongycastleMathRawNat_addBothToWithInt_withIntArray_withIntArray_withIntArray_(12, V, V, G);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_reduce32WithInt_withIntArray_(c, G);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *X3 = new_OrgSpongycastleMathEcCustomSecSecP384R1FieldElement_initWithIntArray_(t4);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(R, X3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(X3->x_, G, X3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Y3 = new_OrgSpongycastleMathEcCustomSecSecP384R1FieldElement_initWithIntArray_(G);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(V, X3->x_, Y3->x_);
  OrgSpongycastleMathRawNat384_mulWithIntArray_withIntArray_withIntArray_(Y3->x_, R, tt2);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_addExtWithIntArray_withIntArray_withIntArray_(tt1, tt2, tt1);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_reduceWithIntArray_withIntArray_(tt1, Y3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Z3 = new_OrgSpongycastleMathEcCustomSecSecP384R1FieldElement_initWithIntArray_(H);
  if (!Z1IsOne) {
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(Z3->x_, Z1->x_, Z3->x_);
  }
  if (!Z2IsOne) {
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(Z3->x_, Z2->x_, Z3->x_);
  }
  IOSObjectArray *zs = [IOSObjectArray newArrayWithObjects:(id[]){ Z3 } count:1 type:OrgSpongycastleMathEcECFieldElement_class_()];
  return new_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(curve, X3, Y3, zs, self->withCompression_);
}

- (OrgSpongycastleMathEcECPoint *)twice {
  if ([self isInfinity]) {
    return self;
  }
  OrgSpongycastleMathEcECCurve *curve = [self getCurve];
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Y1 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk(self->y_, [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  if ([((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(Y1)) isZero]) {
    return [((OrgSpongycastleMathEcECCurve *) nil_chk(curve)) getInfinity];
  }
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *X1 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk(self->x_, [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Z1 = (OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) cast_chk(IOSObjectArray_Get(nil_chk(self->zs_), 0), [OrgSpongycastleMathEcCustomSecSecP384R1FieldElement class]);
  jint c;
  IOSIntArray *t1 = OrgSpongycastleMathRawNat_createWithInt_(12);
  IOSIntArray *t2 = OrgSpongycastleMathRawNat_createWithInt_(12);
  IOSIntArray *Y1Squared = OrgSpongycastleMathRawNat_createWithInt_(12);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(Y1->x_, Y1Squared);
  IOSIntArray *T = OrgSpongycastleMathRawNat_createWithInt_(12);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(Y1Squared, T);
  jboolean Z1IsOne = [((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(Z1)) isOne];
  IOSIntArray *Z1Squared = Z1->x_;
  if (!Z1IsOne) {
    Z1Squared = t2;
    OrgSpongycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(Z1->x_, Z1Squared);
  }
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(((OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *) nil_chk(X1))->x_, Z1Squared, t1);
  IOSIntArray *M = t2;
  OrgSpongycastleMathEcCustomSecSecP384R1Field_addWithIntArray_withIntArray_withIntArray_(X1->x_, Z1Squared, M);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(M, t1, M);
  c = OrgSpongycastleMathRawNat_addBothToWithInt_withIntArray_withIntArray_withIntArray_(12, M, M, M);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_reduce32WithInt_withIntArray_(c, M);
  IOSIntArray *S = Y1Squared;
  OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(Y1Squared, X1->x_, S);
  c = OrgSpongycastleMathRawNat_shiftUpBitsWithInt_withIntArray_withInt_withInt_(12, S, 2, 0);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_reduce32WithInt_withIntArray_(c, S);
  c = OrgSpongycastleMathRawNat_shiftUpBitsWithInt_withIntArray_withInt_withInt_withIntArray_(12, T, 3, 0, t1);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_reduce32WithInt_withIntArray_(c, t1);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *X3 = new_OrgSpongycastleMathEcCustomSecSecP384R1FieldElement_initWithIntArray_(T);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_squareWithIntArray_withIntArray_(M, X3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(X3->x_, S, X3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(X3->x_, S, X3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Y3 = new_OrgSpongycastleMathEcCustomSecSecP384R1FieldElement_initWithIntArray_(S);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(S, X3->x_, Y3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(Y3->x_, M, Y3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_subtractWithIntArray_withIntArray_withIntArray_(Y3->x_, t1, Y3->x_);
  OrgSpongycastleMathEcCustomSecSecP384R1FieldElement *Z3 = new_OrgSpongycastleMathEcCustomSecSecP384R1FieldElement_initWithIntArray_(M);
  OrgSpongycastleMathEcCustomSecSecP384R1Field_twiceWithIntArray_withIntArray_(Y1->x_, Z3->x_);
  if (!Z1IsOne) {
    OrgSpongycastleMathEcCustomSecSecP384R1Field_multiplyWithIntArray_withIntArray_withIntArray_(Z3->x_, Z1->x_, Z3->x_);
  }
  return new_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(curve, X3, Y3, [IOSObjectArray newArrayWithObjects:(id[]){ Z3 } count:1 type:OrgSpongycastleMathEcECFieldElement_class_()], self->withCompression_);
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
  return [((OrgSpongycastleMathEcECPoint *) nil_chk([self twice])) addWithOrgSpongycastleMathEcECPoint:b];
}

- (OrgSpongycastleMathEcECPoint *)threeTimes {
  if ([self isInfinity] || [((OrgSpongycastleMathEcECFieldElement *) nil_chk(self->y_)) isZero]) {
    return self;
  }
  return [((OrgSpongycastleMathEcECPoint *) nil_chk([self twice])) addWithOrgSpongycastleMathEcECPoint:self];
}

- (OrgSpongycastleMathEcECPoint *)negate {
  if ([self isInfinity]) {
    return self;
  }
  return new_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(curve_, self->x_, [((OrgSpongycastleMathEcECFieldElement *) nil_chk(self->y_)) negate], self->zs_, self->withCompression_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, 5, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:);
  methods[1].selector = @selector(initWithOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withBoolean:);
  methods[2].selector = @selector(initWithOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElement:withOrgSpongycastleMathEcECFieldElementArray:withBoolean:);
  methods[3].selector = @selector(detach);
  methods[4].selector = @selector(addWithOrgSpongycastleMathEcECPoint:);
  methods[5].selector = @selector(twice);
  methods[6].selector = @selector(twicePlusWithOrgSpongycastleMathEcECPoint:);
  methods[7].selector = @selector(threeTimes);
  methods[8].selector = @selector(negate);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;", "LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;Z", "LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECFieldElement;LOrgSpongycastleMathEcECFieldElement;[LOrgSpongycastleMathEcECFieldElement;Z", "add", "LOrgSpongycastleMathEcECPoint;", "twicePlus" };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcCustomSecSecP384R1Point = { "SecP384R1Point", "org.spongycastle.math.ec.custom.sec", ptrTable, methods, NULL, 7, 0x1, 9, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcCustomSecSecP384R1Point;
}

@end

void OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcCustomSecSecP384R1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y) {
  OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(self, curve, x, y, false);
}

OrgSpongycastleMathEcCustomSecSecP384R1Point *new_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP384R1Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_, curve, x, y)
}

OrgSpongycastleMathEcCustomSecSecP384R1Point *create_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP384R1Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_, curve, x, y)
}

void OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcCustomSecSecP384R1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression) {
  OrgSpongycastleMathEcECPoint_AbstractFp_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_(self, curve, x, y);
  if ((x == nil) != (y == nil)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Exactly one of the field elements is null");
  }
  self->withCompression_ = withCompression;
}

OrgSpongycastleMathEcCustomSecSecP384R1Point *new_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP384R1Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_, curve, x, y, withCompression)
}

OrgSpongycastleMathEcCustomSecSecP384R1Point *create_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, jboolean withCompression) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP384R1Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withBoolean_, curve, x, y, withCompression)
}

void OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcCustomSecSecP384R1Point *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  OrgSpongycastleMathEcECPoint_AbstractFp_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_(self, curve, x, y, zs);
  self->withCompression_ = withCompression;
}

OrgSpongycastleMathEcCustomSecSecP384R1Point *new_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcCustomSecSecP384R1Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_, curve, x, y, zs, withCompression)
}

OrgSpongycastleMathEcCustomSecSecP384R1Point *create_OrgSpongycastleMathEcCustomSecSecP384R1Point_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECFieldElement *x, OrgSpongycastleMathEcECFieldElement *y, IOSObjectArray *zs, jboolean withCompression) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcCustomSecSecP384R1Point, initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElement_withOrgSpongycastleMathEcECFieldElementArray_withBoolean_, curve, x, y, zs, withCompression)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcCustomSecSecP384R1Point)
