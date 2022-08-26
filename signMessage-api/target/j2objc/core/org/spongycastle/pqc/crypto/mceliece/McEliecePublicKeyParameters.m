//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/mceliece/McEliecePublicKeyParameters.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/pqc/crypto/mceliece/McElieceKeyParameters.h"
#include "org/spongycastle/pqc/crypto/mceliece/McEliecePublicKeyParameters.h"
#include "org/spongycastle/pqc/math/linearalgebra/GF2Matrix.h"

@interface OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters () {
 @public
  jint n_;
  jint t_;
  OrgSpongycastlePqcMathLinearalgebraGF2Matrix *g_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters, g_, OrgSpongycastlePqcMathLinearalgebraGF2Matrix *)

@implementation OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters

- (instancetype)initWithInt:(jint)n
                    withInt:(jint)t
withOrgSpongycastlePqcMathLinearalgebraGF2Matrix:(OrgSpongycastlePqcMathLinearalgebraGF2Matrix *)g {
  OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters_initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_(self, n, t, g);
  return self;
}

- (jint)getN {
  return n_;
}

- (jint)getT {
  return t_;
}

- (OrgSpongycastlePqcMathLinearalgebraGF2Matrix *)getG {
  return g_;
}

- (jint)getK {
  return [((OrgSpongycastlePqcMathLinearalgebraGF2Matrix *) nil_chk(g_)) getNumRows];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastlePqcMathLinearalgebraGF2Matrix;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withInt:withOrgSpongycastlePqcMathLinearalgebraGF2Matrix:);
  methods[1].selector = @selector(getN);
  methods[2].selector = @selector(getT);
  methods[3].selector = @selector(getG);
  methods[4].selector = @selector(getK);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "n_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "t_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "g_", "LOrgSpongycastlePqcMathLinearalgebraGF2Matrix;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "IILOrgSpongycastlePqcMathLinearalgebraGF2Matrix;" };
  static const J2ObjcClassInfo _OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters = { "McEliecePublicKeyParameters", "org.spongycastle.pqc.crypto.mceliece", ptrTable, methods, fields, 7, 0x1, 5, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters;
}

@end

void OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters_initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_(OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters *self, jint n, jint t, OrgSpongycastlePqcMathLinearalgebraGF2Matrix *g) {
  OrgSpongycastlePqcCryptoMcelieceMcElieceKeyParameters_initWithBoolean_withOrgSpongycastlePqcCryptoMcelieceMcElieceParameters_(self, false, nil);
  self->n_ = n;
  self->t_ = t;
  self->g_ = new_OrgSpongycastlePqcMathLinearalgebraGF2Matrix_initWithOrgSpongycastlePqcMathLinearalgebraGF2Matrix_(g);
}

OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters *new_OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters_initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_(jint n, jint t, OrgSpongycastlePqcMathLinearalgebraGF2Matrix *g) {
  J2OBJC_NEW_IMPL(OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters, initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_, n, t, g)
}

OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters *create_OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters_initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_(jint n, jint t, OrgSpongycastlePqcMathLinearalgebraGF2Matrix *g) {
  J2OBJC_CREATE_IMPL(OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters, initWithInt_withInt_withOrgSpongycastlePqcMathLinearalgebraGF2Matrix_, n, t, g)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastlePqcCryptoMcelieceMcEliecePublicKeyParameters)
