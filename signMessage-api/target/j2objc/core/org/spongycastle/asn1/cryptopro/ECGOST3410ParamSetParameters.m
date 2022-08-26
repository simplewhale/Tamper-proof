//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cryptopro/ECGOST3410ParamSetParameters.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cryptopro/ECGOST3410ParamSetParameters.h"

@implementation OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters

+ (OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                                     withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithId_(obj);
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)a
                    withJavaMathBigInteger:(JavaMathBigInteger *)b
                    withJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                                   withInt:(jint)x
                    withJavaMathBigInteger:(JavaMathBigInteger *)y {
  OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_(self, a, b, p, q, x, y);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (JavaMathBigInteger *)getP {
  return [((OrgSpongycastleAsn1ASN1Integer *) nil_chk(p_)) getPositiveValue];
}

- (JavaMathBigInteger *)getQ {
  return [((OrgSpongycastleAsn1ASN1Integer *) nil_chk(q_)) getPositiveValue];
}

- (JavaMathBigInteger *)getA {
  return [((OrgSpongycastleAsn1ASN1Integer *) nil_chk(a_)) getPositiveValue];
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:a_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:b_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:p_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:q_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:x_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:y_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withInt:withJavaMathBigInteger:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getP);
  methods[5].selector = @selector(getQ);
  methods[6].selector = @selector(getA);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "q_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "a_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "b_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "x_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "y_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;ILJavaMathBigInteger;", "LOrgSpongycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters = { "ECGOST3410ParamSetParameters", "org.spongycastle.asn1.cryptopro", ptrTable, methods, fields, 7, 0x1, 8, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters;
}

@end

OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initialize();
  return OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initialize();
  if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters class]]) {
    return (OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *) cast_chk(obj, [OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters class]);
  }
  if ([obj isKindOfClass:[OrgSpongycastleAsn1ASN1Sequence class]]) {
    return new_OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithOrgSpongycastleAsn1ASN1Sequence_((OrgSpongycastleAsn1ASN1Sequence *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid GOST3410Parameter: ", [[obj java_getClass] getName]));
}

void OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_(OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *self, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *p, JavaMathBigInteger *q, jint x, JavaMathBigInteger *y) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->a_ = new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(a);
  self->b_ = new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(b);
  self->p_ = new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(p);
  self->q_ = new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(q);
  self->x_ = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(x);
  self->y_ = new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(y);
}

OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *new_OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_(JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *p, JavaMathBigInteger *q, jint x, JavaMathBigInteger *y) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_, a, b, p, q, x, y)
}

OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *create_OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_(JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *p, JavaMathBigInteger *q, jint x, JavaMathBigInteger *y) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_, a, b, p, q, x, y)
}

void OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->a_ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement], [OrgSpongycastleAsn1ASN1Integer class]);
  self->b_ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([e nextElement], [OrgSpongycastleAsn1ASN1Integer class]);
  self->p_ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([e nextElement], [OrgSpongycastleAsn1ASN1Integer class]);
  self->q_ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([e nextElement], [OrgSpongycastleAsn1ASN1Integer class]);
  self->x_ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([e nextElement], [OrgSpongycastleAsn1ASN1Integer class]);
  self->y_ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([e nextElement], [OrgSpongycastleAsn1ASN1Integer class]);
}

OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *new_OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters *create_OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CryptoproECGOST3410ParamSetParameters)
