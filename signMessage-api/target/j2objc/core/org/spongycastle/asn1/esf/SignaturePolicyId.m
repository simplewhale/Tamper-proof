//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/esf/SignaturePolicyId.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/esf/OtherHashAlgAndValue.h"
#include "org/spongycastle/asn1/esf/SigPolicyQualifiers.h"
#include "org/spongycastle/asn1/esf/SignaturePolicyId.h"

@interface OrgSpongycastleAsn1EsfSignaturePolicyId () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *sigPolicyId_;
  OrgSpongycastleAsn1EsfOtherHashAlgAndValue *sigPolicyHash_;
  OrgSpongycastleAsn1EsfSigPolicyQualifiers *sigPolicyQualifiers_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1EsfSignaturePolicyId, sigPolicyId_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1EsfSignaturePolicyId, sigPolicyHash_, OrgSpongycastleAsn1EsfOtherHashAlgAndValue *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1EsfSignaturePolicyId, sigPolicyQualifiers_, OrgSpongycastleAsn1EsfSigPolicyQualifiers *)

__attribute__((unused)) static void OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1EsfSignaturePolicyId *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1EsfSignaturePolicyId *new_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1EsfSignaturePolicyId *create_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1EsfSignaturePolicyId

+ (OrgSpongycastleAsn1EsfSignaturePolicyId *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1EsfSignaturePolicyId_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)sigPolicyIdentifier
                 withOrgSpongycastleAsn1EsfOtherHashAlgAndValue:(OrgSpongycastleAsn1EsfOtherHashAlgAndValue *)sigPolicyHash {
  OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_(self, sigPolicyIdentifier, sigPolicyHash);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)sigPolicyId
                 withOrgSpongycastleAsn1EsfOtherHashAlgAndValue:(OrgSpongycastleAsn1EsfOtherHashAlgAndValue *)sigPolicyHash
                  withOrgSpongycastleAsn1EsfSigPolicyQualifiers:(OrgSpongycastleAsn1EsfSigPolicyQualifiers *)sigPolicyQualifiers {
  OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_withOrgSpongycastleAsn1EsfSigPolicyQualifiers_(self, sigPolicyId, sigPolicyHash, sigPolicyQualifiers);
  return self;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getSigPolicyId {
  return new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_([((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(sigPolicyId_)) getId]);
}

- (OrgSpongycastleAsn1EsfOtherHashAlgAndValue *)getSigPolicyHash {
  return sigPolicyHash_;
}

- (OrgSpongycastleAsn1EsfSigPolicyQualifiers *)getSigPolicyQualifiers {
  return sigPolicyQualifiers_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:sigPolicyId_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:sigPolicyHash_];
  if (sigPolicyQualifiers_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:sigPolicyQualifiers_];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1EsfSignaturePolicyId;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1EsfOtherHashAlgAndValue;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1EsfSigPolicyQualifiers;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1EsfOtherHashAlgAndValue:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1EsfOtherHashAlgAndValue:withOrgSpongycastleAsn1EsfSigPolicyQualifiers:);
  methods[4].selector = @selector(getSigPolicyId);
  methods[5].selector = @selector(getSigPolicyHash);
  methods[6].selector = @selector(getSigPolicyQualifiers);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "sigPolicyId_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sigPolicyHash_", "LOrgSpongycastleAsn1EsfOtherHashAlgAndValue;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sigPolicyQualifiers_", "LOrgSpongycastleAsn1EsfSigPolicyQualifiers;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1EsfOtherHashAlgAndValue;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1EsfOtherHashAlgAndValue;LOrgSpongycastleAsn1EsfSigPolicyQualifiers;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1EsfSignaturePolicyId = { "SignaturePolicyId", "org.spongycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1EsfSignaturePolicyId;
}

@end

OrgSpongycastleAsn1EsfSignaturePolicyId *OrgSpongycastleAsn1EsfSignaturePolicyId_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1EsfSignaturePolicyId_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1EsfSignaturePolicyId class]]) {
    return (OrgSpongycastleAsn1EsfSignaturePolicyId *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1EsfSignaturePolicyId *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2 && [seq size] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->sigPolicyId_ = OrgSpongycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->sigPolicyHash_ = OrgSpongycastleAsn1EsfOtherHashAlgAndValue_getInstanceWithId_([seq getObjectAtWithInt:1]);
  if ([seq size] == 3) {
    self->sigPolicyQualifiers_ = OrgSpongycastleAsn1EsfSigPolicyQualifiers_getInstanceWithId_([seq getObjectAtWithInt:2]);
  }
}

OrgSpongycastleAsn1EsfSignaturePolicyId *new_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EsfSignaturePolicyId, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1EsfSignaturePolicyId *create_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EsfSignaturePolicyId, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_(OrgSpongycastleAsn1EsfSignaturePolicyId *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *sigPolicyIdentifier, OrgSpongycastleAsn1EsfOtherHashAlgAndValue *sigPolicyHash) {
  OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_withOrgSpongycastleAsn1EsfSigPolicyQualifiers_(self, sigPolicyIdentifier, sigPolicyHash, nil);
}

OrgSpongycastleAsn1EsfSignaturePolicyId *new_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sigPolicyIdentifier, OrgSpongycastleAsn1EsfOtherHashAlgAndValue *sigPolicyHash) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EsfSignaturePolicyId, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_, sigPolicyIdentifier, sigPolicyHash)
}

OrgSpongycastleAsn1EsfSignaturePolicyId *create_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sigPolicyIdentifier, OrgSpongycastleAsn1EsfOtherHashAlgAndValue *sigPolicyHash) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EsfSignaturePolicyId, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_, sigPolicyIdentifier, sigPolicyHash)
}

void OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_withOrgSpongycastleAsn1EsfSigPolicyQualifiers_(OrgSpongycastleAsn1EsfSignaturePolicyId *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *sigPolicyId, OrgSpongycastleAsn1EsfOtherHashAlgAndValue *sigPolicyHash, OrgSpongycastleAsn1EsfSigPolicyQualifiers *sigPolicyQualifiers) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->sigPolicyId_ = sigPolicyId;
  self->sigPolicyHash_ = sigPolicyHash;
  self->sigPolicyQualifiers_ = sigPolicyQualifiers;
}

OrgSpongycastleAsn1EsfSignaturePolicyId *new_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_withOrgSpongycastleAsn1EsfSigPolicyQualifiers_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sigPolicyId, OrgSpongycastleAsn1EsfOtherHashAlgAndValue *sigPolicyHash, OrgSpongycastleAsn1EsfSigPolicyQualifiers *sigPolicyQualifiers) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EsfSignaturePolicyId, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_withOrgSpongycastleAsn1EsfSigPolicyQualifiers_, sigPolicyId, sigPolicyHash, sigPolicyQualifiers)
}

OrgSpongycastleAsn1EsfSignaturePolicyId *create_OrgSpongycastleAsn1EsfSignaturePolicyId_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_withOrgSpongycastleAsn1EsfSigPolicyQualifiers_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sigPolicyId, OrgSpongycastleAsn1EsfOtherHashAlgAndValue *sigPolicyHash, OrgSpongycastleAsn1EsfSigPolicyQualifiers *sigPolicyQualifiers) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EsfSignaturePolicyId, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1EsfOtherHashAlgAndValue_withOrgSpongycastleAsn1EsfSigPolicyQualifiers_, sigPolicyId, sigPolicyHash, sigPolicyQualifiers)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1EsfSignaturePolicyId)