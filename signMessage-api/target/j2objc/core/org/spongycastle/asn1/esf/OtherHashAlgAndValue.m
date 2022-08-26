//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/esf/OtherHashAlgAndValue.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/esf/OtherHashAlgAndValue.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"

@interface OrgSpongycastleAsn1EsfOtherHashAlgAndValue () {
 @public
  OrgSpongycastleAsn1X509AlgorithmIdentifier *hashAlgorithm_;
  OrgSpongycastleAsn1ASN1OctetString *hashValue_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1EsfOtherHashAlgAndValue, hashAlgorithm_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1EsfOtherHashAlgAndValue, hashValue_, OrgSpongycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1EsfOtherHashAlgAndValue *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1EsfOtherHashAlgAndValue *new_OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1EsfOtherHashAlgAndValue *create_OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1EsfOtherHashAlgAndValue

+ (OrgSpongycastleAsn1EsfOtherHashAlgAndValue *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1EsfOtherHashAlgAndValue_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)hashAlgorithm
                            withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)hashValue {
  OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(self, hashAlgorithm, hashValue);
  return self;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getHashAlgorithm {
  return hashAlgorithm_;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getHashValue {
  return hashValue_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:hashAlgorithm_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:hashValue_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1EsfOtherHashAlgAndValue;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1ASN1OctetString:);
  methods[3].selector = @selector(getHashAlgorithm);
  methods[4].selector = @selector(getHashValue);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "hashAlgorithm_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashValue_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1ASN1OctetString;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1EsfOtherHashAlgAndValue = { "OtherHashAlgAndValue", "org.spongycastle.asn1.esf", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1EsfOtherHashAlgAndValue;
}

@end

OrgSpongycastleAsn1EsfOtherHashAlgAndValue *OrgSpongycastleAsn1EsfOtherHashAlgAndValue_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1EsfOtherHashAlgAndValue class]]) {
    return (OrgSpongycastleAsn1EsfOtherHashAlgAndValue *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1EsfOtherHashAlgAndValue *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->hashAlgorithm_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->hashValue_ = OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

OrgSpongycastleAsn1EsfOtherHashAlgAndValue *new_OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EsfOtherHashAlgAndValue, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1EsfOtherHashAlgAndValue *create_OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EsfOtherHashAlgAndValue, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1EsfOtherHashAlgAndValue *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, OrgSpongycastleAsn1ASN1OctetString *hashValue) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->hashAlgorithm_ = hashAlgorithm;
  self->hashValue_ = hashValue;
}

OrgSpongycastleAsn1EsfOtherHashAlgAndValue *new_OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, OrgSpongycastleAsn1ASN1OctetString *hashValue) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EsfOtherHashAlgAndValue, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_, hashAlgorithm, hashValue)
}

OrgSpongycastleAsn1EsfOtherHashAlgAndValue *create_OrgSpongycastleAsn1EsfOtherHashAlgAndValue_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, OrgSpongycastleAsn1ASN1OctetString *hashValue) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EsfOtherHashAlgAndValue, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_, hashAlgorithm, hashValue)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1EsfOtherHashAlgAndValue)