//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/PopLinkWitnessV2.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cmc/PopLinkWitnessV2.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleAsn1CmcPopLinkWitnessV2 () {
 @public
  OrgSpongycastleAsn1X509AlgorithmIdentifier *keyGenAlgorithm_;
  OrgSpongycastleAsn1X509AlgorithmIdentifier *macAlgorithm_;
  IOSByteArray *witness_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcPopLinkWitnessV2, keyGenAlgorithm_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcPopLinkWitnessV2, macAlgorithm_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcPopLinkWitnessV2, witness_, IOSByteArray *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcPopLinkWitnessV2 *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmcPopLinkWitnessV2 *new_OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmcPopLinkWitnessV2 *create_OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmcPopLinkWitnessV2

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)keyGenAlgorithm
                    withOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)macAlgorithm
                                                     withByteArray:(IOSByteArray *)witness {
  OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(self, keyGenAlgorithm, macAlgorithm, witness);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmcPopLinkWitnessV2 *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmcPopLinkWitnessV2_getInstanceWithId_(o);
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getKeyGenAlgorithm {
  return keyGenAlgorithm_;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getMacAlgorithm {
  return macAlgorithm_;
}

- (IOSByteArray *)getWitness {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(witness_);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:keyGenAlgorithm_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:macAlgorithm_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_([self getWitness])];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcPopLinkWitnessV2;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1X509AlgorithmIdentifier:withByteArray:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getKeyGenAlgorithm);
  methods[4].selector = @selector(getMacAlgorithm);
  methods[5].selector = @selector(getWitness);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "keyGenAlgorithm_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "macAlgorithm_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "witness_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1X509AlgorithmIdentifier;[B", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmcPopLinkWitnessV2 = { "PopLinkWitnessV2", "org.spongycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmcPopLinkWitnessV2;
}

@end

void OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1CmcPopLinkWitnessV2 *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyGenAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *macAlgorithm, IOSByteArray *witness) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->keyGenAlgorithm_ = keyGenAlgorithm;
  self->macAlgorithm_ = macAlgorithm;
  self->witness_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(witness);
}

OrgSpongycastleAsn1CmcPopLinkWitnessV2 *new_OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *keyGenAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *macAlgorithm, IOSByteArray *witness) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcPopLinkWitnessV2, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_, keyGenAlgorithm, macAlgorithm, witness)
}

OrgSpongycastleAsn1CmcPopLinkWitnessV2 *create_OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *keyGenAlgorithm, OrgSpongycastleAsn1X509AlgorithmIdentifier *macAlgorithm, IOSByteArray *witness) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcPopLinkWitnessV2, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_, keyGenAlgorithm, macAlgorithm, witness)
}

void OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcPopLinkWitnessV2 *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->keyGenAlgorithm_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->macAlgorithm_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->witness_ = OrgSpongycastleUtilArrays_cloneWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:2]))) getOctets]);
}

OrgSpongycastleAsn1CmcPopLinkWitnessV2 *new_OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcPopLinkWitnessV2, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcPopLinkWitnessV2 *create_OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcPopLinkWitnessV2, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcPopLinkWitnessV2 *OrgSpongycastleAsn1CmcPopLinkWitnessV2_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmcPopLinkWitnessV2_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmcPopLinkWitnessV2 class]]) {
    return (OrgSpongycastleAsn1CmcPopLinkWitnessV2 *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmcPopLinkWitnessV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmcPopLinkWitnessV2)
