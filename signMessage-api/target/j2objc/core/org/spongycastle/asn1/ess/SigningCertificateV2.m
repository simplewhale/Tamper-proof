//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ess/SigningCertificateV2.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/ess/ESSCertIDv2.h"
#include "org/spongycastle/asn1/ess/SigningCertificateV2.h"
#include "org/spongycastle/asn1/x509/PolicyInformation.h"

@interface OrgSpongycastleAsn1EssSigningCertificateV2 ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1EssSigningCertificateV2 *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1EssSigningCertificateV2 *new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1EssSigningCertificateV2 *create_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1EssSigningCertificateV2

+ (OrgSpongycastleAsn1EssSigningCertificateV2 *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1EssSigningCertificateV2_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1EssESSCertIDv2:(OrgSpongycastleAsn1EssESSCertIDv2 *)cert {
  OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2_(self, cert);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1EssESSCertIDv2Array:(IOSObjectArray *)certs {
  OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_(self, certs);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1EssESSCertIDv2Array:(IOSObjectArray *)certs
             withOrgSpongycastleAsn1X509PolicyInformationArray:(IOSObjectArray *)policies {
  OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_(self, certs, policies);
  return self;
}

- (IOSObjectArray *)getCerts {
  IOSObjectArray *certIds = [IOSObjectArray newArrayWithLength:[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(certs_)) size] type:OrgSpongycastleAsn1EssESSCertIDv2_class_()];
  for (jint i = 0; i != [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(certs_)) size]; i++) {
    (void) IOSObjectArray_Set(certIds, i, OrgSpongycastleAsn1EssESSCertIDv2_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(certs_)) getObjectAtWithInt:i]));
  }
  return certIds;
}

- (IOSObjectArray *)getPolicies {
  if (policies_ == nil) {
    return nil;
  }
  IOSObjectArray *policyInformations = [IOSObjectArray newArrayWithLength:[policies_ size] type:OrgSpongycastleAsn1X509PolicyInformation_class_()];
  for (jint i = 0; i != [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(policies_)) size]; i++) {
    (void) IOSObjectArray_Set(policyInformations, i, OrgSpongycastleAsn1X509PolicyInformation_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(policies_)) getObjectAtWithInt:i]));
  }
  return policyInformations;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:certs_];
  if (policies_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:policies_];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1EssSigningCertificateV2;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1EssESSCertIDv2;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1X509PolicyInformation;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1EssESSCertIDv2:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1EssESSCertIDv2Array:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1EssESSCertIDv2Array:withOrgSpongycastleAsn1X509PolicyInformationArray:);
  methods[5].selector = @selector(getCerts);
  methods[6].selector = @selector(getPolicies);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certs_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "policies_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1EssESSCertIDv2;", "[LOrgSpongycastleAsn1EssESSCertIDv2;", "[LOrgSpongycastleAsn1EssESSCertIDv2;[LOrgSpongycastleAsn1X509PolicyInformation;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1EssSigningCertificateV2 = { "SigningCertificateV2", "org.spongycastle.asn1.ess", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1EssSigningCertificateV2;
}

@end

OrgSpongycastleAsn1EssSigningCertificateV2 *OrgSpongycastleAsn1EssSigningCertificateV2_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1EssSigningCertificateV2_initialize();
  if (o == nil || [o isKindOfClass:[OrgSpongycastleAsn1EssSigningCertificateV2 class]]) {
    return (OrgSpongycastleAsn1EssSigningCertificateV2 *) cast_chk(o, [OrgSpongycastleAsn1EssSigningCertificateV2 class]);
  }
  else if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1Sequence class]]) {
    return new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1ASN1Sequence_((OrgSpongycastleAsn1ASN1Sequence *) o);
  }
  return nil;
}

void OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1EssSigningCertificateV2 *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 1 || [seq size] > 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->certs_ = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:0]);
  if ([seq size] > 1) {
    self->policies_ = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:1]);
  }
}

OrgSpongycastleAsn1EssSigningCertificateV2 *new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EssSigningCertificateV2, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1EssSigningCertificateV2 *create_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EssSigningCertificateV2, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2_(OrgSpongycastleAsn1EssSigningCertificateV2 *self, OrgSpongycastleAsn1EssESSCertIDv2 *cert) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->certs_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(cert);
}

OrgSpongycastleAsn1EssSigningCertificateV2 *new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2_(OrgSpongycastleAsn1EssESSCertIDv2 *cert) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EssSigningCertificateV2, initWithOrgSpongycastleAsn1EssESSCertIDv2_, cert)
}

OrgSpongycastleAsn1EssSigningCertificateV2 *create_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2_(OrgSpongycastleAsn1EssESSCertIDv2 *cert) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EssSigningCertificateV2, initWithOrgSpongycastleAsn1EssESSCertIDv2_, cert)
}

void OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_(OrgSpongycastleAsn1EssSigningCertificateV2 *self, IOSObjectArray *certs) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(certs))->size_; i++) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:IOSObjectArray_Get(certs, i)];
  }
  self->certs_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

OrgSpongycastleAsn1EssSigningCertificateV2 *new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_(IOSObjectArray *certs) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EssSigningCertificateV2, initWithOrgSpongycastleAsn1EssESSCertIDv2Array_, certs)
}

OrgSpongycastleAsn1EssSigningCertificateV2 *create_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_(IOSObjectArray *certs) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EssSigningCertificateV2, initWithOrgSpongycastleAsn1EssESSCertIDv2Array_, certs)
}

void OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_(OrgSpongycastleAsn1EssSigningCertificateV2 *self, IOSObjectArray *certs, IOSObjectArray *policies) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(certs))->size_; i++) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:IOSObjectArray_Get(certs, i)];
  }
  self->certs_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
  if (policies != nil) {
    v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
    for (jint i = 0; i < policies->size_; i++) {
      [v addWithOrgSpongycastleAsn1ASN1Encodable:IOSObjectArray_Get(policies, i)];
    }
    self->policies_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
  }
}

OrgSpongycastleAsn1EssSigningCertificateV2 *new_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_(IOSObjectArray *certs, IOSObjectArray *policies) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1EssSigningCertificateV2, initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_, certs, policies)
}

OrgSpongycastleAsn1EssSigningCertificateV2 *create_OrgSpongycastleAsn1EssSigningCertificateV2_initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_(IOSObjectArray *certs, IOSObjectArray *policies) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1EssSigningCertificateV2, initWithOrgSpongycastleAsn1EssESSCertIDv2Array_withOrgSpongycastleAsn1X509PolicyInformationArray_, certs, policies)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1EssSigningCertificateV2)