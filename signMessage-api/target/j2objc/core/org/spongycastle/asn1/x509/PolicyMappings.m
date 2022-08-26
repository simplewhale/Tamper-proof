//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/PolicyMappings.java
//

#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/x509/CertPolicyId.h"
#include "org/spongycastle/asn1/x509/PolicyMappings.h"

@interface OrgSpongycastleAsn1X509PolicyMappings ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509PolicyMappings *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X509PolicyMappings *new_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509PolicyMappings *create_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1X509PolicyMappings

+ (OrgSpongycastleAsn1X509PolicyMappings *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509PolicyMappings_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithJavaUtilHashtable:(JavaUtilHashtable *)mappings {
  OrgSpongycastleAsn1X509PolicyMappings_initWithJavaUtilHashtable_(self, mappings);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509CertPolicyId:(OrgSpongycastleAsn1X509CertPolicyId *)issuerDomainPolicy
                    withOrgSpongycastleAsn1X509CertPolicyId:(OrgSpongycastleAsn1X509CertPolicyId *)subjectDomainPolicy {
  OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1X509CertPolicyId_withOrgSpongycastleAsn1X509CertPolicyId_(self, issuerDomainPolicy, subjectDomainPolicy);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509CertPolicyIdArray:(IOSObjectArray *)issuerDomainPolicy
                    withOrgSpongycastleAsn1X509CertPolicyIdArray:(IOSObjectArray *)subjectDomainPolicy {
  OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1X509CertPolicyIdArray_withOrgSpongycastleAsn1X509CertPolicyIdArray_(self, issuerDomainPolicy, subjectDomainPolicy);
  return self;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return seq_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1X509PolicyMappings;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithJavaUtilHashtable:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1X509CertPolicyId:withOrgSpongycastleAsn1X509CertPolicyId:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1X509CertPolicyIdArray:withOrgSpongycastleAsn1X509CertPolicyIdArray:);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seq_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LJavaUtilHashtable;", "LOrgSpongycastleAsn1X509CertPolicyId;LOrgSpongycastleAsn1X509CertPolicyId;", "[LOrgSpongycastleAsn1X509CertPolicyId;[LOrgSpongycastleAsn1X509CertPolicyId;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509PolicyMappings = { "PolicyMappings", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509PolicyMappings;
}

@end

OrgSpongycastleAsn1X509PolicyMappings *OrgSpongycastleAsn1X509PolicyMappings_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509PolicyMappings_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1X509PolicyMappings class]]) {
    return (OrgSpongycastleAsn1X509PolicyMappings *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509PolicyMappings *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  self->seq_ = seq;
}

OrgSpongycastleAsn1X509PolicyMappings *new_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509PolicyMappings, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509PolicyMappings *create_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509PolicyMappings, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1X509PolicyMappings_initWithJavaUtilHashtable_(OrgSpongycastleAsn1X509PolicyMappings *self, JavaUtilHashtable *mappings) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  OrgSpongycastleAsn1ASN1EncodableVector *dev = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  id<JavaUtilEnumeration> it = [((JavaUtilHashtable *) nil_chk(mappings)) keys];
  while ([((id<JavaUtilEnumeration>) nil_chk(it)) hasMoreElements]) {
    NSString *idp = (NSString *) cast_chk([it nextElement], [NSString class]);
    NSString *sdp = (NSString *) cast_chk([mappings getWithId:idp], [NSString class]);
    OrgSpongycastleAsn1ASN1EncodableVector *dv = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
    [dv addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(idp)];
    [dv addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_(sdp)];
    [dev addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(dv)];
  }
  self->seq_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(dev);
}

OrgSpongycastleAsn1X509PolicyMappings *new_OrgSpongycastleAsn1X509PolicyMappings_initWithJavaUtilHashtable_(JavaUtilHashtable *mappings) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509PolicyMappings, initWithJavaUtilHashtable_, mappings)
}

OrgSpongycastleAsn1X509PolicyMappings *create_OrgSpongycastleAsn1X509PolicyMappings_initWithJavaUtilHashtable_(JavaUtilHashtable *mappings) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509PolicyMappings, initWithJavaUtilHashtable_, mappings)
}

void OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1X509CertPolicyId_withOrgSpongycastleAsn1X509CertPolicyId_(OrgSpongycastleAsn1X509PolicyMappings *self, OrgSpongycastleAsn1X509CertPolicyId *issuerDomainPolicy, OrgSpongycastleAsn1X509CertPolicyId *subjectDomainPolicy) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  OrgSpongycastleAsn1ASN1EncodableVector *dv = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [dv addWithOrgSpongycastleAsn1ASN1Encodable:issuerDomainPolicy];
  [dv addWithOrgSpongycastleAsn1ASN1Encodable:subjectDomainPolicy];
  self->seq_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(dv));
}

OrgSpongycastleAsn1X509PolicyMappings *new_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1X509CertPolicyId_withOrgSpongycastleAsn1X509CertPolicyId_(OrgSpongycastleAsn1X509CertPolicyId *issuerDomainPolicy, OrgSpongycastleAsn1X509CertPolicyId *subjectDomainPolicy) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509PolicyMappings, initWithOrgSpongycastleAsn1X509CertPolicyId_withOrgSpongycastleAsn1X509CertPolicyId_, issuerDomainPolicy, subjectDomainPolicy)
}

OrgSpongycastleAsn1X509PolicyMappings *create_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1X509CertPolicyId_withOrgSpongycastleAsn1X509CertPolicyId_(OrgSpongycastleAsn1X509CertPolicyId *issuerDomainPolicy, OrgSpongycastleAsn1X509CertPolicyId *subjectDomainPolicy) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509PolicyMappings, initWithOrgSpongycastleAsn1X509CertPolicyId_withOrgSpongycastleAsn1X509CertPolicyId_, issuerDomainPolicy, subjectDomainPolicy)
}

void OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1X509CertPolicyIdArray_withOrgSpongycastleAsn1X509CertPolicyIdArray_(OrgSpongycastleAsn1X509PolicyMappings *self, IOSObjectArray *issuerDomainPolicy, IOSObjectArray *subjectDomainPolicy) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->seq_ = nil;
  OrgSpongycastleAsn1ASN1EncodableVector *dev = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(issuerDomainPolicy))->size_; i++) {
    OrgSpongycastleAsn1ASN1EncodableVector *dv = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
    [dv addWithOrgSpongycastleAsn1ASN1Encodable:IOSObjectArray_Get(issuerDomainPolicy, i)];
    [dv addWithOrgSpongycastleAsn1ASN1Encodable:IOSObjectArray_Get(nil_chk(subjectDomainPolicy), i)];
    [dev addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(dv)];
  }
  self->seq_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(dev);
}

OrgSpongycastleAsn1X509PolicyMappings *new_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1X509CertPolicyIdArray_withOrgSpongycastleAsn1X509CertPolicyIdArray_(IOSObjectArray *issuerDomainPolicy, IOSObjectArray *subjectDomainPolicy) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509PolicyMappings, initWithOrgSpongycastleAsn1X509CertPolicyIdArray_withOrgSpongycastleAsn1X509CertPolicyIdArray_, issuerDomainPolicy, subjectDomainPolicy)
}

OrgSpongycastleAsn1X509PolicyMappings *create_OrgSpongycastleAsn1X509PolicyMappings_initWithOrgSpongycastleAsn1X509CertPolicyIdArray_withOrgSpongycastleAsn1X509CertPolicyIdArray_(IOSObjectArray *issuerDomainPolicy, IOSObjectArray *subjectDomainPolicy) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509PolicyMappings, initWithOrgSpongycastleAsn1X509CertPolicyIdArray_withOrgSpongycastleAsn1X509CertPolicyIdArray_, issuerDomainPolicy, subjectDomainPolicy)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509PolicyMappings)
