//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x9/KeySpecificInfo.java
//

#include "J2ObjC_source.h"
#include "java/util/Enumeration.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/x9/KeySpecificInfo.h"

@interface OrgSpongycastleAsn1X9KeySpecificInfo () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *algorithm_;
  OrgSpongycastleAsn1ASN1OctetString *counter_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X9KeySpecificInfo, algorithm_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X9KeySpecificInfo, counter_, OrgSpongycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X9KeySpecificInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X9KeySpecificInfo *new_OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X9KeySpecificInfo *create_OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1X9KeySpecificInfo

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)algorithm
                         withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)counter {
  OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(self, algorithm, counter);
  return self;
}

+ (OrgSpongycastleAsn1X9KeySpecificInfo *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X9KeySpecificInfo_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getAlgorithm {
  return algorithm_;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getCounter {
  return counter_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:algorithm_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:counter_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X9KeySpecificInfo;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1OctetString:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getAlgorithm);
  methods[4].selector = @selector(getCounter);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "algorithm_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "counter_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1OctetString;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X9KeySpecificInfo = { "KeySpecificInfo", "org.spongycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X9KeySpecificInfo;
}

@end

void OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1X9KeySpecificInfo *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *algorithm, OrgSpongycastleAsn1ASN1OctetString *counter) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->algorithm_ = algorithm;
  self->counter_ = counter;
}

OrgSpongycastleAsn1X9KeySpecificInfo *new_OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1ObjectIdentifier *algorithm, OrgSpongycastleAsn1ASN1OctetString *counter) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X9KeySpecificInfo, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1OctetString_, algorithm, counter)
}

OrgSpongycastleAsn1X9KeySpecificInfo *create_OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1ASN1ObjectIdentifier *algorithm, OrgSpongycastleAsn1ASN1OctetString *counter) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X9KeySpecificInfo, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1OctetString_, algorithm, counter)
}

OrgSpongycastleAsn1X9KeySpecificInfo *OrgSpongycastleAsn1X9KeySpecificInfo_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X9KeySpecificInfo_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1X9KeySpecificInfo class]]) {
    return (OrgSpongycastleAsn1X9KeySpecificInfo *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X9KeySpecificInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->algorithm_ = (OrgSpongycastleAsn1ASN1ObjectIdentifier *) cast_chk([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement], [OrgSpongycastleAsn1ASN1ObjectIdentifier class]);
  self->counter_ = (OrgSpongycastleAsn1ASN1OctetString *) cast_chk([e nextElement], [OrgSpongycastleAsn1ASN1OctetString class]);
}

OrgSpongycastleAsn1X9KeySpecificInfo *new_OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X9KeySpecificInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X9KeySpecificInfo *create_OrgSpongycastleAsn1X9KeySpecificInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X9KeySpecificInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X9KeySpecificInfo)
