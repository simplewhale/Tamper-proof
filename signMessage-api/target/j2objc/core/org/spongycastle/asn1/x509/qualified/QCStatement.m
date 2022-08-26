//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/qualified/QCStatement.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/util/Enumeration.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/x509/qualified/QCStatement.h"

@interface OrgSpongycastleAsn1X509QualifiedQCStatement ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509QualifiedQCStatement *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X509QualifiedQCStatement *new_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509QualifiedQCStatement *create_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1X509QualifiedQCStatement

+ (OrgSpongycastleAsn1X509QualifiedQCStatement *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509QualifiedQCStatement_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)qcStatementId {
  OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(self, qcStatementId);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)qcStatementId
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)qcStatementInfo {
  OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(self, qcStatementId, qcStatementInfo);
  return self;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getStatementId {
  return qcStatementId_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getStatementInfo {
  return qcStatementInfo_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *seq = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [seq addWithOrgSpongycastleAsn1ASN1Encodable:qcStatementId_];
  if (qcStatementInfo_ != nil) {
    [seq addWithOrgSpongycastleAsn1ASN1Encodable:qcStatementInfo_];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(seq);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1X509QualifiedQCStatement;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Encodable:);
  methods[4].selector = @selector(getStatementId);
  methods[5].selector = @selector(getStatementInfo);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "qcStatementId_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "qcStatementInfo_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509QualifiedQCStatement = { "QCStatement", "org.spongycastle.asn1.x509.qualified", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509QualifiedQCStatement;
}

@end

OrgSpongycastleAsn1X509QualifiedQCStatement *OrgSpongycastleAsn1X509QualifiedQCStatement_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509QualifiedQCStatement_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1X509QualifiedQCStatement class]]) {
    return (OrgSpongycastleAsn1X509QualifiedQCStatement *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509QualifiedQCStatement *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->qcStatementId_ = OrgSpongycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement]);
  if ([e hasMoreElements]) {
    self->qcStatementInfo_ = (id<OrgSpongycastleAsn1ASN1Encodable>) cast_check([e nextElement], OrgSpongycastleAsn1ASN1Encodable_class_());
  }
}

OrgSpongycastleAsn1X509QualifiedQCStatement *new_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509QualifiedQCStatement, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509QualifiedQCStatement *create_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509QualifiedQCStatement, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1X509QualifiedQCStatement *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *qcStatementId) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->qcStatementId_ = qcStatementId;
  self->qcStatementInfo_ = nil;
}

OrgSpongycastleAsn1X509QualifiedQCStatement *new_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *qcStatementId) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509QualifiedQCStatement, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_, qcStatementId)
}

OrgSpongycastleAsn1X509QualifiedQCStatement *create_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(OrgSpongycastleAsn1ASN1ObjectIdentifier *qcStatementId) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509QualifiedQCStatement, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_, qcStatementId)
}

void OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1X509QualifiedQCStatement *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *qcStatementId, id<OrgSpongycastleAsn1ASN1Encodable> qcStatementInfo) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->qcStatementId_ = qcStatementId;
  self->qcStatementInfo_ = qcStatementInfo;
}

OrgSpongycastleAsn1X509QualifiedQCStatement *new_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *qcStatementId, id<OrgSpongycastleAsn1ASN1Encodable> qcStatementInfo) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509QualifiedQCStatement, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, qcStatementId, qcStatementInfo)
}

OrgSpongycastleAsn1X509QualifiedQCStatement *create_OrgSpongycastleAsn1X509QualifiedQCStatement_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *qcStatementId, id<OrgSpongycastleAsn1ASN1Encodable> qcStatementInfo) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509QualifiedQCStatement, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, qcStatementId, qcStatementInfo)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509QualifiedQCStatement)
