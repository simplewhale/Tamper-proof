//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/CertConfirmContent.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/cmp/CertConfirmContent.h"
#include "org/spongycastle/asn1/cmp/CertStatus.h"

@interface OrgSpongycastleAsn1CmpCertConfirmContent () {
 @public
  OrgSpongycastleAsn1ASN1Sequence *content_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpCertConfirmContent, content_, OrgSpongycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmpCertConfirmContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmpCertConfirmContent *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmpCertConfirmContent *new_OrgSpongycastleAsn1CmpCertConfirmContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmpCertConfirmContent *create_OrgSpongycastleAsn1CmpCertConfirmContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmpCertConfirmContent

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmpCertConfirmContent_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmpCertConfirmContent *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmpCertConfirmContent_getInstanceWithId_(o);
}

- (IOSObjectArray *)toCertStatusArray {
  IOSObjectArray *result = [IOSObjectArray newArrayWithLength:[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(content_)) size] type:OrgSpongycastleAsn1CmpCertStatus_class_()];
  for (jint i = 0; i != result->size_; i++) {
    (void) IOSObjectArray_Set(result, i, OrgSpongycastleAsn1CmpCertStatus_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(content_)) getObjectAtWithInt:i]));
  }
  return result;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return content_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmpCertConfirmContent;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1CmpCertStatus;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(toCertStatusArray);
  methods[3].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "content_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmpCertConfirmContent = { "CertConfirmContent", "org.spongycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmpCertConfirmContent;
}

@end

void OrgSpongycastleAsn1CmpCertConfirmContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmpCertConfirmContent *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->content_ = seq;
}

OrgSpongycastleAsn1CmpCertConfirmContent *new_OrgSpongycastleAsn1CmpCertConfirmContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpCertConfirmContent, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmpCertConfirmContent *create_OrgSpongycastleAsn1CmpCertConfirmContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpCertConfirmContent, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmpCertConfirmContent *OrgSpongycastleAsn1CmpCertConfirmContent_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmpCertConfirmContent_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmpCertConfirmContent class]]) {
    return (OrgSpongycastleAsn1CmpCertConfirmContent *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmpCertConfirmContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmpCertConfirmContent)