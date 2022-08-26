//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/PKIMessages.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cmp/PKIMessage.h"
#include "org/spongycastle/asn1/cmp/PKIMessages.h"

@interface OrgSpongycastleAsn1CmpPKIMessages () {
 @public
  OrgSpongycastleAsn1ASN1Sequence *content_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpPKIMessages, content_, OrgSpongycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmpPKIMessages *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmpPKIMessages *new_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmpPKIMessages *create_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmpPKIMessages

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmpPKIMessages *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmpPKIMessages_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1CmpPKIMessage:(OrgSpongycastleAsn1CmpPKIMessage *)msg {
  OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1CmpPKIMessage_(self, msg);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1CmpPKIMessageArray:(IOSObjectArray *)msgs {
  OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1CmpPKIMessageArray_(self, msgs);
  return self;
}

- (IOSObjectArray *)toPKIMessageArray {
  IOSObjectArray *result = [IOSObjectArray newArrayWithLength:[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(content_)) size] type:OrgSpongycastleAsn1CmpPKIMessage_class_()];
  for (jint i = 0; i != result->size_; i++) {
    (void) IOSObjectArray_Set(result, i, OrgSpongycastleAsn1CmpPKIMessage_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(content_)) getObjectAtWithInt:i]));
  }
  return result;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return content_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmpPKIMessages;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1CmpPKIMessage;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1CmpPKIMessage:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1CmpPKIMessageArray:);
  methods[4].selector = @selector(toPKIMessageArray);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "content_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1CmpPKIMessage;", "[LOrgSpongycastleAsn1CmpPKIMessage;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmpPKIMessages = { "PKIMessages", "org.spongycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 6, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmpPKIMessages;
}

@end

void OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmpPKIMessages *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->content_ = seq;
}

OrgSpongycastleAsn1CmpPKIMessages *new_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpPKIMessages, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmpPKIMessages *create_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpPKIMessages, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmpPKIMessages *OrgSpongycastleAsn1CmpPKIMessages_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmpPKIMessages_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmpPKIMessages class]]) {
    return (OrgSpongycastleAsn1CmpPKIMessages *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1CmpPKIMessage_(OrgSpongycastleAsn1CmpPKIMessages *self, OrgSpongycastleAsn1CmpPKIMessage *msg) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->content_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(msg);
}

OrgSpongycastleAsn1CmpPKIMessages *new_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1CmpPKIMessage_(OrgSpongycastleAsn1CmpPKIMessage *msg) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpPKIMessages, initWithOrgSpongycastleAsn1CmpPKIMessage_, msg)
}

OrgSpongycastleAsn1CmpPKIMessages *create_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1CmpPKIMessage_(OrgSpongycastleAsn1CmpPKIMessage *msg) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpPKIMessages, initWithOrgSpongycastleAsn1CmpPKIMessage_, msg)
}

void OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1CmpPKIMessageArray_(OrgSpongycastleAsn1CmpPKIMessages *self, IOSObjectArray *msgs) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i < ((IOSObjectArray *) nil_chk(msgs))->size_; i++) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:IOSObjectArray_Get(msgs, i)];
  }
  self->content_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

OrgSpongycastleAsn1CmpPKIMessages *new_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1CmpPKIMessageArray_(IOSObjectArray *msgs) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpPKIMessages, initWithOrgSpongycastleAsn1CmpPKIMessageArray_, msgs)
}

OrgSpongycastleAsn1CmpPKIMessages *create_OrgSpongycastleAsn1CmpPKIMessages_initWithOrgSpongycastleAsn1CmpPKIMessageArray_(IOSObjectArray *msgs) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpPKIMessages, initWithOrgSpongycastleAsn1CmpPKIMessageArray_, msgs)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmpPKIMessages)
