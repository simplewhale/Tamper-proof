//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/OtherRecipientInfo.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cms/OtherRecipientInfo.h"

@interface OrgSpongycastleAsn1CmsOtherRecipientInfo () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *oriType_;
  id<OrgSpongycastleAsn1ASN1Encodable> oriValue_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsOtherRecipientInfo, oriType_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsOtherRecipientInfo, oriValue_, id<OrgSpongycastleAsn1ASN1Encodable>)

@implementation OrgSpongycastleAsn1CmsOtherRecipientInfo

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oriType
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)oriValue {
  OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(self, oriType, oriValue);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmsOtherRecipientInfo *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                     withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CmsOtherRecipientInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1CmsOtherRecipientInfo *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CmsOtherRecipientInfo_getInstanceWithId_(obj);
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getType {
  return oriType_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getValue {
  return oriValue_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:oriType_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:oriValue_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsOtherRecipientInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsOtherRecipientInfo;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Encodable:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getType);
  methods[5].selector = @selector(getValue);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "oriType_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "oriValue_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Encodable;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsOtherRecipientInfo = { "OtherRecipientInfo", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsOtherRecipientInfo;
}

@end

void OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CmsOtherRecipientInfo *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *oriType, id<OrgSpongycastleAsn1ASN1Encodable> oriValue) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->oriType_ = oriType;
  self->oriValue_ = oriValue;
}

OrgSpongycastleAsn1CmsOtherRecipientInfo *new_OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oriType, id<OrgSpongycastleAsn1ASN1Encodable> oriValue) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOtherRecipientInfo, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, oriType, oriValue)
}

OrgSpongycastleAsn1CmsOtherRecipientInfo *create_OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oriType, id<OrgSpongycastleAsn1ASN1Encodable> oriValue) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOtherRecipientInfo, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, oriType, oriValue)
}

void OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsOtherRecipientInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->oriType_ = OrgSpongycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
  self->oriValue_ = [seq getObjectAtWithInt:1];
}

OrgSpongycastleAsn1CmsOtherRecipientInfo *new_OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOtherRecipientInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsOtherRecipientInfo *create_OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOtherRecipientInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsOtherRecipientInfo *OrgSpongycastleAsn1CmsOtherRecipientInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1CmsOtherRecipientInfo_initialize();
  return OrgSpongycastleAsn1CmsOtherRecipientInfo_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1CmsOtherRecipientInfo *OrgSpongycastleAsn1CmsOtherRecipientInfo_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CmsOtherRecipientInfo_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1CmsOtherRecipientInfo class]]) {
    return (OrgSpongycastleAsn1CmsOtherRecipientInfo *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1CmsOtherRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsOtherRecipientInfo)
