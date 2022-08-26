//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/TaggedContentInfo.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cmc/BodyPartID.h"
#include "org/spongycastle/asn1/cmc/TaggedContentInfo.h"
#include "org/spongycastle/asn1/cms/ContentInfo.h"

@interface OrgSpongycastleAsn1CmcTaggedContentInfo () {
 @public
  OrgSpongycastleAsn1CmcBodyPartID *bodyPartID_;
  OrgSpongycastleAsn1CmsContentInfo *contentInfo_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcTaggedContentInfo, bodyPartID_, OrgSpongycastleAsn1CmcBodyPartID *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcTaggedContentInfo, contentInfo_, OrgSpongycastleAsn1CmsContentInfo *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcTaggedContentInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmcTaggedContentInfo *new_OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmcTaggedContentInfo *create_OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmcTaggedContentInfo

- (instancetype)initWithOrgSpongycastleAsn1CmcBodyPartID:(OrgSpongycastleAsn1CmcBodyPartID *)bodyPartID
                   withOrgSpongycastleAsn1CmsContentInfo:(OrgSpongycastleAsn1CmsContentInfo *)contentInfo {
  OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1CmcBodyPartID_withOrgSpongycastleAsn1CmsContentInfo_(self, bodyPartID, contentInfo);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmcTaggedContentInfo *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmcTaggedContentInfo_getInstanceWithId_(o);
}

+ (OrgSpongycastleAsn1CmcTaggedContentInfo *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CmcTaggedContentInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:bodyPartID_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:contentInfo_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

- (OrgSpongycastleAsn1CmcBodyPartID *)getBodyPartID {
  return bodyPartID_;
}

- (OrgSpongycastleAsn1CmsContentInfo *)getContentInfo {
  return contentInfo_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcTaggedContentInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcTaggedContentInfo;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcBodyPartID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsContentInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1CmcBodyPartID:withOrgSpongycastleAsn1CmsContentInfo:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(toASN1Primitive);
  methods[5].selector = @selector(getBodyPartID);
  methods[6].selector = @selector(getContentInfo);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bodyPartID_", "LOrgSpongycastleAsn1CmcBodyPartID;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "contentInfo_", "LOrgSpongycastleAsn1CmsContentInfo;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1CmcBodyPartID;LOrgSpongycastleAsn1CmsContentInfo;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmcTaggedContentInfo = { "TaggedContentInfo", "org.spongycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmcTaggedContentInfo;
}

@end

void OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1CmcBodyPartID_withOrgSpongycastleAsn1CmsContentInfo_(OrgSpongycastleAsn1CmcTaggedContentInfo *self, OrgSpongycastleAsn1CmcBodyPartID *bodyPartID, OrgSpongycastleAsn1CmsContentInfo *contentInfo) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->bodyPartID_ = bodyPartID;
  self->contentInfo_ = contentInfo;
}

OrgSpongycastleAsn1CmcTaggedContentInfo *new_OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1CmcBodyPartID_withOrgSpongycastleAsn1CmsContentInfo_(OrgSpongycastleAsn1CmcBodyPartID *bodyPartID, OrgSpongycastleAsn1CmsContentInfo *contentInfo) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcTaggedContentInfo, initWithOrgSpongycastleAsn1CmcBodyPartID_withOrgSpongycastleAsn1CmsContentInfo_, bodyPartID, contentInfo)
}

OrgSpongycastleAsn1CmcTaggedContentInfo *create_OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1CmcBodyPartID_withOrgSpongycastleAsn1CmsContentInfo_(OrgSpongycastleAsn1CmcBodyPartID *bodyPartID, OrgSpongycastleAsn1CmsContentInfo *contentInfo) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcTaggedContentInfo, initWithOrgSpongycastleAsn1CmcBodyPartID_withOrgSpongycastleAsn1CmsContentInfo_, bodyPartID, contentInfo)
}

void OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcTaggedContentInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->bodyPartID_ = OrgSpongycastleAsn1CmcBodyPartID_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->contentInfo_ = OrgSpongycastleAsn1CmsContentInfo_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

OrgSpongycastleAsn1CmcTaggedContentInfo *new_OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcTaggedContentInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcTaggedContentInfo *create_OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcTaggedContentInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcTaggedContentInfo *OrgSpongycastleAsn1CmcTaggedContentInfo_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmcTaggedContentInfo_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmcTaggedContentInfo class]]) {
    return (OrgSpongycastleAsn1CmcTaggedContentInfo *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmcTaggedContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

OrgSpongycastleAsn1CmcTaggedContentInfo *OrgSpongycastleAsn1CmcTaggedContentInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1CmcTaggedContentInfo_initialize();
  return OrgSpongycastleAsn1CmcTaggedContentInfo_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmcTaggedContentInfo)