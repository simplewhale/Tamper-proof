//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/BodyPartList.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cmc/BodyPartID.h"
#include "org/spongycastle/asn1/cmc/BodyPartList.h"
#include "org/spongycastle/asn1/cmc/Utils.h"

@interface OrgSpongycastleAsn1CmcBodyPartList () {
 @public
  IOSObjectArray *bodyPartIDs_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcBodyPartList, bodyPartIDs_, IOSObjectArray *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcBodyPartList *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmcBodyPartList *new_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmcBodyPartList *create_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmcBodyPartList

+ (OrgSpongycastleAsn1CmcBodyPartList *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CmcBodyPartList_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1CmcBodyPartList *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                               withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CmcBodyPartList_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithOrgSpongycastleAsn1CmcBodyPartID:(OrgSpongycastleAsn1CmcBodyPartID *)bodyPartID {
  OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1CmcBodyPartID_(self, bodyPartID);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1CmcBodyPartIDArray:(IOSObjectArray *)bodyPartIDs {
  OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1CmcBodyPartIDArray_(self, bodyPartIDs);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (IOSObjectArray *)getBodyPartIDs {
  return OrgSpongycastleAsn1CmcUtils_cloneWithOrgSpongycastleAsn1CmcBodyPartIDArray_(bodyPartIDs_);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableArray_(bodyPartIDs_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1CmcBodyPartList;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcBodyPartList;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1CmcBodyPartID;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1CmcBodyPartID:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1CmcBodyPartIDArray:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(getBodyPartIDs);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bodyPartIDs_", "[LOrgSpongycastleAsn1CmcBodyPartID;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LOrgSpongycastleAsn1CmcBodyPartID;", "[LOrgSpongycastleAsn1CmcBodyPartID;", "LOrgSpongycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmcBodyPartList = { "BodyPartList", "org.spongycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 7, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmcBodyPartList;
}

@end

OrgSpongycastleAsn1CmcBodyPartList *OrgSpongycastleAsn1CmcBodyPartList_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CmcBodyPartList_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1CmcBodyPartList class]]) {
    return (OrgSpongycastleAsn1CmcBodyPartList *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

OrgSpongycastleAsn1CmcBodyPartList *OrgSpongycastleAsn1CmcBodyPartList_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1CmcBodyPartList_initialize();
  return OrgSpongycastleAsn1CmcBodyPartList_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1CmcBodyPartID_(OrgSpongycastleAsn1CmcBodyPartList *self, OrgSpongycastleAsn1CmcBodyPartID *bodyPartID) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->bodyPartIDs_ = [IOSObjectArray newArrayWithObjects:(id[]){ bodyPartID } count:1 type:OrgSpongycastleAsn1CmcBodyPartID_class_()];
}

OrgSpongycastleAsn1CmcBodyPartList *new_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1CmcBodyPartID_(OrgSpongycastleAsn1CmcBodyPartID *bodyPartID) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcBodyPartList, initWithOrgSpongycastleAsn1CmcBodyPartID_, bodyPartID)
}

OrgSpongycastleAsn1CmcBodyPartList *create_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1CmcBodyPartID_(OrgSpongycastleAsn1CmcBodyPartID *bodyPartID) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcBodyPartList, initWithOrgSpongycastleAsn1CmcBodyPartID_, bodyPartID)
}

void OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1CmcBodyPartIDArray_(OrgSpongycastleAsn1CmcBodyPartList *self, IOSObjectArray *bodyPartIDs) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->bodyPartIDs_ = OrgSpongycastleAsn1CmcUtils_cloneWithOrgSpongycastleAsn1CmcBodyPartIDArray_(bodyPartIDs);
}

OrgSpongycastleAsn1CmcBodyPartList *new_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1CmcBodyPartIDArray_(IOSObjectArray *bodyPartIDs) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcBodyPartList, initWithOrgSpongycastleAsn1CmcBodyPartIDArray_, bodyPartIDs)
}

OrgSpongycastleAsn1CmcBodyPartList *create_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1CmcBodyPartIDArray_(IOSObjectArray *bodyPartIDs) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcBodyPartList, initWithOrgSpongycastleAsn1CmcBodyPartIDArray_, bodyPartIDs)
}

void OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcBodyPartList *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->bodyPartIDs_ = OrgSpongycastleAsn1CmcUtils_toBodyPartIDArrayWithOrgSpongycastleAsn1ASN1Sequence_(seq);
}

OrgSpongycastleAsn1CmcBodyPartList *new_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcBodyPartList, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcBodyPartList *create_OrgSpongycastleAsn1CmcBodyPartList_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcBodyPartList, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmcBodyPartList)
