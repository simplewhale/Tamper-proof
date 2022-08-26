//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/ContentInfo.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/BERSequence.h"
#include "org/spongycastle/asn1/BERTaggedObject.h"
#include "org/spongycastle/asn1/cms/ContentInfo.h"

@interface OrgSpongycastleAsn1CmsContentInfo () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *contentType_;
  id<OrgSpongycastleAsn1ASN1Encodable> content_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsContentInfo, contentType_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsContentInfo, content_, id<OrgSpongycastleAsn1ASN1Encodable>)

@implementation OrgSpongycastleAsn1CmsContentInfo

+ (OrgSpongycastleAsn1CmsContentInfo *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CmsContentInfo_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1CmsContentInfo *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                              withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CmsContentInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)contentType
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)content {
  OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(self, contentType, content);
  return self;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getContentType {
  return contentType_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getContent {
  return content_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:contentType_];
  if (content_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1BERTaggedObject_initWithInt_withOrgSpongycastleAsn1ASN1Encodable_(0, content_)];
  }
  return new_OrgSpongycastleAsn1BERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1CmsContentInfo;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsContentInfo;", 0x9, 0, 2, -1, -1, -1, -1 },
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
  methods[1].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Encodable:);
  methods[4].selector = @selector(getContentType);
  methods[5].selector = @selector(getContent);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "contentType_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "content_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsContentInfo = { "ContentInfo", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsContentInfo;
}

@end

OrgSpongycastleAsn1CmsContentInfo *OrgSpongycastleAsn1CmsContentInfo_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CmsContentInfo_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1CmsContentInfo class]]) {
    return (OrgSpongycastleAsn1CmsContentInfo *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

OrgSpongycastleAsn1CmsContentInfo *OrgSpongycastleAsn1CmsContentInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1CmsContentInfo_initialize();
  return OrgSpongycastleAsn1CmsContentInfo_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsContentInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 1 || [seq size] > 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->contentType_ = (OrgSpongycastleAsn1ASN1ObjectIdentifier *) cast_chk([seq getObjectAtWithInt:0], [OrgSpongycastleAsn1ASN1ObjectIdentifier class]);
  if ([seq size] > 1) {
    OrgSpongycastleAsn1ASN1TaggedObject *tagged = (OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:1], [OrgSpongycastleAsn1ASN1TaggedObject class]);
    if (![((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) isExplicit] || [tagged getTagNo] != 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Bad tag for 'content'");
    }
    self->content_ = [tagged getObject];
  }
}

OrgSpongycastleAsn1CmsContentInfo *new_OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsContentInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsContentInfo *create_OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsContentInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CmsContentInfo *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *contentType, id<OrgSpongycastleAsn1ASN1Encodable> content) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->contentType_ = contentType;
  self->content_ = content;
}

OrgSpongycastleAsn1CmsContentInfo *new_OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *contentType, id<OrgSpongycastleAsn1ASN1Encodable> content) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsContentInfo, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, contentType, content)
}

OrgSpongycastleAsn1CmsContentInfo *create_OrgSpongycastleAsn1CmsContentInfo_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *contentType, id<OrgSpongycastleAsn1ASN1Encodable> content) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsContentInfo, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, contentType, content)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsContentInfo)
