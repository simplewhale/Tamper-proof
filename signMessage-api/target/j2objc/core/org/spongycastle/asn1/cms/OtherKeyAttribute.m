//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/OtherKeyAttribute.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cms/OtherKeyAttribute.h"

@interface OrgSpongycastleAsn1CmsOtherKeyAttribute () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *keyAttrId_;
  id<OrgSpongycastleAsn1ASN1Encodable> keyAttr_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsOtherKeyAttribute, keyAttrId_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsOtherKeyAttribute, keyAttr_, id<OrgSpongycastleAsn1ASN1Encodable>)

@implementation OrgSpongycastleAsn1CmsOtherKeyAttribute

+ (OrgSpongycastleAsn1CmsOtherKeyAttribute *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmsOtherKeyAttribute_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)keyAttrId
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)keyAttr {
  OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(self, keyAttrId, keyAttr);
  return self;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getKeyAttrId {
  return keyAttrId_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getKeyAttr {
  return keyAttr_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:keyAttrId_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:keyAttr_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1CmsOtherKeyAttribute;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Encodable:);
  methods[3].selector = @selector(getKeyAttrId);
  methods[4].selector = @selector(getKeyAttr);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "keyAttrId_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyAttr_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsOtherKeyAttribute = { "OtherKeyAttribute", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsOtherKeyAttribute;
}

@end

OrgSpongycastleAsn1CmsOtherKeyAttribute *OrgSpongycastleAsn1CmsOtherKeyAttribute_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmsOtherKeyAttribute_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmsOtherKeyAttribute class]]) {
    return (OrgSpongycastleAsn1CmsOtherKeyAttribute *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsOtherKeyAttribute *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->keyAttrId_ = (OrgSpongycastleAsn1ASN1ObjectIdentifier *) cast_chk([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0], [OrgSpongycastleAsn1ASN1ObjectIdentifier class]);
  self->keyAttr_ = [seq getObjectAtWithInt:1];
}

OrgSpongycastleAsn1CmsOtherKeyAttribute *new_OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOtherKeyAttribute, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsOtherKeyAttribute *create_OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOtherKeyAttribute, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CmsOtherKeyAttribute *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *keyAttrId, id<OrgSpongycastleAsn1ASN1Encodable> keyAttr) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->keyAttrId_ = keyAttrId;
  self->keyAttr_ = keyAttr;
}

OrgSpongycastleAsn1CmsOtherKeyAttribute *new_OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *keyAttrId, id<OrgSpongycastleAsn1ASN1Encodable> keyAttr) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsOtherKeyAttribute, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, keyAttrId, keyAttr)
}

OrgSpongycastleAsn1CmsOtherKeyAttribute *create_OrgSpongycastleAsn1CmsOtherKeyAttribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *keyAttrId, id<OrgSpongycastleAsn1ASN1Encodable> keyAttr) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsOtherKeyAttribute, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, keyAttrId, keyAttr)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsOtherKeyAttribute)
