//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/pkcs/SafeBag.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1Set.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DLSequence.h"
#include "org/spongycastle/asn1/DLTaggedObject.h"
#include "org/spongycastle/asn1/pkcs/SafeBag.h"

@interface OrgSpongycastleAsn1PkcsSafeBag () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *bagId_;
  id<OrgSpongycastleAsn1ASN1Encodable> bagValue_;
  OrgSpongycastleAsn1ASN1Set *bagAttributes_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsSafeBag, bagId_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsSafeBag, bagValue_, id<OrgSpongycastleAsn1ASN1Encodable>)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1PkcsSafeBag, bagAttributes_, OrgSpongycastleAsn1ASN1Set *)

__attribute__((unused)) static void OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1PkcsSafeBag *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1PkcsSafeBag *new_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1PkcsSafeBag *create_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1PkcsSafeBag

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj {
  OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(self, oid, obj);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)oid
                           withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj
                                 withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)bagAttributes {
  OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_(self, oid, obj, bagAttributes);
  return self;
}

+ (OrgSpongycastleAsn1PkcsSafeBag *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1PkcsSafeBag_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getBagId {
  return bagId_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getBagValue {
  return bagValue_;
}

- (OrgSpongycastleAsn1ASN1Set *)getBagAttributes {
  return bagAttributes_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:bagId_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DLTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 0, bagValue_)];
  if (bagAttributes_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:bagAttributes_];
  }
  return new_OrgSpongycastleAsn1DLSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1PkcsSafeBag;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Encodable:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Encodable:withOrgSpongycastleAsn1ASN1Set:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getBagId);
  methods[5].selector = @selector(getBagValue);
  methods[6].selector = @selector(getBagAttributes);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bagId_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "bagValue_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "bagAttributes_", "LOrgSpongycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Encodable;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Encodable;LOrgSpongycastleAsn1ASN1Set;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1PkcsSafeBag = { "SafeBag", "org.spongycastle.asn1.pkcs", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1PkcsSafeBag;
}

@end

void OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1PkcsSafeBag *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->bagId_ = oid;
  self->bagValue_ = obj;
  self->bagAttributes_ = nil;
}

OrgSpongycastleAsn1PkcsSafeBag *new_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1PkcsSafeBag, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, oid, obj)
}

OrgSpongycastleAsn1PkcsSafeBag *create_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1PkcsSafeBag, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, oid, obj)
}

void OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1PkcsSafeBag *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj, OrgSpongycastleAsn1ASN1Set *bagAttributes) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->bagId_ = oid;
  self->bagValue_ = obj;
  self->bagAttributes_ = bagAttributes;
}

OrgSpongycastleAsn1PkcsSafeBag *new_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj, OrgSpongycastleAsn1ASN1Set *bagAttributes) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1PkcsSafeBag, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_, oid, obj, bagAttributes)
}

OrgSpongycastleAsn1PkcsSafeBag *create_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1ObjectIdentifier *oid, id<OrgSpongycastleAsn1ASN1Encodable> obj, OrgSpongycastleAsn1ASN1Set *bagAttributes) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1PkcsSafeBag, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_withOrgSpongycastleAsn1ASN1Set_, oid, obj, bagAttributes)
}

OrgSpongycastleAsn1PkcsSafeBag *OrgSpongycastleAsn1PkcsSafeBag_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1PkcsSafeBag_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1PkcsSafeBag class]]) {
    return (OrgSpongycastleAsn1PkcsSafeBag *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1PkcsSafeBag *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->bagId_ = (OrgSpongycastleAsn1ASN1ObjectIdentifier *) cast_chk([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0], [OrgSpongycastleAsn1ASN1ObjectIdentifier class]);
  self->bagValue_ = [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:1], [OrgSpongycastleAsn1ASN1TaggedObject class])))) getObject];
  if ([seq size] == 3) {
    self->bagAttributes_ = (OrgSpongycastleAsn1ASN1Set *) cast_chk([seq getObjectAtWithInt:2], [OrgSpongycastleAsn1ASN1Set class]);
  }
}

OrgSpongycastleAsn1PkcsSafeBag *new_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1PkcsSafeBag, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1PkcsSafeBag *create_OrgSpongycastleAsn1PkcsSafeBag_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1PkcsSafeBag, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1PkcsSafeBag)
