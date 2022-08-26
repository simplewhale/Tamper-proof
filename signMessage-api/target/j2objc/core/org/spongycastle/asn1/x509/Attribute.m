//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/Attribute.java
//

#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1Set.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/x509/Attribute.h"

@interface OrgSpongycastleAsn1X509Attribute () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *attrType_;
  OrgSpongycastleAsn1ASN1Set *attrValues_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509Attribute, attrType_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509Attribute, attrValues_, OrgSpongycastleAsn1ASN1Set *)

__attribute__((unused)) static void OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509Attribute *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X509Attribute *new_OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509Attribute *create_OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1X509Attribute

+ (OrgSpongycastleAsn1X509Attribute *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1X509Attribute_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)attrType
                                 withOrgSpongycastleAsn1ASN1Set:(OrgSpongycastleAsn1ASN1Set *)attrValues {
  OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Set_(self, attrType, attrValues);
  return self;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getAttrType {
  return new_OrgSpongycastleAsn1ASN1ObjectIdentifier_initWithNSString_([((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk(attrType_)) getId]);
}

- (IOSObjectArray *)getAttributeValues {
  return [((OrgSpongycastleAsn1ASN1Set *) nil_chk(attrValues_)) toArray];
}

- (OrgSpongycastleAsn1ASN1Set *)getAttrValues {
  return attrValues_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:attrType_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:attrValues_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1X509Attribute;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Set;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Set:);
  methods[3].selector = @selector(getAttrType);
  methods[4].selector = @selector(getAttributeValues);
  methods[5].selector = @selector(getAttrValues);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "attrType_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "attrValues_", "LOrgSpongycastleAsn1ASN1Set;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Set;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509Attribute = { "Attribute", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509Attribute;
}

@end

OrgSpongycastleAsn1X509Attribute *OrgSpongycastleAsn1X509Attribute_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1X509Attribute_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1X509Attribute class]]) {
    return (OrgSpongycastleAsn1X509Attribute *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509Attribute *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->attrType_ = OrgSpongycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->attrValues_ = OrgSpongycastleAsn1ASN1Set_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

OrgSpongycastleAsn1X509Attribute *new_OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509Attribute, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509Attribute *create_OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509Attribute, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1X509Attribute *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *attrType, OrgSpongycastleAsn1ASN1Set *attrValues) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->attrType_ = attrType;
  self->attrValues_ = attrValues;
}

OrgSpongycastleAsn1X509Attribute *new_OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1ObjectIdentifier *attrType, OrgSpongycastleAsn1ASN1Set *attrValues) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509Attribute, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Set_, attrType, attrValues)
}

OrgSpongycastleAsn1X509Attribute *create_OrgSpongycastleAsn1X509Attribute_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Set_(OrgSpongycastleAsn1ASN1ObjectIdentifier *attrType, OrgSpongycastleAsn1ASN1Set *attrValues) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509Attribute, initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Set_, attrType, attrValues)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509Attribute)
