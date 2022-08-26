//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/crmf/ProofOfPossession.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERNull.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/crmf/POPOPrivKey.h"
#include "org/spongycastle/asn1/crmf/POPOSigningKey.h"
#include "org/spongycastle/asn1/crmf/ProofOfPossession.h"

@interface OrgSpongycastleAsn1CrmfProofOfPossession () {
 @public
  jint tagNo_;
  id<OrgSpongycastleAsn1ASN1Encodable> obj_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)tagged;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfProofOfPossession, obj_, id<OrgSpongycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1CrmfProofOfPossession *self, OrgSpongycastleAsn1ASN1TaggedObject *tagged);

__attribute__((unused)) static OrgSpongycastleAsn1CrmfProofOfPossession *new_OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *tagged) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CrmfProofOfPossession *create_OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *tagged);

@implementation OrgSpongycastleAsn1CrmfProofOfPossession

- (instancetype)initWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)tagged {
  OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1ASN1TaggedObject_(self, tagged);
  return self;
}

+ (OrgSpongycastleAsn1CrmfProofOfPossession *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CrmfProofOfPossession_getInstanceWithId_(o);
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleAsn1CrmfProofOfPossession_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithOrgSpongycastleAsn1CrmfPOPOSigningKey:(OrgSpongycastleAsn1CrmfPOPOSigningKey *)poposk {
  OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1CrmfPOPOSigningKey_(self, poposk);
  return self;
}

- (instancetype)initWithInt:(jint)type
withOrgSpongycastleAsn1CrmfPOPOPrivKey:(OrgSpongycastleAsn1CrmfPOPOPrivKey *)privkey {
  OrgSpongycastleAsn1CrmfProofOfPossession_initWithInt_withOrgSpongycastleAsn1CrmfPOPOPrivKey_(self, type, privkey);
  return self;
}

- (jint)getType {
  return tagNo_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getObject {
  return obj_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, tagNo_, obj_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CrmfProofOfPossession;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1TaggedObject:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(init);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1CrmfPOPOSigningKey:);
  methods[4].selector = @selector(initWithInt:withOrgSpongycastleAsn1CrmfPOPOPrivKey:);
  methods[5].selector = @selector(getType);
  methods[6].selector = @selector(getObject);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "TYPE_RA_VERIFIED", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfProofOfPossession_TYPE_RA_VERIFIED, 0x19, -1, -1, -1, -1 },
    { "TYPE_SIGNING_KEY", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfProofOfPossession_TYPE_SIGNING_KEY, 0x19, -1, -1, -1, -1 },
    { "TYPE_KEY_ENCIPHERMENT", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfProofOfPossession_TYPE_KEY_ENCIPHERMENT, 0x19, -1, -1, -1, -1 },
    { "TYPE_KEY_AGREEMENT", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfProofOfPossession_TYPE_KEY_AGREEMENT, 0x19, -1, -1, -1, -1 },
    { "tagNo_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "obj_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1TaggedObject;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1CrmfPOPOSigningKey;", "ILOrgSpongycastleAsn1CrmfPOPOPrivKey;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CrmfProofOfPossession = { "ProofOfPossession", "org.spongycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 8, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CrmfProofOfPossession;
}

@end

void OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1CrmfProofOfPossession *self, OrgSpongycastleAsn1ASN1TaggedObject *tagged) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->tagNo_ = [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) getTagNo];
  switch (self->tagNo_) {
    case 0:
    self->obj_ = JreLoadStatic(OrgSpongycastleAsn1DERNull, INSTANCE);
    break;
    case 1:
    self->obj_ = OrgSpongycastleAsn1CrmfPOPOSigningKey_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false);
    break;
    case 2:
    case 3:
    self->obj_ = OrgSpongycastleAsn1CrmfPOPOPrivKey_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tagged, true);
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown tag: ", self->tagNo_));
  }
}

OrgSpongycastleAsn1CrmfProofOfPossession *new_OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *tagged) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfProofOfPossession, initWithOrgSpongycastleAsn1ASN1TaggedObject_, tagged)
}

OrgSpongycastleAsn1CrmfProofOfPossession *create_OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *tagged) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfProofOfPossession, initWithOrgSpongycastleAsn1ASN1TaggedObject_, tagged)
}

OrgSpongycastleAsn1CrmfProofOfPossession *OrgSpongycastleAsn1CrmfProofOfPossession_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CrmfProofOfPossession_initialize();
  if (o == nil || [o isKindOfClass:[OrgSpongycastleAsn1CrmfProofOfPossession class]]) {
    return (OrgSpongycastleAsn1CrmfProofOfPossession *) cast_chk(o, [OrgSpongycastleAsn1CrmfProofOfPossession class]);
  }
  if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    return new_OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1ASN1TaggedObject_((OrgSpongycastleAsn1ASN1TaggedObject *) o);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid object: ", [[o java_getClass] getName]));
}

void OrgSpongycastleAsn1CrmfProofOfPossession_init(OrgSpongycastleAsn1CrmfProofOfPossession *self) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->tagNo_ = OrgSpongycastleAsn1CrmfProofOfPossession_TYPE_RA_VERIFIED;
  self->obj_ = JreLoadStatic(OrgSpongycastleAsn1DERNull, INSTANCE);
}

OrgSpongycastleAsn1CrmfProofOfPossession *new_OrgSpongycastleAsn1CrmfProofOfPossession_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfProofOfPossession, init)
}

OrgSpongycastleAsn1CrmfProofOfPossession *create_OrgSpongycastleAsn1CrmfProofOfPossession_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfProofOfPossession, init)
}

void OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1CrmfPOPOSigningKey_(OrgSpongycastleAsn1CrmfProofOfPossession *self, OrgSpongycastleAsn1CrmfPOPOSigningKey *poposk) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->tagNo_ = OrgSpongycastleAsn1CrmfProofOfPossession_TYPE_SIGNING_KEY;
  self->obj_ = poposk;
}

OrgSpongycastleAsn1CrmfProofOfPossession *new_OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1CrmfPOPOSigningKey_(OrgSpongycastleAsn1CrmfPOPOSigningKey *poposk) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfProofOfPossession, initWithOrgSpongycastleAsn1CrmfPOPOSigningKey_, poposk)
}

OrgSpongycastleAsn1CrmfProofOfPossession *create_OrgSpongycastleAsn1CrmfProofOfPossession_initWithOrgSpongycastleAsn1CrmfPOPOSigningKey_(OrgSpongycastleAsn1CrmfPOPOSigningKey *poposk) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfProofOfPossession, initWithOrgSpongycastleAsn1CrmfPOPOSigningKey_, poposk)
}

void OrgSpongycastleAsn1CrmfProofOfPossession_initWithInt_withOrgSpongycastleAsn1CrmfPOPOPrivKey_(OrgSpongycastleAsn1CrmfProofOfPossession *self, jint type, OrgSpongycastleAsn1CrmfPOPOPrivKey *privkey) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->tagNo_ = type;
  self->obj_ = privkey;
}

OrgSpongycastleAsn1CrmfProofOfPossession *new_OrgSpongycastleAsn1CrmfProofOfPossession_initWithInt_withOrgSpongycastleAsn1CrmfPOPOPrivKey_(jint type, OrgSpongycastleAsn1CrmfPOPOPrivKey *privkey) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfProofOfPossession, initWithInt_withOrgSpongycastleAsn1CrmfPOPOPrivKey_, type, privkey)
}

OrgSpongycastleAsn1CrmfProofOfPossession *create_OrgSpongycastleAsn1CrmfProofOfPossession_initWithInt_withOrgSpongycastleAsn1CrmfPOPOPrivKey_(jint type, OrgSpongycastleAsn1CrmfPOPOPrivKey *privkey) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfProofOfPossession, initWithInt_withOrgSpongycastleAsn1CrmfPOPOPrivKey_, type, privkey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CrmfProofOfPossession)