//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/crmf/POPOPrivKey.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERBitString.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/cms/EnvelopedData.h"
#include "org/spongycastle/asn1/crmf/PKMACValue.h"
#include "org/spongycastle/asn1/crmf/POPOPrivKey.h"
#include "org/spongycastle/asn1/crmf/SubsequentMessage.h"

@interface OrgSpongycastleAsn1CrmfPOPOPrivKey () {
 @public
  jint tagNo_;
  id<OrgSpongycastleAsn1ASN1Encodable> obj_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfPOPOPrivKey, obj_, id<OrgSpongycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1CrmfPOPOPrivKey *self, OrgSpongycastleAsn1ASN1TaggedObject *obj);

__attribute__((unused)) static OrgSpongycastleAsn1CrmfPOPOPrivKey *new_OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *obj) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CrmfPOPOPrivKey *create_OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *obj);

@implementation OrgSpongycastleAsn1CrmfPOPOPrivKey

- (instancetype)initWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj {
  OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1ASN1TaggedObject_(self, obj);
  return self;
}

+ (OrgSpongycastleAsn1CrmfPOPOPrivKey *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CrmfPOPOPrivKey_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1CrmfPOPOPrivKey *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                               withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1CrmfPOPOPrivKey_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithOrgSpongycastleAsn1CrmfSubsequentMessage:(OrgSpongycastleAsn1CrmfSubsequentMessage *)msg {
  OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1CrmfSubsequentMessage_(self, msg);
  return self;
}

- (jint)getType {
  return tagNo_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getValue {
  return obj_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, tagNo_, obj_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CrmfPOPOPrivKey;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CrmfPOPOPrivKey;", 0x9, 1, 3, -1, -1, -1, -1 },
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
  methods[2].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1CrmfSubsequentMessage:);
  methods[4].selector = @selector(getType);
  methods[5].selector = @selector(getValue);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "thisMessage", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfPOPOPrivKey_thisMessage, 0x19, -1, -1, -1, -1 },
    { "subsequentMessage", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfPOPOPrivKey_subsequentMessage, 0x19, -1, -1, -1, -1 },
    { "dhMAC", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfPOPOPrivKey_dhMAC, 0x19, -1, -1, -1, -1 },
    { "agreeMAC", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfPOPOPrivKey_agreeMAC, 0x19, -1, -1, -1, -1 },
    { "encryptedKey", "I", .constantValue.asInt = OrgSpongycastleAsn1CrmfPOPOPrivKey_encryptedKey, 0x19, -1, -1, -1, -1 },
    { "tagNo_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "obj_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1TaggedObject;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LOrgSpongycastleAsn1CrmfSubsequentMessage;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CrmfPOPOPrivKey = { "POPOPrivKey", "org.spongycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 7, 7, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CrmfPOPOPrivKey;
}

@end

void OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1CrmfPOPOPrivKey *self, OrgSpongycastleAsn1ASN1TaggedObject *obj) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->tagNo_ = [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getTagNo];
  switch (self->tagNo_) {
    case OrgSpongycastleAsn1CrmfPOPOPrivKey_thisMessage:
    self->obj_ = OrgSpongycastleAsn1DERBitString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, false);
    break;
    case OrgSpongycastleAsn1CrmfPOPOPrivKey_subsequentMessage:
    self->obj_ = OrgSpongycastleAsn1CrmfSubsequentMessage_valueOfWithInt_([((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(OrgSpongycastleAsn1ASN1Integer_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, false))) getValue])) intValue]);
    break;
    case OrgSpongycastleAsn1CrmfPOPOPrivKey_dhMAC:
    self->obj_ = OrgSpongycastleAsn1DERBitString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, false);
    break;
    case OrgSpongycastleAsn1CrmfPOPOPrivKey_agreeMAC:
    self->obj_ = OrgSpongycastleAsn1CrmfPKMACValue_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, false);
    break;
    case OrgSpongycastleAsn1CrmfPOPOPrivKey_encryptedKey:
    self->obj_ = OrgSpongycastleAsn1CmsEnvelopedData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, false);
    break;
    default:
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown tag in POPOPrivKey");
  }
}

OrgSpongycastleAsn1CrmfPOPOPrivKey *new_OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *obj) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfPOPOPrivKey, initWithOrgSpongycastleAsn1ASN1TaggedObject_, obj)
}

OrgSpongycastleAsn1CrmfPOPOPrivKey *create_OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *obj) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfPOPOPrivKey, initWithOrgSpongycastleAsn1ASN1TaggedObject_, obj)
}

OrgSpongycastleAsn1CrmfPOPOPrivKey *OrgSpongycastleAsn1CrmfPOPOPrivKey_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CrmfPOPOPrivKey_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1CrmfPOPOPrivKey class]]) {
    return (OrgSpongycastleAsn1CrmfPOPOPrivKey *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithId_(obj));
  }
  return nil;
}

OrgSpongycastleAsn1CrmfPOPOPrivKey *OrgSpongycastleAsn1CrmfPOPOPrivKey_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1CrmfPOPOPrivKey_initialize();
  return OrgSpongycastleAsn1CrmfPOPOPrivKey_getInstanceWithId_(OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1CrmfSubsequentMessage_(OrgSpongycastleAsn1CrmfPOPOPrivKey *self, OrgSpongycastleAsn1CrmfSubsequentMessage *msg) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->tagNo_ = OrgSpongycastleAsn1CrmfPOPOPrivKey_subsequentMessage;
  self->obj_ = msg;
}

OrgSpongycastleAsn1CrmfPOPOPrivKey *new_OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1CrmfSubsequentMessage_(OrgSpongycastleAsn1CrmfSubsequentMessage *msg) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfPOPOPrivKey, initWithOrgSpongycastleAsn1CrmfSubsequentMessage_, msg)
}

OrgSpongycastleAsn1CrmfPOPOPrivKey *create_OrgSpongycastleAsn1CrmfPOPOPrivKey_initWithOrgSpongycastleAsn1CrmfSubsequentMessage_(OrgSpongycastleAsn1CrmfSubsequentMessage *msg) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfPOPOPrivKey, initWithOrgSpongycastleAsn1CrmfSubsequentMessage_, msg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CrmfPOPOPrivKey)
