//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/crmf/EncryptedKey.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/cms/EnvelopedData.h"
#include "org/spongycastle/asn1/crmf/EncryptedKey.h"
#include "org/spongycastle/asn1/crmf/EncryptedValue.h"

@interface OrgSpongycastleAsn1CrmfEncryptedKey () {
 @public
  OrgSpongycastleAsn1CmsEnvelopedData *envelopedData_;
  OrgSpongycastleAsn1CrmfEncryptedValue *encryptedValue_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncryptedKey, envelopedData_, OrgSpongycastleAsn1CmsEnvelopedData *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CrmfEncryptedKey, encryptedValue_, OrgSpongycastleAsn1CrmfEncryptedValue *)

@implementation OrgSpongycastleAsn1CrmfEncryptedKey

+ (OrgSpongycastleAsn1CrmfEncryptedKey *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CrmfEncryptedKey_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1CmsEnvelopedData:(OrgSpongycastleAsn1CmsEnvelopedData *)envelopedData {
  OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CmsEnvelopedData_(self, envelopedData);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1CrmfEncryptedValue:(OrgSpongycastleAsn1CrmfEncryptedValue *)encryptedValue {
  OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(self, encryptedValue);
  return self;
}

- (jboolean)isEncryptedValue {
  return encryptedValue_ != nil;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getValue {
  if (encryptedValue_ != nil) {
    return encryptedValue_;
  }
  return envelopedData_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (encryptedValue_ != nil) {
    return [encryptedValue_ toASN1Primitive];
  }
  return new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, envelopedData_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1CrmfEncryptedKey;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1CmsEnvelopedData:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1CrmfEncryptedValue:);
  methods[3].selector = @selector(isEncryptedValue);
  methods[4].selector = @selector(getValue);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "envelopedData_", "LOrgSpongycastleAsn1CmsEnvelopedData;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encryptedValue_", "LOrgSpongycastleAsn1CrmfEncryptedValue;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1CmsEnvelopedData;", "LOrgSpongycastleAsn1CrmfEncryptedValue;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CrmfEncryptedKey = { "EncryptedKey", "org.spongycastle.asn1.crmf", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CrmfEncryptedKey;
}

@end

OrgSpongycastleAsn1CrmfEncryptedKey *OrgSpongycastleAsn1CrmfEncryptedKey_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CrmfEncryptedKey_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CrmfEncryptedKey class]]) {
    return (OrgSpongycastleAsn1CrmfEncryptedKey *) o;
  }
  else if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    return new_OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CmsEnvelopedData_(OrgSpongycastleAsn1CmsEnvelopedData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) o, false));
  }
  else if ([o isKindOfClass:[OrgSpongycastleAsn1CrmfEncryptedValue class]]) {
    return new_OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CrmfEncryptedValue_((OrgSpongycastleAsn1CrmfEncryptedValue *) o);
  }
  else {
    return new_OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(OrgSpongycastleAsn1CrmfEncryptedValue_getInstanceWithId_(o));
  }
}

void OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CmsEnvelopedData_(OrgSpongycastleAsn1CrmfEncryptedKey *self, OrgSpongycastleAsn1CmsEnvelopedData *envelopedData) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->envelopedData_ = envelopedData;
}

OrgSpongycastleAsn1CrmfEncryptedKey *new_OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CmsEnvelopedData_(OrgSpongycastleAsn1CmsEnvelopedData *envelopedData) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfEncryptedKey, initWithOrgSpongycastleAsn1CmsEnvelopedData_, envelopedData)
}

OrgSpongycastleAsn1CrmfEncryptedKey *create_OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CmsEnvelopedData_(OrgSpongycastleAsn1CmsEnvelopedData *envelopedData) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfEncryptedKey, initWithOrgSpongycastleAsn1CmsEnvelopedData_, envelopedData)
}

void OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(OrgSpongycastleAsn1CrmfEncryptedKey *self, OrgSpongycastleAsn1CrmfEncryptedValue *encryptedValue) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->encryptedValue_ = encryptedValue;
}

OrgSpongycastleAsn1CrmfEncryptedKey *new_OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(OrgSpongycastleAsn1CrmfEncryptedValue *encryptedValue) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CrmfEncryptedKey, initWithOrgSpongycastleAsn1CrmfEncryptedValue_, encryptedValue)
}

OrgSpongycastleAsn1CrmfEncryptedKey *create_OrgSpongycastleAsn1CrmfEncryptedKey_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(OrgSpongycastleAsn1CrmfEncryptedValue *encryptedValue) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CrmfEncryptedKey, initWithOrgSpongycastleAsn1CrmfEncryptedValue_, encryptedValue)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CrmfEncryptedKey)
