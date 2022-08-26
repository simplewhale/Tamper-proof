//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/CertOrEncCert.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/cmp/CMPCertificate.h"
#include "org/spongycastle/asn1/cmp/CertOrEncCert.h"
#include "org/spongycastle/asn1/crmf/EncryptedValue.h"

@interface OrgSpongycastleAsn1CmpCertOrEncCert () {
 @public
  OrgSpongycastleAsn1CmpCMPCertificate *certificate_;
  OrgSpongycastleAsn1CrmfEncryptedValue *encryptedCert_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)tagged;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpCertOrEncCert, certificate_, OrgSpongycastleAsn1CmpCMPCertificate *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpCertOrEncCert, encryptedCert_, OrgSpongycastleAsn1CrmfEncryptedValue *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1CmpCertOrEncCert *self, OrgSpongycastleAsn1ASN1TaggedObject *tagged);

__attribute__((unused)) static OrgSpongycastleAsn1CmpCertOrEncCert *new_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *tagged) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmpCertOrEncCert *create_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *tagged);

@implementation OrgSpongycastleAsn1CmpCertOrEncCert

- (instancetype)initWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)tagged {
  OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1ASN1TaggedObject_(self, tagged);
  return self;
}

+ (OrgSpongycastleAsn1CmpCertOrEncCert *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmpCertOrEncCert_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1CmpCMPCertificate:(OrgSpongycastleAsn1CmpCMPCertificate *)certificate {
  OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1CmpCMPCertificate_(self, certificate);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1CrmfEncryptedValue:(OrgSpongycastleAsn1CrmfEncryptedValue *)encryptedCert {
  OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(self, encryptedCert);
  return self;
}

- (OrgSpongycastleAsn1CmpCMPCertificate *)getCertificate {
  return certificate_;
}

- (OrgSpongycastleAsn1CrmfEncryptedValue *)getEncryptedCert {
  return encryptedCert_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (certificate_ != nil) {
    return new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 0, certificate_);
  }
  return new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 1, encryptedCert_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmpCertOrEncCert;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmpCMPCertificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CrmfEncryptedValue;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1TaggedObject:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1CmpCMPCertificate:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1CrmfEncryptedValue:);
  methods[4].selector = @selector(getCertificate);
  methods[5].selector = @selector(getEncryptedCert);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "certificate_", "LOrgSpongycastleAsn1CmpCMPCertificate;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encryptedCert_", "LOrgSpongycastleAsn1CrmfEncryptedValue;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1TaggedObject;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1CmpCMPCertificate;", "LOrgSpongycastleAsn1CrmfEncryptedValue;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmpCertOrEncCert = { "CertOrEncCert", "org.spongycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmpCertOrEncCert;
}

@end

void OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1CmpCertOrEncCert *self, OrgSpongycastleAsn1ASN1TaggedObject *tagged) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) getTagNo] == 0) {
    self->certificate_ = OrgSpongycastleAsn1CmpCMPCertificate_getInstanceWithId_([tagged getObject]);
  }
  else if ([tagged getTagNo] == 1) {
    self->encryptedCert_ = OrgSpongycastleAsn1CrmfEncryptedValue_getInstanceWithId_([tagged getObject]);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown tag: ", [tagged getTagNo]));
  }
}

OrgSpongycastleAsn1CmpCertOrEncCert *new_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *tagged) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpCertOrEncCert, initWithOrgSpongycastleAsn1ASN1TaggedObject_, tagged)
}

OrgSpongycastleAsn1CmpCertOrEncCert *create_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *tagged) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpCertOrEncCert, initWithOrgSpongycastleAsn1ASN1TaggedObject_, tagged)
}

OrgSpongycastleAsn1CmpCertOrEncCert *OrgSpongycastleAsn1CmpCertOrEncCert_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmpCertOrEncCert_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmpCertOrEncCert class]]) {
    return (OrgSpongycastleAsn1CmpCertOrEncCert *) o;
  }
  if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    return new_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1ASN1TaggedObject_((OrgSpongycastleAsn1ASN1TaggedObject *) o);
  }
  return nil;
}

void OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1CmpCMPCertificate_(OrgSpongycastleAsn1CmpCertOrEncCert *self, OrgSpongycastleAsn1CmpCMPCertificate *certificate) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if (certificate == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'certificate' cannot be null");
  }
  self->certificate_ = certificate;
}

OrgSpongycastleAsn1CmpCertOrEncCert *new_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1CmpCMPCertificate_(OrgSpongycastleAsn1CmpCMPCertificate *certificate) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpCertOrEncCert, initWithOrgSpongycastleAsn1CmpCMPCertificate_, certificate)
}

OrgSpongycastleAsn1CmpCertOrEncCert *create_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1CmpCMPCertificate_(OrgSpongycastleAsn1CmpCMPCertificate *certificate) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpCertOrEncCert, initWithOrgSpongycastleAsn1CmpCMPCertificate_, certificate)
}

void OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(OrgSpongycastleAsn1CmpCertOrEncCert *self, OrgSpongycastleAsn1CrmfEncryptedValue *encryptedCert) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if (encryptedCert == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'encryptedCert' cannot be null");
  }
  self->encryptedCert_ = encryptedCert;
}

OrgSpongycastleAsn1CmpCertOrEncCert *new_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(OrgSpongycastleAsn1CrmfEncryptedValue *encryptedCert) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpCertOrEncCert, initWithOrgSpongycastleAsn1CrmfEncryptedValue_, encryptedCert)
}

OrgSpongycastleAsn1CmpCertOrEncCert *create_OrgSpongycastleAsn1CmpCertOrEncCert_initWithOrgSpongycastleAsn1CrmfEncryptedValue_(OrgSpongycastleAsn1CrmfEncryptedValue *encryptedCert) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpCertOrEncCert, initWithOrgSpongycastleAsn1CrmfEncryptedValue_, encryptedCert)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmpCertOrEncCert)
