//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/KeyTransRecipientInfo.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cms/KeyTransRecipientInfo.h"
#include "org/spongycastle/asn1/cms/RecipientIdentifier.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"

@interface OrgSpongycastleAsn1CmsKeyTransRecipientInfo () {
 @public
  OrgSpongycastleAsn1ASN1Integer *version__;
  OrgSpongycastleAsn1CmsRecipientIdentifier *rid_;
  OrgSpongycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm_;
  OrgSpongycastleAsn1ASN1OctetString *encryptedKey_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsKeyTransRecipientInfo, version__, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsKeyTransRecipientInfo, rid_, OrgSpongycastleAsn1CmsRecipientIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsKeyTransRecipientInfo, keyEncryptionAlgorithm_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsKeyTransRecipientInfo, encryptedKey_, OrgSpongycastleAsn1ASN1OctetString *)

@implementation OrgSpongycastleAsn1CmsKeyTransRecipientInfo

- (instancetype)initWithOrgSpongycastleAsn1CmsRecipientIdentifier:(OrgSpongycastleAsn1CmsRecipientIdentifier *)rid
                   withOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)keyEncryptionAlgorithm
                           withOrgSpongycastleAsn1ASN1OctetString:(OrgSpongycastleAsn1ASN1OctetString *)encryptedKey {
  OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(self, rid, keyEncryptionAlgorithm, encryptedKey);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmsKeyTransRecipientInfo *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CmsKeyTransRecipientInfo_getInstanceWithId_(obj);
}

- (OrgSpongycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (OrgSpongycastleAsn1CmsRecipientIdentifier *)getRecipientIdentifier {
  return rid_;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getKeyEncryptionAlgorithm {
  return keyEncryptionAlgorithm_;
}

- (OrgSpongycastleAsn1ASN1OctetString *)getEncryptedKey {
  return encryptedKey_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:version__];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:rid_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:keyEncryptionAlgorithm_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:encryptedKey_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsKeyTransRecipientInfo;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsRecipientIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1OctetString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1CmsRecipientIdentifier:withOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1ASN1OctetString:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getVersion);
  methods[4].selector = @selector(getRecipientIdentifier);
  methods[5].selector = @selector(getKeyEncryptionAlgorithm);
  methods[6].selector = @selector(getEncryptedKey);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 4, -1, -1, -1 },
    { "rid_", "LOrgSpongycastleAsn1CmsRecipientIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyEncryptionAlgorithm_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encryptedKey_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1CmsRecipientIdentifier;LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1ASN1OctetString;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "version" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsKeyTransRecipientInfo = { "KeyTransRecipientInfo", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 8, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsKeyTransRecipientInfo;
}

@end

void OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1CmsKeyTransRecipientInfo *self, OrgSpongycastleAsn1CmsRecipientIdentifier *rid, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, OrgSpongycastleAsn1ASN1OctetString *encryptedKey) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([[((OrgSpongycastleAsn1CmsRecipientIdentifier *) nil_chk(rid)) toASN1Primitive] isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    self->version__ = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(2);
  }
  else {
    self->version__ = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(0);
  }
  self->rid_ = rid;
  self->keyEncryptionAlgorithm_ = keyEncryptionAlgorithm;
  self->encryptedKey_ = encryptedKey;
}

OrgSpongycastleAsn1CmsKeyTransRecipientInfo *new_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1CmsRecipientIdentifier *rid, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, OrgSpongycastleAsn1ASN1OctetString *encryptedKey) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsKeyTransRecipientInfo, initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_, rid, keyEncryptionAlgorithm, encryptedKey)
}

OrgSpongycastleAsn1CmsKeyTransRecipientInfo *create_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_(OrgSpongycastleAsn1CmsRecipientIdentifier *rid, OrgSpongycastleAsn1X509AlgorithmIdentifier *keyEncryptionAlgorithm, OrgSpongycastleAsn1ASN1OctetString *encryptedKey) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsKeyTransRecipientInfo, initWithOrgSpongycastleAsn1CmsRecipientIdentifier_withOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1ASN1OctetString_, rid, keyEncryptionAlgorithm, encryptedKey)
}

void OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsKeyTransRecipientInfo *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->version__ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0], [OrgSpongycastleAsn1ASN1Integer class]);
  self->rid_ = OrgSpongycastleAsn1CmsRecipientIdentifier_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->keyEncryptionAlgorithm_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:2]);
  self->encryptedKey_ = (OrgSpongycastleAsn1ASN1OctetString *) cast_chk([seq getObjectAtWithInt:3], [OrgSpongycastleAsn1ASN1OctetString class]);
}

OrgSpongycastleAsn1CmsKeyTransRecipientInfo *new_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsKeyTransRecipientInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsKeyTransRecipientInfo *create_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsKeyTransRecipientInfo, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsKeyTransRecipientInfo *OrgSpongycastleAsn1CmsKeyTransRecipientInfo_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1CmsKeyTransRecipientInfo class]]) {
    return (OrgSpongycastleAsn1CmsKeyTransRecipientInfo *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1CmsKeyTransRecipientInfo_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsKeyTransRecipientInfo)
