//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/DigestedData.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/BERSequence.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/cms/ContentInfo.h"
#include "org/spongycastle/asn1/cms/DigestedData.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"

@interface OrgSpongycastleAsn1CmsDigestedData () {
 @public
  OrgSpongycastleAsn1ASN1Integer *version__;
  OrgSpongycastleAsn1X509AlgorithmIdentifier *digestAlgorithm_;
  OrgSpongycastleAsn1CmsContentInfo *encapContentInfo_;
  OrgSpongycastleAsn1ASN1OctetString *digest_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsDigestedData, version__, OrgSpongycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsDigestedData, digestAlgorithm_, OrgSpongycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsDigestedData, encapContentInfo_, OrgSpongycastleAsn1CmsContentInfo *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsDigestedData, digest_, OrgSpongycastleAsn1ASN1OctetString *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsDigestedData *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmsDigestedData *new_OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmsDigestedData *create_OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmsDigestedData

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)digestAlgorithm
                             withOrgSpongycastleAsn1CmsContentInfo:(OrgSpongycastleAsn1CmsContentInfo *)encapContentInfo
                                                     withByteArray:(IOSByteArray *)digest {
  OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1CmsContentInfo_withByteArray_(self, digestAlgorithm, encapContentInfo, digest);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmsDigestedData *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)ato
                                                                               withBoolean:(jboolean)isExplicit {
  return OrgSpongycastleAsn1CmsDigestedData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(ato, isExplicit);
}

+ (OrgSpongycastleAsn1CmsDigestedData *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1CmsDigestedData_getInstanceWithId_(obj);
}

- (OrgSpongycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getDigestAlgorithm {
  return digestAlgorithm_;
}

- (OrgSpongycastleAsn1CmsContentInfo *)getEncapContentInfo {
  return encapContentInfo_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:version__];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:digestAlgorithm_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:encapContentInfo_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:digest_];
  return new_OrgSpongycastleAsn1BERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

- (IOSByteArray *)getDigest {
  return [((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(digest_)) getOctets];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsDigestedData;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsDigestedData;", 0x9, 2, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmsContentInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:withOrgSpongycastleAsn1CmsContentInfo:withByteArray:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getVersion);
  methods[5].selector = @selector(getDigestAlgorithm);
  methods[6].selector = @selector(getEncapContentInfo);
  methods[7].selector = @selector(toASN1Primitive);
  methods[8].selector = @selector(getDigest);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, 5, -1, -1, -1 },
    { "digestAlgorithm_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "encapContentInfo_", "LOrgSpongycastleAsn1CmsContentInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "digest_", "LOrgSpongycastleAsn1ASN1OctetString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1X509AlgorithmIdentifier;LOrgSpongycastleAsn1CmsContentInfo;[B", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "version" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsDigestedData = { "DigestedData", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 9, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsDigestedData;
}

@end

void OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1CmsContentInfo_withByteArray_(OrgSpongycastleAsn1CmsDigestedData *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, OrgSpongycastleAsn1CmsContentInfo *encapContentInfo, IOSByteArray *digest) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->version__ = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(0);
  self->digestAlgorithm_ = digestAlgorithm;
  self->encapContentInfo_ = encapContentInfo;
  self->digest_ = new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(digest);
}

OrgSpongycastleAsn1CmsDigestedData *new_OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1CmsContentInfo_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, OrgSpongycastleAsn1CmsContentInfo *encapContentInfo, IOSByteArray *digest) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsDigestedData, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1CmsContentInfo_withByteArray_, digestAlgorithm, encapContentInfo, digest)
}

OrgSpongycastleAsn1CmsDigestedData *create_OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1CmsContentInfo_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *digestAlgorithm, OrgSpongycastleAsn1CmsContentInfo *encapContentInfo, IOSByteArray *digest) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsDigestedData, initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withOrgSpongycastleAsn1CmsContentInfo_withByteArray_, digestAlgorithm, encapContentInfo, digest)
}

void OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmsDigestedData *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->version__ = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0], [OrgSpongycastleAsn1ASN1Integer class]);
  self->digestAlgorithm_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->encapContentInfo_ = OrgSpongycastleAsn1CmsContentInfo_getInstanceWithId_([seq getObjectAtWithInt:2]);
  self->digest_ = OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:3]);
}

OrgSpongycastleAsn1CmsDigestedData *new_OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsDigestedData, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsDigestedData *create_OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsDigestedData, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmsDigestedData *OrgSpongycastleAsn1CmsDigestedData_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *ato, jboolean isExplicit) {
  OrgSpongycastleAsn1CmsDigestedData_initialize();
  return OrgSpongycastleAsn1CmsDigestedData_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(ato, isExplicit));
}

OrgSpongycastleAsn1CmsDigestedData *OrgSpongycastleAsn1CmsDigestedData_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1CmsDigestedData_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1CmsDigestedData class]]) {
    return (OrgSpongycastleAsn1CmsDigestedData *) obj;
  }
  if (obj != nil) {
    return new_OrgSpongycastleAsn1CmsDigestedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsDigestedData)
