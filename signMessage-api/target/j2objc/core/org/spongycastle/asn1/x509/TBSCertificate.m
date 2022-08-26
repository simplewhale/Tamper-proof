//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/TBSCertificate.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERBitString.h"
#include "org/spongycastle/asn1/x500/X500Name.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"
#include "org/spongycastle/asn1/x509/Extensions.h"
#include "org/spongycastle/asn1/x509/SubjectPublicKeyInfo.h"
#include "org/spongycastle/asn1/x509/TBSCertificate.h"
#include "org/spongycastle/asn1/x509/Time.h"

@interface OrgSpongycastleAsn1X509TBSCertificate ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void OrgSpongycastleAsn1X509TBSCertificate_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509TBSCertificate *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X509TBSCertificate *new_OrgSpongycastleAsn1X509TBSCertificate_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509TBSCertificate *create_OrgSpongycastleAsn1X509TBSCertificate_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1X509TBSCertificate

+ (OrgSpongycastleAsn1X509TBSCertificate *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                  withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1X509TBSCertificate_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1X509TBSCertificate *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509TBSCertificate_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509TBSCertificate_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (jint)getVersionNumber {
  return [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(version__)) getValue])) intValue] + 1;
}

- (OrgSpongycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (OrgSpongycastleAsn1ASN1Integer *)getSerialNumber {
  return serialNumber_;
}

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getSignature {
  return signature_;
}

- (OrgSpongycastleAsn1X500X500Name *)getIssuer {
  return issuer_;
}

- (OrgSpongycastleAsn1X509Time *)getStartDate {
  return startDate_;
}

- (OrgSpongycastleAsn1X509Time *)getEndDate {
  return endDate_;
}

- (OrgSpongycastleAsn1X500X500Name *)getSubject {
  return subject_;
}

- (OrgSpongycastleAsn1X509SubjectPublicKeyInfo *)getSubjectPublicKeyInfo {
  return subjectPublicKeyInfo_;
}

- (OrgSpongycastleAsn1DERBitString *)getIssuerUniqueId {
  return issuerUniqueId_;
}

- (OrgSpongycastleAsn1DERBitString *)getSubjectUniqueId {
  return subjectUniqueId_;
}

- (OrgSpongycastleAsn1X509Extensions *)getExtensions {
  return extensions_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return seq_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1X509TBSCertificate;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509TBSCertificate;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X500X500Name;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509Time;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509Time;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X500X500Name;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509SubjectPublicKeyInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DERBitString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getVersionNumber);
  methods[4].selector = @selector(getVersion);
  methods[5].selector = @selector(getSerialNumber);
  methods[6].selector = @selector(getSignature);
  methods[7].selector = @selector(getIssuer);
  methods[8].selector = @selector(getStartDate);
  methods[9].selector = @selector(getEndDate);
  methods[10].selector = @selector(getSubject);
  methods[11].selector = @selector(getSubjectPublicKeyInfo);
  methods[12].selector = @selector(getIssuerUniqueId);
  methods[13].selector = @selector(getSubjectUniqueId);
  methods[14].selector = @selector(getExtensions);
  methods[15].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seq_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "version__", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, 4, -1, -1, -1 },
    { "serialNumber_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "signature_", "LOrgSpongycastleAsn1X509AlgorithmIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "issuer_", "LOrgSpongycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "startDate_", "LOrgSpongycastleAsn1X509Time;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "endDate_", "LOrgSpongycastleAsn1X509Time;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "subject_", "LOrgSpongycastleAsn1X500X500Name;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "subjectPublicKeyInfo_", "LOrgSpongycastleAsn1X509SubjectPublicKeyInfo;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "issuerUniqueId_", "LOrgSpongycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "subjectUniqueId_", "LOrgSpongycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "extensions_", "LOrgSpongycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "version" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509TBSCertificate = { "TBSCertificate", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 16, 12, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509TBSCertificate;
}

@end

OrgSpongycastleAsn1X509TBSCertificate *OrgSpongycastleAsn1X509TBSCertificate_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1X509TBSCertificate_initialize();
  return OrgSpongycastleAsn1X509TBSCertificate_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1X509TBSCertificate *OrgSpongycastleAsn1X509TBSCertificate_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509TBSCertificate_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1X509TBSCertificate class]]) {
    return (OrgSpongycastleAsn1X509TBSCertificate *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1X509TBSCertificate_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1X509TBSCertificate_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509TBSCertificate *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  jint seqStart = 0;
  self->seq_ = seq;
  if ([[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0] isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    self->version__ = OrgSpongycastleAsn1ASN1Integer_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:0], [OrgSpongycastleAsn1ASN1TaggedObject class]), true);
  }
  else {
    seqStart = -1;
    self->version__ = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(0);
  }
  jboolean isV1 = false;
  jboolean isV2 = false;
  if ([((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(self->version__)) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(0)]) {
    isV1 = true;
  }
  else if ([((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(self->version__)) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(1)]) {
    isV2 = true;
  }
  else if (![((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(self->version__)) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(2)]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"version number not recognised");
  }
  self->serialNumber_ = OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 1]);
  self->signature_ = OrgSpongycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 2]);
  self->issuer_ = OrgSpongycastleAsn1X500X500Name_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 3]);
  OrgSpongycastleAsn1ASN1Sequence *dates = (OrgSpongycastleAsn1ASN1Sequence *) cast_chk([seq getObjectAtWithInt:seqStart + 4], [OrgSpongycastleAsn1ASN1Sequence class]);
  self->startDate_ = OrgSpongycastleAsn1X509Time_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(dates)) getObjectAtWithInt:0]);
  self->endDate_ = OrgSpongycastleAsn1X509Time_getInstanceWithId_([dates getObjectAtWithInt:1]);
  self->subject_ = OrgSpongycastleAsn1X500X500Name_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 5]);
  self->subjectPublicKeyInfo_ = OrgSpongycastleAsn1X509SubjectPublicKeyInfo_getInstanceWithId_([seq getObjectAtWithInt:seqStart + 6]);
  jint extras = [seq size] - (seqStart + 6) - 1;
  if (extras != 0 && isV1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"version 1 certificate contains extra data");
  }
  while (extras > 0) {
    OrgSpongycastleAsn1ASN1TaggedObject *extra = (OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:seqStart + 6 + extras], [OrgSpongycastleAsn1ASN1TaggedObject class]);
    switch ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(extra)) getTagNo]) {
      case 1:
      self->issuerUniqueId_ = OrgSpongycastleAsn1DERBitString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(extra, false);
      break;
      case 2:
      self->subjectUniqueId_ = OrgSpongycastleAsn1DERBitString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(extra, false);
      break;
      case 3:
      if (isV2) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"version 2 certificate cannot contain extensions");
      }
      self->extensions_ = OrgSpongycastleAsn1X509Extensions_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(extra, true));
    }
    extras--;
  }
}

OrgSpongycastleAsn1X509TBSCertificate *new_OrgSpongycastleAsn1X509TBSCertificate_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509TBSCertificate, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509TBSCertificate *create_OrgSpongycastleAsn1X509TBSCertificate_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509TBSCertificate, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509TBSCertificate)
