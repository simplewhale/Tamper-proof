//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/tsp/TimeStampReq.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Boolean.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/tsp/MessageImprint.h"
#include "org/spongycastle/asn1/tsp/TimeStampReq.h"
#include "org/spongycastle/asn1/x509/Extensions.h"

@interface OrgSpongycastleAsn1TspTimeStampReq ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1TspTimeStampReq *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1TspTimeStampReq *new_OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1TspTimeStampReq *create_OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1TspTimeStampReq

+ (OrgSpongycastleAsn1TspTimeStampReq *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1TspTimeStampReq_getInstanceWithId_(o);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1TspMessageImprint:(OrgSpongycastleAsn1TspMessageImprint *)messageImprint
                 withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)tsaPolicy
                          withOrgSpongycastleAsn1ASN1Integer:(OrgSpongycastleAsn1ASN1Integer *)nonce
                          withOrgSpongycastleAsn1ASN1Boolean:(OrgSpongycastleAsn1ASN1Boolean *)certReq
                       withOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)extensions {
  OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1TspMessageImprint_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1X509Extensions_(self, messageImprint, tsaPolicy, nonce, certReq, extensions);
  return self;
}

- (OrgSpongycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (OrgSpongycastleAsn1TspMessageImprint *)getMessageImprint {
  return messageImprint_;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getReqPolicy {
  return tsaPolicy_;
}

- (OrgSpongycastleAsn1ASN1Integer *)getNonce {
  return nonce_;
}

- (OrgSpongycastleAsn1ASN1Boolean *)getCertReq {
  return certReq_;
}

- (OrgSpongycastleAsn1X509Extensions *)getExtensions {
  return extensions_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:version__];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:messageImprint_];
  if (tsaPolicy_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:tsaPolicy_];
  }
  if (nonce_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:nonce_];
  }
  if (certReq_ != nil && [certReq_ isTrue]) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:certReq_];
  }
  if (extensions_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, extensions_)];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1TspTimeStampReq;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1TspMessageImprint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Boolean;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1TspMessageImprint:withOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Integer:withOrgSpongycastleAsn1ASN1Boolean:withOrgSpongycastleAsn1X509Extensions:);
  methods[3].selector = @selector(getVersion);
  methods[4].selector = @selector(getMessageImprint);
  methods[5].selector = @selector(getReqPolicy);
  methods[6].selector = @selector(getNonce);
  methods[7].selector = @selector(getCertReq);
  methods[8].selector = @selector(getExtensions);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, 4, -1, -1, -1 },
    { "messageImprint_", "LOrgSpongycastleAsn1TspMessageImprint;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "tsaPolicy_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "nonce_", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "certReq_", "LOrgSpongycastleAsn1ASN1Boolean;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "extensions_", "LOrgSpongycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1TspMessageImprint;LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Integer;LOrgSpongycastleAsn1ASN1Boolean;LOrgSpongycastleAsn1X509Extensions;", "version" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1TspTimeStampReq = { "TimeStampReq", "org.spongycastle.asn1.tsp", ptrTable, methods, fields, 7, 0x1, 10, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1TspTimeStampReq;
}

@end

OrgSpongycastleAsn1TspTimeStampReq *OrgSpongycastleAsn1TspTimeStampReq_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1TspTimeStampReq_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1TspTimeStampReq class]]) {
    return (OrgSpongycastleAsn1TspTimeStampReq *) o;
  }
  else if (o != nil) {
    return new_OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1TspTimeStampReq *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  jint nbObjects = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size];
  jint seqStart = 0;
  self->version__ = OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:seqStart]);
  seqStart++;
  self->messageImprint_ = OrgSpongycastleAsn1TspMessageImprint_getInstanceWithId_([seq getObjectAtWithInt:seqStart]);
  seqStart++;
  for (jint opt = seqStart; opt < nbObjects; opt++) {
    if ([[seq getObjectAtWithInt:opt] isKindOfClass:[OrgSpongycastleAsn1ASN1ObjectIdentifier class]]) {
      self->tsaPolicy_ = OrgSpongycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:opt]);
    }
    else if ([[seq getObjectAtWithInt:opt] isKindOfClass:[OrgSpongycastleAsn1ASN1Integer class]]) {
      self->nonce_ = OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:opt]);
    }
    else if ([[seq getObjectAtWithInt:opt] isKindOfClass:[OrgSpongycastleAsn1ASN1Boolean class]]) {
      self->certReq_ = OrgSpongycastleAsn1ASN1Boolean_getInstanceWithId_([seq getObjectAtWithInt:opt]);
    }
    else if ([[seq getObjectAtWithInt:opt] isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
      OrgSpongycastleAsn1ASN1TaggedObject *tagged = (OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:opt], [OrgSpongycastleAsn1ASN1TaggedObject class]);
      if ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(tagged)) getTagNo] == 0) {
        self->extensions_ = OrgSpongycastleAsn1X509Extensions_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(tagged, false);
      }
    }
  }
}

OrgSpongycastleAsn1TspTimeStampReq *new_OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1TspTimeStampReq, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1TspTimeStampReq *create_OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1TspTimeStampReq, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1TspMessageImprint_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1TspTimeStampReq *self, OrgSpongycastleAsn1TspMessageImprint *messageImprint, OrgSpongycastleAsn1ASN1ObjectIdentifier *tsaPolicy, OrgSpongycastleAsn1ASN1Integer *nonce, OrgSpongycastleAsn1ASN1Boolean *certReq, OrgSpongycastleAsn1X509Extensions *extensions) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->version__ = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(1);
  self->messageImprint_ = messageImprint;
  self->tsaPolicy_ = tsaPolicy;
  self->nonce_ = nonce;
  self->certReq_ = certReq;
  self->extensions_ = extensions;
}

OrgSpongycastleAsn1TspTimeStampReq *new_OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1TspMessageImprint_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1TspMessageImprint *messageImprint, OrgSpongycastleAsn1ASN1ObjectIdentifier *tsaPolicy, OrgSpongycastleAsn1ASN1Integer *nonce, OrgSpongycastleAsn1ASN1Boolean *certReq, OrgSpongycastleAsn1X509Extensions *extensions) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1TspTimeStampReq, initWithOrgSpongycastleAsn1TspMessageImprint_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1X509Extensions_, messageImprint, tsaPolicy, nonce, certReq, extensions)
}

OrgSpongycastleAsn1TspTimeStampReq *create_OrgSpongycastleAsn1TspTimeStampReq_initWithOrgSpongycastleAsn1TspMessageImprint_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1TspMessageImprint *messageImprint, OrgSpongycastleAsn1ASN1ObjectIdentifier *tsaPolicy, OrgSpongycastleAsn1ASN1Integer *nonce, OrgSpongycastleAsn1ASN1Boolean *certReq, OrgSpongycastleAsn1X509Extensions *extensions) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1TspTimeStampReq, initWithOrgSpongycastleAsn1TspMessageImprint_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Integer_withOrgSpongycastleAsn1ASN1Boolean_withOrgSpongycastleAsn1X509Extensions_, messageImprint, tsaPolicy, nonce, certReq, extensions)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1TspTimeStampReq)
