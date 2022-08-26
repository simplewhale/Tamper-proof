//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/V2Form.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/x509/GeneralNames.h"
#include "org/spongycastle/asn1/x509/IssuerSerial.h"
#include "org/spongycastle/asn1/x509/ObjectDigestInfo.h"
#include "org/spongycastle/asn1/x509/V2Form.h"

@implementation OrgSpongycastleAsn1X509V2Form

+ (OrgSpongycastleAsn1X509V2Form *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                          withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1X509V2Form_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1X509V2Form *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509V2Form_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1X509GeneralNames:(OrgSpongycastleAsn1X509GeneralNames *)issuerName {
  OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_(self, issuerName);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509GeneralNames:(OrgSpongycastleAsn1X509GeneralNames *)issuerName
                    withOrgSpongycastleAsn1X509IssuerSerial:(OrgSpongycastleAsn1X509IssuerSerial *)baseCertificateID {
  OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_(self, issuerName, baseCertificateID);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509GeneralNames:(OrgSpongycastleAsn1X509GeneralNames *)issuerName
                withOrgSpongycastleAsn1X509ObjectDigestInfo:(OrgSpongycastleAsn1X509ObjectDigestInfo *)objectDigestInfo {
  OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509ObjectDigestInfo_(self, issuerName, objectDigestInfo);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509GeneralNames:(OrgSpongycastleAsn1X509GeneralNames *)issuerName
                    withOrgSpongycastleAsn1X509IssuerSerial:(OrgSpongycastleAsn1X509IssuerSerial *)baseCertificateID
                withOrgSpongycastleAsn1X509ObjectDigestInfo:(OrgSpongycastleAsn1X509ObjectDigestInfo *)objectDigestInfo {
  OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_(self, issuerName, baseCertificateID, objectDigestInfo);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (OrgSpongycastleAsn1X509GeneralNames *)getIssuerName {
  return issuerName_;
}

- (OrgSpongycastleAsn1X509IssuerSerial *)getBaseCertificateID {
  return baseCertificateID_;
}

- (OrgSpongycastleAsn1X509ObjectDigestInfo *)getObjectDigestInfo {
  return objectDigestInfo_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  if (issuerName_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:issuerName_];
  }
  if (baseCertificateID_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, baseCertificateID_)];
  }
  if (objectDigestInfo_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 1, objectDigestInfo_)];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1X509V2Form;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509V2Form;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 6, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509GeneralNames;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509IssuerSerial;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509ObjectDigestInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509GeneralNames:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1X509GeneralNames:withOrgSpongycastleAsn1X509IssuerSerial:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1X509GeneralNames:withOrgSpongycastleAsn1X509ObjectDigestInfo:);
  methods[5].selector = @selector(initWithOrgSpongycastleAsn1X509GeneralNames:withOrgSpongycastleAsn1X509IssuerSerial:withOrgSpongycastleAsn1X509ObjectDigestInfo:);
  methods[6].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[7].selector = @selector(getIssuerName);
  methods[8].selector = @selector(getBaseCertificateID);
  methods[9].selector = @selector(getObjectDigestInfo);
  methods[10].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "issuerName_", "LOrgSpongycastleAsn1X509GeneralNames;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "baseCertificateID_", "LOrgSpongycastleAsn1X509IssuerSerial;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "objectDigestInfo_", "LOrgSpongycastleAsn1X509ObjectDigestInfo;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LOrgSpongycastleAsn1X509GeneralNames;", "LOrgSpongycastleAsn1X509GeneralNames;LOrgSpongycastleAsn1X509IssuerSerial;", "LOrgSpongycastleAsn1X509GeneralNames;LOrgSpongycastleAsn1X509ObjectDigestInfo;", "LOrgSpongycastleAsn1X509GeneralNames;LOrgSpongycastleAsn1X509IssuerSerial;LOrgSpongycastleAsn1X509ObjectDigestInfo;", "LOrgSpongycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509V2Form = { "V2Form", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 11, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509V2Form;
}

@end

OrgSpongycastleAsn1X509V2Form *OrgSpongycastleAsn1X509V2Form_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1X509V2Form_initialize();
  return OrgSpongycastleAsn1X509V2Form_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1X509V2Form *OrgSpongycastleAsn1X509V2Form_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509V2Form_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1X509V2Form class]]) {
    return (OrgSpongycastleAsn1X509V2Form *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_(OrgSpongycastleAsn1X509V2Form *self, OrgSpongycastleAsn1X509GeneralNames *issuerName) {
  OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_(self, issuerName, nil, nil);
}

OrgSpongycastleAsn1X509V2Form *new_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_(OrgSpongycastleAsn1X509GeneralNames *issuerName) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1X509GeneralNames_, issuerName)
}

OrgSpongycastleAsn1X509V2Form *create_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_(OrgSpongycastleAsn1X509GeneralNames *issuerName) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1X509GeneralNames_, issuerName)
}

void OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_(OrgSpongycastleAsn1X509V2Form *self, OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509IssuerSerial *baseCertificateID) {
  OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_(self, issuerName, baseCertificateID, nil);
}

OrgSpongycastleAsn1X509V2Form *new_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_(OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509IssuerSerial *baseCertificateID) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_, issuerName, baseCertificateID)
}

OrgSpongycastleAsn1X509V2Form *create_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_(OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509IssuerSerial *baseCertificateID) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_, issuerName, baseCertificateID)
}

void OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509ObjectDigestInfo_(OrgSpongycastleAsn1X509V2Form *self, OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509ObjectDigestInfo *objectDigestInfo) {
  OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_(self, issuerName, nil, objectDigestInfo);
}

OrgSpongycastleAsn1X509V2Form *new_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509ObjectDigestInfo_(OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509ObjectDigestInfo *objectDigestInfo) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509ObjectDigestInfo_, issuerName, objectDigestInfo)
}

OrgSpongycastleAsn1X509V2Form *create_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509ObjectDigestInfo_(OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509ObjectDigestInfo *objectDigestInfo) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509ObjectDigestInfo_, issuerName, objectDigestInfo)
}

void OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_(OrgSpongycastleAsn1X509V2Form *self, OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509IssuerSerial *baseCertificateID, OrgSpongycastleAsn1X509ObjectDigestInfo *objectDigestInfo) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->issuerName_ = issuerName;
  self->baseCertificateID_ = baseCertificateID;
  self->objectDigestInfo_ = objectDigestInfo;
}

OrgSpongycastleAsn1X509V2Form *new_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_(OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509IssuerSerial *baseCertificateID, OrgSpongycastleAsn1X509ObjectDigestInfo *objectDigestInfo) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_, issuerName, baseCertificateID, objectDigestInfo)
}

OrgSpongycastleAsn1X509V2Form *create_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_(OrgSpongycastleAsn1X509GeneralNames *issuerName, OrgSpongycastleAsn1X509IssuerSerial *baseCertificateID, OrgSpongycastleAsn1X509ObjectDigestInfo *objectDigestInfo) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1X509GeneralNames_withOrgSpongycastleAsn1X509IssuerSerial_withOrgSpongycastleAsn1X509ObjectDigestInfo_, issuerName, baseCertificateID, objectDigestInfo)
}

void OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509V2Form *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] > 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  jint index = 0;
  if (!([[seq getObjectAtWithInt:0] isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]])) {
    index++;
    self->issuerName_ = OrgSpongycastleAsn1X509GeneralNames_getInstanceWithId_([seq getObjectAtWithInt:0]);
  }
  for (jint i = index; i != [seq size]; i++) {
    OrgSpongycastleAsn1ASN1TaggedObject *o = OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithId_([seq getObjectAtWithInt:i]);
    if ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo] == 0) {
      self->baseCertificateID_ = OrgSpongycastleAsn1X509IssuerSerial_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false);
    }
    else if ([o getTagNo] == 1) {
      self->objectDigestInfo_ = OrgSpongycastleAsn1X509ObjectDigestInfo_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false);
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad tag number: ", [o getTagNo]));
    }
  }
}

OrgSpongycastleAsn1X509V2Form *new_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509V2Form *create_OrgSpongycastleAsn1X509V2Form_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509V2Form, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509V2Form)
