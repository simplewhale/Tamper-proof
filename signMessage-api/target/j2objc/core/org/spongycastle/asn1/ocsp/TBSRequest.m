//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ocsp/TBSRequest.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/ocsp/TBSRequest.h"
#include "org/spongycastle/asn1/x509/Extensions.h"
#include "org/spongycastle/asn1/x509/GeneralName.h"
#include "org/spongycastle/asn1/x509/X509Extensions.h"

@interface OrgSpongycastleAsn1OcspTBSRequest ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

inline OrgSpongycastleAsn1ASN1Integer *OrgSpongycastleAsn1OcspTBSRequest_get_V1(void);
static OrgSpongycastleAsn1ASN1Integer *OrgSpongycastleAsn1OcspTBSRequest_V1;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleAsn1OcspTBSRequest, V1, OrgSpongycastleAsn1ASN1Integer *)

__attribute__((unused)) static void OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1OcspTBSRequest *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1OcspTBSRequest *new_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1OcspTBSRequest *create_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleAsn1OcspTBSRequest)

@implementation OrgSpongycastleAsn1OcspTBSRequest

- (instancetype)initWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)requestorName
                       withOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)requestList
                 withOrgSpongycastleAsn1X509X509Extensions:(OrgSpongycastleAsn1X509X509Extensions *)requestExtensions {
  OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509X509Extensions_(self, requestorName, requestList, requestExtensions);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509GeneralName:(OrgSpongycastleAsn1X509GeneralName *)requestorName
                       withOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)requestList
                     withOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)requestExtensions {
  OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509Extensions_(self, requestorName, requestList, requestExtensions);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1OcspTBSRequest *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                              withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1OcspTBSRequest_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1OcspTBSRequest *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1OcspTBSRequest_getInstanceWithId_(obj);
}

- (OrgSpongycastleAsn1ASN1Integer *)getVersion {
  return version__;
}

- (OrgSpongycastleAsn1X509GeneralName *)getRequestorName {
  return requestorName_;
}

- (OrgSpongycastleAsn1ASN1Sequence *)getRequestList {
  return requestList_;
}

- (OrgSpongycastleAsn1X509Extensions *)getRequestExtensions {
  return requestExtensions_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  if (![((OrgSpongycastleAsn1ASN1Integer *) nil_chk(version__)) isEqual:OrgSpongycastleAsn1OcspTBSRequest_V1] || versionSet_) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 0, version__)];
  }
  if (requestorName_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 1, requestorName_)];
  }
  [v addWithOrgSpongycastleAsn1ASN1Encodable:requestList_];
  if (requestExtensions_ != nil) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 2, requestExtensions_)];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1OcspTBSRequest;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1OcspTBSRequest;", 0x9, 3, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509GeneralName;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Sequence;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509Extensions;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1X509GeneralName:withOrgSpongycastleAsn1ASN1Sequence:withOrgSpongycastleAsn1X509X509Extensions:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1X509GeneralName:withOrgSpongycastleAsn1ASN1Sequence:withOrgSpongycastleAsn1X509Extensions:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[4].selector = @selector(getInstanceWithId:);
  methods[5].selector = @selector(getVersion);
  methods[6].selector = @selector(getRequestorName);
  methods[7].selector = @selector(getRequestList);
  methods[8].selector = @selector(getRequestExtensions);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "V1", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x1a, -1, 6, -1, -1 },
    { "version__", "LOrgSpongycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, 7, -1, -1, -1 },
    { "requestorName_", "LOrgSpongycastleAsn1X509GeneralName;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "requestList_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "requestExtensions_", "LOrgSpongycastleAsn1X509Extensions;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "versionSet_", "Z", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1X509GeneralName;LOrgSpongycastleAsn1ASN1Sequence;LOrgSpongycastleAsn1X509X509Extensions;", "LOrgSpongycastleAsn1X509GeneralName;LOrgSpongycastleAsn1ASN1Sequence;LOrgSpongycastleAsn1X509Extensions;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", &OrgSpongycastleAsn1OcspTBSRequest_V1, "version" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1OcspTBSRequest = { "TBSRequest", "org.spongycastle.asn1.ocsp", ptrTable, methods, fields, 7, 0x1, 10, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1OcspTBSRequest;
}

+ (void)initialize {
  if (self == [OrgSpongycastleAsn1OcspTBSRequest class]) {
    OrgSpongycastleAsn1OcspTBSRequest_V1 = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(0);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleAsn1OcspTBSRequest)
  }
}

@end

void OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1OcspTBSRequest *self, OrgSpongycastleAsn1X509GeneralName *requestorName, OrgSpongycastleAsn1ASN1Sequence *requestList, OrgSpongycastleAsn1X509X509Extensions *requestExtensions) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->version__ = OrgSpongycastleAsn1OcspTBSRequest_V1;
  self->requestorName_ = requestorName;
  self->requestList_ = requestList;
  self->requestExtensions_ = OrgSpongycastleAsn1X509Extensions_getInstanceWithId_(requestExtensions);
}

OrgSpongycastleAsn1OcspTBSRequest *new_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1X509GeneralName *requestorName, OrgSpongycastleAsn1ASN1Sequence *requestList, OrgSpongycastleAsn1X509X509Extensions *requestExtensions) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1OcspTBSRequest, initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509X509Extensions_, requestorName, requestList, requestExtensions)
}

OrgSpongycastleAsn1OcspTBSRequest *create_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509X509Extensions_(OrgSpongycastleAsn1X509GeneralName *requestorName, OrgSpongycastleAsn1ASN1Sequence *requestList, OrgSpongycastleAsn1X509X509Extensions *requestExtensions) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1OcspTBSRequest, initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509X509Extensions_, requestorName, requestList, requestExtensions)
}

void OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1OcspTBSRequest *self, OrgSpongycastleAsn1X509GeneralName *requestorName, OrgSpongycastleAsn1ASN1Sequence *requestList, OrgSpongycastleAsn1X509Extensions *requestExtensions) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->version__ = OrgSpongycastleAsn1OcspTBSRequest_V1;
  self->requestorName_ = requestorName;
  self->requestList_ = requestList;
  self->requestExtensions_ = requestExtensions;
}

OrgSpongycastleAsn1OcspTBSRequest *new_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1X509GeneralName *requestorName, OrgSpongycastleAsn1ASN1Sequence *requestList, OrgSpongycastleAsn1X509Extensions *requestExtensions) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1OcspTBSRequest, initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509Extensions_, requestorName, requestList, requestExtensions)
}

OrgSpongycastleAsn1OcspTBSRequest *create_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1X509GeneralName *requestorName, OrgSpongycastleAsn1ASN1Sequence *requestList, OrgSpongycastleAsn1X509Extensions *requestExtensions) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1OcspTBSRequest, initWithOrgSpongycastleAsn1X509GeneralName_withOrgSpongycastleAsn1ASN1Sequence_withOrgSpongycastleAsn1X509Extensions_, requestorName, requestList, requestExtensions)
}

void OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1OcspTBSRequest *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  jint index = 0;
  if ([[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0] isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    OrgSpongycastleAsn1ASN1TaggedObject *o = (OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:0], [OrgSpongycastleAsn1ASN1TaggedObject class]);
    if ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo] == 0) {
      self->versionSet_ = true;
      self->version__ = OrgSpongycastleAsn1ASN1Integer_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:0], [OrgSpongycastleAsn1ASN1TaggedObject class]), true);
      index++;
    }
    else {
      self->version__ = OrgSpongycastleAsn1OcspTBSRequest_V1;
    }
  }
  else {
    self->version__ = OrgSpongycastleAsn1OcspTBSRequest_V1;
  }
  if ([[seq getObjectAtWithInt:index] isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    self->requestorName_ = OrgSpongycastleAsn1X509GeneralName_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:index++], [OrgSpongycastleAsn1ASN1TaggedObject class]), true);
  }
  self->requestList_ = (OrgSpongycastleAsn1ASN1Sequence *) cast_chk([seq getObjectAtWithInt:index++], [OrgSpongycastleAsn1ASN1Sequence class]);
  if ([seq size] == (index + 1)) {
    self->requestExtensions_ = OrgSpongycastleAsn1X509Extensions_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_((OrgSpongycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:index], [OrgSpongycastleAsn1ASN1TaggedObject class]), true);
  }
}

OrgSpongycastleAsn1OcspTBSRequest *new_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1OcspTBSRequest, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1OcspTBSRequest *create_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1OcspTBSRequest, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1OcspTBSRequest *OrgSpongycastleAsn1OcspTBSRequest_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1OcspTBSRequest_initialize();
  return OrgSpongycastleAsn1OcspTBSRequest_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1OcspTBSRequest *OrgSpongycastleAsn1OcspTBSRequest_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1OcspTBSRequest_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1OcspTBSRequest class]]) {
    return (OrgSpongycastleAsn1OcspTBSRequest *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1OcspTBSRequest_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1OcspTBSRequest)
