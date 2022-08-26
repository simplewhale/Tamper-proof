//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmp/KeyRecRepContent.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/cmp/CMPCertificate.h"
#include "org/spongycastle/asn1/cmp/CertifiedKeyPair.h"
#include "org/spongycastle/asn1/cmp/KeyRecRepContent.h"
#include "org/spongycastle/asn1/cmp/PKIStatusInfo.h"

@interface OrgSpongycastleAsn1CmpKeyRecRepContent () {
 @public
  OrgSpongycastleAsn1CmpPKIStatusInfo *status_;
  OrgSpongycastleAsn1CmpCMPCertificate *newSigCert_;
  OrgSpongycastleAsn1ASN1Sequence *caCerts_;
  OrgSpongycastleAsn1ASN1Sequence *keyPairHist_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (void)addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v
                                                      withInt:(jint)tagNo
                         withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpKeyRecRepContent, status_, OrgSpongycastleAsn1CmpPKIStatusInfo *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpKeyRecRepContent, newSigCert_, OrgSpongycastleAsn1CmpCMPCertificate *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpKeyRecRepContent, caCerts_, OrgSpongycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmpKeyRecRepContent, keyPairHist_, OrgSpongycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void OrgSpongycastleAsn1CmpKeyRecRepContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmpKeyRecRepContent *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmpKeyRecRepContent *new_OrgSpongycastleAsn1CmpKeyRecRepContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmpKeyRecRepContent *create_OrgSpongycastleAsn1CmpKeyRecRepContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void OrgSpongycastleAsn1CmpKeyRecRepContent_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CmpKeyRecRepContent *self, OrgSpongycastleAsn1ASN1EncodableVector *v, jint tagNo, id<OrgSpongycastleAsn1ASN1Encodable> obj);

@implementation OrgSpongycastleAsn1CmpKeyRecRepContent

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmpKeyRecRepContent_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmpKeyRecRepContent *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmpKeyRecRepContent_getInstanceWithId_(o);
}

- (OrgSpongycastleAsn1CmpPKIStatusInfo *)getStatus {
  return status_;
}

- (OrgSpongycastleAsn1CmpCMPCertificate *)getNewSigCert {
  return newSigCert_;
}

- (IOSObjectArray *)getCaCerts {
  if (caCerts_ == nil) {
    return nil;
  }
  IOSObjectArray *results = [IOSObjectArray newArrayWithLength:[caCerts_ size] type:OrgSpongycastleAsn1CmpCMPCertificate_class_()];
  for (jint i = 0; i != results->size_; i++) {
    (void) IOSObjectArray_Set(results, i, OrgSpongycastleAsn1CmpCMPCertificate_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(caCerts_)) getObjectAtWithInt:i]));
  }
  return results;
}

- (IOSObjectArray *)getKeyPairHist {
  if (keyPairHist_ == nil) {
    return nil;
  }
  IOSObjectArray *results = [IOSObjectArray newArrayWithLength:[keyPairHist_ size] type:OrgSpongycastleAsn1CmpCertifiedKeyPair_class_()];
  for (jint i = 0; i != results->size_; i++) {
    (void) IOSObjectArray_Set(results, i, OrgSpongycastleAsn1CmpCertifiedKeyPair_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(keyPairHist_)) getObjectAtWithInt:i]));
  }
  return results;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:status_];
  OrgSpongycastleAsn1CmpKeyRecRepContent_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, 0, newSigCert_);
  OrgSpongycastleAsn1CmpKeyRecRepContent_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, 1, caCerts_);
  OrgSpongycastleAsn1CmpKeyRecRepContent_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, 2, keyPairHist_);
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

- (void)addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)v
                                                      withInt:(jint)tagNo
                         withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj {
  OrgSpongycastleAsn1CmpKeyRecRepContent_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(self, v, tagNo, obj);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmpKeyRecRepContent;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmpPKIStatusInfo;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmpCMPCertificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1CmpCMPCertificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1CmpCertifiedKeyPair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(getStatus);
  methods[3].selector = @selector(getNewSigCert);
  methods[4].selector = @selector(getCaCerts);
  methods[5].selector = @selector(getKeyPairHist);
  methods[6].selector = @selector(toASN1Primitive);
  methods[7].selector = @selector(addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector:withInt:withOrgSpongycastleAsn1ASN1Encodable:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "status_", "LOrgSpongycastleAsn1CmpPKIStatusInfo;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "newSigCert_", "LOrgSpongycastleAsn1CmpCMPCertificate;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "caCerts_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyPairHist_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "addOptional", "LOrgSpongycastleAsn1ASN1EncodableVector;ILOrgSpongycastleAsn1ASN1Encodable;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmpKeyRecRepContent = { "KeyRecRepContent", "org.spongycastle.asn1.cmp", ptrTable, methods, fields, 7, 0x1, 8, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmpKeyRecRepContent;
}

@end

void OrgSpongycastleAsn1CmpKeyRecRepContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmpKeyRecRepContent *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> en = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->status_ = OrgSpongycastleAsn1CmpPKIStatusInfo_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(en)) nextElement]);
  while ([en hasMoreElements]) {
    OrgSpongycastleAsn1ASN1TaggedObject *tObj = OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithId_([en nextElement]);
    switch ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(tObj)) getTagNo]) {
      case 0:
      self->newSigCert_ = OrgSpongycastleAsn1CmpCMPCertificate_getInstanceWithId_([tObj getObject]);
      break;
      case 1:
      self->caCerts_ = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_([tObj getObject]);
      break;
      case 2:
      self->keyPairHist_ = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_([tObj getObject]);
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown tag number: ", [tObj getTagNo]));
    }
  }
}

OrgSpongycastleAsn1CmpKeyRecRepContent *new_OrgSpongycastleAsn1CmpKeyRecRepContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmpKeyRecRepContent, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmpKeyRecRepContent *create_OrgSpongycastleAsn1CmpKeyRecRepContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmpKeyRecRepContent, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmpKeyRecRepContent *OrgSpongycastleAsn1CmpKeyRecRepContent_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmpKeyRecRepContent_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmpKeyRecRepContent class]]) {
    return (OrgSpongycastleAsn1CmpKeyRecRepContent *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmpKeyRecRepContent_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

void OrgSpongycastleAsn1CmpKeyRecRepContent_addOptionalWithOrgSpongycastleAsn1ASN1EncodableVector_withInt_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CmpKeyRecRepContent *self, OrgSpongycastleAsn1ASN1EncodableVector *v, jint tagNo, id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  if (obj != nil) {
    [((OrgSpongycastleAsn1ASN1EncodableVector *) nil_chk(v)) addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, tagNo, obj)];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmpKeyRecRepContent)
