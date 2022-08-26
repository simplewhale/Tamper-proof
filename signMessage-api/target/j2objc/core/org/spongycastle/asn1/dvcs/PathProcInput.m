//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/dvcs/PathProcInput.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Arrays.h"
#include "java/util/List.h"
#include "org/spongycastle/asn1/ASN1Boolean.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/dvcs/PathProcInput.h"
#include "org/spongycastle/asn1/x509/PolicyInformation.h"

@interface OrgSpongycastleAsn1DvcsPathProcInput () {
 @public
  IOSObjectArray *acceptablePolicySet_;
  jboolean inhibitPolicyMapping_;
  jboolean explicitPolicyReqd_;
  jboolean inhibitAnyPolicy_;
}

+ (IOSObjectArray *)fromSequenceWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (void)setInhibitPolicyMappingWithBoolean:(jboolean)inhibitPolicyMapping;

- (void)setExplicitPolicyReqdWithBoolean:(jboolean)explicitPolicyReqd;

- (void)setInhibitAnyPolicyWithBoolean:(jboolean)inhibitAnyPolicy;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DvcsPathProcInput, acceptablePolicySet_, IOSObjectArray *)

__attribute__((unused)) static IOSObjectArray *OrgSpongycastleAsn1DvcsPathProcInput_fromSequenceWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void OrgSpongycastleAsn1DvcsPathProcInput_setInhibitPolicyMappingWithBoolean_(OrgSpongycastleAsn1DvcsPathProcInput *self, jboolean inhibitPolicyMapping);

__attribute__((unused)) static void OrgSpongycastleAsn1DvcsPathProcInput_setExplicitPolicyReqdWithBoolean_(OrgSpongycastleAsn1DvcsPathProcInput *self, jboolean explicitPolicyReqd);

__attribute__((unused)) static void OrgSpongycastleAsn1DvcsPathProcInput_setInhibitAnyPolicyWithBoolean_(OrgSpongycastleAsn1DvcsPathProcInput *self, jboolean inhibitAnyPolicy);

@implementation OrgSpongycastleAsn1DvcsPathProcInput

- (instancetype)initWithOrgSpongycastleAsn1X509PolicyInformationArray:(IOSObjectArray *)acceptablePolicySet {
  OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_(self, acceptablePolicySet);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509PolicyInformationArray:(IOSObjectArray *)acceptablePolicySet
                                                          withBoolean:(jboolean)inhibitPolicyMapping
                                                          withBoolean:(jboolean)explicitPolicyReqd
                                                          withBoolean:(jboolean)inhibitAnyPolicy {
  OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_withBoolean_withBoolean_withBoolean_(self, acceptablePolicySet, inhibitPolicyMapping, explicitPolicyReqd, inhibitAnyPolicy);
  return self;
}

+ (IOSObjectArray *)fromSequenceWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  return OrgSpongycastleAsn1DvcsPathProcInput_fromSequenceWithOrgSpongycastleAsn1ASN1Sequence_(seq);
}

+ (OrgSpongycastleAsn1DvcsPathProcInput *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1DvcsPathProcInput_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1DvcsPathProcInput *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                 withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1DvcsPathProcInput_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  OrgSpongycastleAsn1ASN1EncodableVector *pV = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(acceptablePolicySet_))->size_; i++) {
    [pV addWithOrgSpongycastleAsn1ASN1Encodable:IOSObjectArray_Get(acceptablePolicySet_, i)];
  }
  [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(pV)];
  if (inhibitPolicyMapping_) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:OrgSpongycastleAsn1ASN1Boolean_getInstanceWithBoolean_(inhibitPolicyMapping_)];
  }
  if (explicitPolicyReqd_) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, OrgSpongycastleAsn1ASN1Boolean_getInstanceWithBoolean_(explicitPolicyReqd_))];
  }
  if (inhibitAnyPolicy_) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 1, OrgSpongycastleAsn1ASN1Boolean_getInstanceWithBoolean_(inhibitAnyPolicy_))];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

- (NSString *)description {
  return JreStrcat("$@$Z$Z$Z$", @"PathProcInput: {\nacceptablePolicySet: ", JavaUtilArrays_asListWithNSObjectArray_(acceptablePolicySet_), @"\ninhibitPolicyMapping: ", inhibitPolicyMapping_, @"\nexplicitPolicyReqd: ", explicitPolicyReqd_, @"\ninhibitAnyPolicy: ", inhibitAnyPolicy_, @"\n}\n");
}

- (IOSObjectArray *)getAcceptablePolicySet {
  return acceptablePolicySet_;
}

- (jboolean)isInhibitPolicyMapping {
  return inhibitPolicyMapping_;
}

- (void)setInhibitPolicyMappingWithBoolean:(jboolean)inhibitPolicyMapping {
  OrgSpongycastleAsn1DvcsPathProcInput_setInhibitPolicyMappingWithBoolean_(self, inhibitPolicyMapping);
}

- (jboolean)isExplicitPolicyReqd {
  return explicitPolicyReqd_;
}

- (void)setExplicitPolicyReqdWithBoolean:(jboolean)explicitPolicyReqd {
  OrgSpongycastleAsn1DvcsPathProcInput_setExplicitPolicyReqdWithBoolean_(self, explicitPolicyReqd);
}

- (jboolean)isInhibitAnyPolicy {
  return inhibitAnyPolicy_;
}

- (void)setInhibitAnyPolicyWithBoolean:(jboolean)inhibitAnyPolicy {
  OrgSpongycastleAsn1DvcsPathProcInput_setInhibitAnyPolicyWithBoolean_(self, inhibitAnyPolicy);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1X509PolicyInformation;", 0xa, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DvcsPathProcInput;", 0x9, 4, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DvcsPathProcInput;", 0x9, 4, 6, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 7, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1X509PolicyInformation;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 10, 9, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 11, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1X509PolicyInformationArray:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1X509PolicyInformationArray:withBoolean:withBoolean:withBoolean:);
  methods[2].selector = @selector(fromSequenceWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[5].selector = @selector(toASN1Primitive);
  methods[6].selector = @selector(description);
  methods[7].selector = @selector(getAcceptablePolicySet);
  methods[8].selector = @selector(isInhibitPolicyMapping);
  methods[9].selector = @selector(setInhibitPolicyMappingWithBoolean:);
  methods[10].selector = @selector(isExplicitPolicyReqd);
  methods[11].selector = @selector(setExplicitPolicyReqdWithBoolean:);
  methods[12].selector = @selector(isInhibitAnyPolicy);
  methods[13].selector = @selector(setInhibitAnyPolicyWithBoolean:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "acceptablePolicySet_", "[LOrgSpongycastleAsn1X509PolicyInformation;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "inhibitPolicyMapping_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "explicitPolicyReqd_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "inhibitAnyPolicy_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[LOrgSpongycastleAsn1X509PolicyInformation;", "[LOrgSpongycastleAsn1X509PolicyInformation;ZZZ", "fromSequence", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "toString", "setInhibitPolicyMapping", "Z", "setExplicitPolicyReqd", "setInhibitAnyPolicy" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1DvcsPathProcInput = { "PathProcInput", "org.spongycastle.asn1.dvcs", ptrTable, methods, fields, 7, 0x1, 14, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1DvcsPathProcInput;
}

@end

void OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_(OrgSpongycastleAsn1DvcsPathProcInput *self, IOSObjectArray *acceptablePolicySet) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->inhibitPolicyMapping_ = false;
  self->explicitPolicyReqd_ = false;
  self->inhibitAnyPolicy_ = false;
  self->acceptablePolicySet_ = acceptablePolicySet;
}

OrgSpongycastleAsn1DvcsPathProcInput *new_OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_(IOSObjectArray *acceptablePolicySet) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DvcsPathProcInput, initWithOrgSpongycastleAsn1X509PolicyInformationArray_, acceptablePolicySet)
}

OrgSpongycastleAsn1DvcsPathProcInput *create_OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_(IOSObjectArray *acceptablePolicySet) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DvcsPathProcInput, initWithOrgSpongycastleAsn1X509PolicyInformationArray_, acceptablePolicySet)
}

void OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_withBoolean_withBoolean_withBoolean_(OrgSpongycastleAsn1DvcsPathProcInput *self, IOSObjectArray *acceptablePolicySet, jboolean inhibitPolicyMapping, jboolean explicitPolicyReqd, jboolean inhibitAnyPolicy) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->inhibitPolicyMapping_ = false;
  self->explicitPolicyReqd_ = false;
  self->inhibitAnyPolicy_ = false;
  self->acceptablePolicySet_ = acceptablePolicySet;
  self->inhibitPolicyMapping_ = inhibitPolicyMapping;
  self->explicitPolicyReqd_ = explicitPolicyReqd;
  self->inhibitAnyPolicy_ = inhibitAnyPolicy;
}

OrgSpongycastleAsn1DvcsPathProcInput *new_OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_withBoolean_withBoolean_withBoolean_(IOSObjectArray *acceptablePolicySet, jboolean inhibitPolicyMapping, jboolean explicitPolicyReqd, jboolean inhibitAnyPolicy) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DvcsPathProcInput, initWithOrgSpongycastleAsn1X509PolicyInformationArray_withBoolean_withBoolean_withBoolean_, acceptablePolicySet, inhibitPolicyMapping, explicitPolicyReqd, inhibitAnyPolicy)
}

OrgSpongycastleAsn1DvcsPathProcInput *create_OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_withBoolean_withBoolean_withBoolean_(IOSObjectArray *acceptablePolicySet, jboolean inhibitPolicyMapping, jboolean explicitPolicyReqd, jboolean inhibitAnyPolicy) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DvcsPathProcInput, initWithOrgSpongycastleAsn1X509PolicyInformationArray_withBoolean_withBoolean_withBoolean_, acceptablePolicySet, inhibitPolicyMapping, explicitPolicyReqd, inhibitAnyPolicy)
}

IOSObjectArray *OrgSpongycastleAsn1DvcsPathProcInput_fromSequenceWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1DvcsPathProcInput_initialize();
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] type:OrgSpongycastleAsn1X509PolicyInformation_class_()];
  for (jint i = 0; i != tmp->size_; i++) {
    (void) IOSObjectArray_Set(tmp, i, OrgSpongycastleAsn1X509PolicyInformation_getInstanceWithId_([seq getObjectAtWithInt:i]));
  }
  return tmp;
}

OrgSpongycastleAsn1DvcsPathProcInput *OrgSpongycastleAsn1DvcsPathProcInput_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1DvcsPathProcInput_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1DvcsPathProcInput class]]) {
    return (OrgSpongycastleAsn1DvcsPathProcInput *) obj;
  }
  else if (obj != nil) {
    OrgSpongycastleAsn1ASN1Sequence *seq = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj);
    OrgSpongycastleAsn1ASN1Sequence *policies = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]);
    OrgSpongycastleAsn1DvcsPathProcInput *result = new_OrgSpongycastleAsn1DvcsPathProcInput_initWithOrgSpongycastleAsn1X509PolicyInformationArray_(OrgSpongycastleAsn1DvcsPathProcInput_fromSequenceWithOrgSpongycastleAsn1ASN1Sequence_(policies));
    for (jint i = 1; i < [seq size]; i++) {
      id o = [seq getObjectAtWithInt:i];
      if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1Boolean class]]) {
        OrgSpongycastleAsn1ASN1Boolean *x = OrgSpongycastleAsn1ASN1Boolean_getInstanceWithId_(o);
        OrgSpongycastleAsn1DvcsPathProcInput_setInhibitPolicyMappingWithBoolean_(result, [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(x)) isTrue]);
      }
      else if ([o isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
        OrgSpongycastleAsn1ASN1TaggedObject *t = OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithId_(o);
        OrgSpongycastleAsn1ASN1Boolean *x;
        switch ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(t)) getTagNo]) {
          case 0:
          x = OrgSpongycastleAsn1ASN1Boolean_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
          OrgSpongycastleAsn1DvcsPathProcInput_setExplicitPolicyReqdWithBoolean_(result, [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(x)) isTrue]);
          break;
          case 1:
          x = OrgSpongycastleAsn1ASN1Boolean_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(t, false);
          OrgSpongycastleAsn1DvcsPathProcInput_setInhibitAnyPolicyWithBoolean_(result, [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(x)) isTrue]);
          break;
          default:
          @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Unknown tag encountered: ", [t getTagNo]));
        }
      }
    }
    return result;
  }
  return nil;
}

OrgSpongycastleAsn1DvcsPathProcInput *OrgSpongycastleAsn1DvcsPathProcInput_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1DvcsPathProcInput_initialize();
  return OrgSpongycastleAsn1DvcsPathProcInput_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

void OrgSpongycastleAsn1DvcsPathProcInput_setInhibitPolicyMappingWithBoolean_(OrgSpongycastleAsn1DvcsPathProcInput *self, jboolean inhibitPolicyMapping) {
  self->inhibitPolicyMapping_ = inhibitPolicyMapping;
}

void OrgSpongycastleAsn1DvcsPathProcInput_setExplicitPolicyReqdWithBoolean_(OrgSpongycastleAsn1DvcsPathProcInput *self, jboolean explicitPolicyReqd) {
  self->explicitPolicyReqd_ = explicitPolicyReqd;
}

void OrgSpongycastleAsn1DvcsPathProcInput_setInhibitAnyPolicyWithBoolean_(OrgSpongycastleAsn1DvcsPathProcInput *self, jboolean inhibitAnyPolicy) {
  self->inhibitAnyPolicy_ = inhibitAnyPolicy;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1DvcsPathProcInput)
