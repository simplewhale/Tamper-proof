//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/IssuingDistributionPoint.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/StringBuffer.h"
#include "org/spongycastle/asn1/ASN1Boolean.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERBitString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/x509/DistributionPointName.h"
#include "org/spongycastle/asn1/x509/IssuingDistributionPoint.h"
#include "org/spongycastle/asn1/x509/ReasonFlags.h"
#include "org/spongycastle/util/Strings.h"

@interface OrgSpongycastleAsn1X509IssuingDistributionPoint () {
 @public
  OrgSpongycastleAsn1X509DistributionPointName *distributionPoint_;
  jboolean onlyContainsUserCerts_;
  jboolean onlyContainsCACerts_;
  OrgSpongycastleAsn1X509ReasonFlags *onlySomeReasons_;
  jboolean indirectCRL_;
  jboolean onlyContainsAttributeCerts_;
  OrgSpongycastleAsn1ASN1Sequence *seq_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

- (void)appendObjectWithJavaLangStringBuffer:(JavaLangStringBuffer *)buf
                                withNSString:(NSString *)sep
                                withNSString:(NSString *)name
                                withNSString:(NSString *)value;

- (NSString *)booleanToStringWithBoolean:(jboolean)value;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509IssuingDistributionPoint, distributionPoint_, OrgSpongycastleAsn1X509DistributionPointName *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509IssuingDistributionPoint, onlySomeReasons_, OrgSpongycastleAsn1X509ReasonFlags *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509IssuingDistributionPoint, seq_, OrgSpongycastleAsn1ASN1Sequence *)

__attribute__((unused)) static void OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X509IssuingDistributionPoint *new_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509IssuingDistributionPoint *create_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static void OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, JavaLangStringBuffer *buf, NSString *sep, NSString *name, NSString *value);

__attribute__((unused)) static NSString *OrgSpongycastleAsn1X509IssuingDistributionPoint_booleanToStringWithBoolean_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, jboolean value);

@implementation OrgSpongycastleAsn1X509IssuingDistributionPoint

+ (OrgSpongycastleAsn1X509IssuingDistributionPoint *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                            withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1X509IssuingDistributionPoint_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1X509IssuingDistributionPoint *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509IssuingDistributionPoint_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1X509DistributionPointName:(OrgSpongycastleAsn1X509DistributionPointName *)distributionPoint
                                                         withBoolean:(jboolean)onlyContainsUserCerts
                                                         withBoolean:(jboolean)onlyContainsCACerts
                              withOrgSpongycastleAsn1X509ReasonFlags:(OrgSpongycastleAsn1X509ReasonFlags *)onlySomeReasons
                                                         withBoolean:(jboolean)indirectCRL
                                                         withBoolean:(jboolean)onlyContainsAttributeCerts {
  OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(self, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509DistributionPointName:(OrgSpongycastleAsn1X509DistributionPointName *)distributionPoint
                                                         withBoolean:(jboolean)indirectCRL
                                                         withBoolean:(jboolean)onlyContainsAttributeCerts {
  OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(self, distributionPoint, indirectCRL, onlyContainsAttributeCerts);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (jboolean)onlyContainsUserCerts {
  return onlyContainsUserCerts_;
}

- (jboolean)onlyContainsCACerts {
  return onlyContainsCACerts_;
}

- (jboolean)isIndirectCRL {
  return indirectCRL_;
}

- (jboolean)onlyContainsAttributeCerts {
  return onlyContainsAttributeCerts_;
}

- (OrgSpongycastleAsn1X509DistributionPointName *)getDistributionPoint {
  return distributionPoint_;
}

- (OrgSpongycastleAsn1X509ReasonFlags *)getOnlySomeReasons {
  return onlySomeReasons_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return seq_;
}

- (NSString *)description {
  NSString *sep = OrgSpongycastleUtilStrings_lineSeparator();
  JavaLangStringBuffer *buf = new_JavaLangStringBuffer_init();
  (void) [buf appendWithNSString:@"IssuingDistributionPoint: ["];
  (void) [buf appendWithNSString:sep];
  if (distributionPoint_ != nil) {
    OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(self, buf, sep, @"distributionPoint", [distributionPoint_ description]);
  }
  if (onlyContainsUserCerts_) {
    OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(self, buf, sep, @"onlyContainsUserCerts", OrgSpongycastleAsn1X509IssuingDistributionPoint_booleanToStringWithBoolean_(self, onlyContainsUserCerts_));
  }
  if (onlyContainsCACerts_) {
    OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(self, buf, sep, @"onlyContainsCACerts", OrgSpongycastleAsn1X509IssuingDistributionPoint_booleanToStringWithBoolean_(self, onlyContainsCACerts_));
  }
  if (onlySomeReasons_ != nil) {
    OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(self, buf, sep, @"onlySomeReasons", [onlySomeReasons_ description]);
  }
  if (onlyContainsAttributeCerts_) {
    OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(self, buf, sep, @"onlyContainsAttributeCerts", OrgSpongycastleAsn1X509IssuingDistributionPoint_booleanToStringWithBoolean_(self, onlyContainsAttributeCerts_));
  }
  if (indirectCRL_) {
    OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(self, buf, sep, @"indirectCRL", OrgSpongycastleAsn1X509IssuingDistributionPoint_booleanToStringWithBoolean_(self, indirectCRL_));
  }
  (void) [buf appendWithNSString:@"]"];
  (void) [buf appendWithNSString:sep];
  return [buf description];
}

- (void)appendObjectWithJavaLangStringBuffer:(JavaLangStringBuffer *)buf
                                withNSString:(NSString *)sep
                                withNSString:(NSString *)name
                                withNSString:(NSString *)value {
  OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(self, buf, sep, name, value);
}

- (NSString *)booleanToStringWithBoolean:(jboolean)value {
  return OrgSpongycastleAsn1X509IssuingDistributionPoint_booleanToStringWithBoolean_(self, value);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1X509IssuingDistributionPoint;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509IssuingDistributionPoint;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509DistributionPointName;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509ReasonFlags;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 6, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 7, 8, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x2, 9, 10, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509DistributionPointName:withBoolean:withBoolean:withOrgSpongycastleAsn1X509ReasonFlags:withBoolean:withBoolean:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1X509DistributionPointName:withBoolean:withBoolean:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(onlyContainsUserCerts);
  methods[6].selector = @selector(onlyContainsCACerts);
  methods[7].selector = @selector(isIndirectCRL);
  methods[8].selector = @selector(onlyContainsAttributeCerts);
  methods[9].selector = @selector(getDistributionPoint);
  methods[10].selector = @selector(getOnlySomeReasons);
  methods[11].selector = @selector(toASN1Primitive);
  methods[12].selector = @selector(description);
  methods[13].selector = @selector(appendObjectWithJavaLangStringBuffer:withNSString:withNSString:withNSString:);
  methods[14].selector = @selector(booleanToStringWithBoolean:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "distributionPoint_", "LOrgSpongycastleAsn1X509DistributionPointName;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "onlyContainsUserCerts_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "onlyContainsCACerts_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "onlySomeReasons_", "LOrgSpongycastleAsn1X509ReasonFlags;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "indirectCRL_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "onlyContainsAttributeCerts_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "seq_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LOrgSpongycastleAsn1X509DistributionPointName;ZZLOrgSpongycastleAsn1X509ReasonFlags;ZZ", "LOrgSpongycastleAsn1X509DistributionPointName;ZZ", "LOrgSpongycastleAsn1ASN1Sequence;", "toString", "appendObject", "LJavaLangStringBuffer;LNSString;LNSString;LNSString;", "booleanToString", "Z" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509IssuingDistributionPoint = { "IssuingDistributionPoint", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 15, 7, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509IssuingDistributionPoint;
}

@end

OrgSpongycastleAsn1X509IssuingDistributionPoint *OrgSpongycastleAsn1X509IssuingDistributionPoint_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1X509IssuingDistributionPoint_initialize();
  return OrgSpongycastleAsn1X509IssuingDistributionPoint_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1X509IssuingDistributionPoint *OrgSpongycastleAsn1X509IssuingDistributionPoint_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509IssuingDistributionPoint_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1X509IssuingDistributionPoint class]]) {
    return (OrgSpongycastleAsn1X509IssuingDistributionPoint *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, OrgSpongycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->distributionPoint_ = distributionPoint;
  self->indirectCRL_ = indirectCRL;
  self->onlyContainsAttributeCerts_ = onlyContainsAttributeCerts;
  self->onlyContainsCACerts_ = onlyContainsCACerts;
  self->onlyContainsUserCerts_ = onlyContainsUserCerts;
  self->onlySomeReasons_ = onlySomeReasons;
  OrgSpongycastleAsn1ASN1EncodableVector *vec = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  if (distributionPoint != nil) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 0, distributionPoint)];
  }
  if (onlyContainsUserCerts) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 1, OrgSpongycastleAsn1ASN1Boolean_getInstanceWithBoolean_(true))];
  }
  if (onlyContainsCACerts) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 2, OrgSpongycastleAsn1ASN1Boolean_getInstanceWithBoolean_(true))];
  }
  if (onlySomeReasons != nil) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 3, onlySomeReasons)];
  }
  if (indirectCRL) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 4, OrgSpongycastleAsn1ASN1Boolean_getInstanceWithBoolean_(true))];
  }
  if (onlyContainsAttributeCerts) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 5, OrgSpongycastleAsn1ASN1Boolean_getInstanceWithBoolean_(true))];
  }
  self->seq_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(vec);
}

OrgSpongycastleAsn1X509IssuingDistributionPoint *new_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, OrgSpongycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509IssuingDistributionPoint, initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts)
}

OrgSpongycastleAsn1X509IssuingDistributionPoint *create_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean onlyContainsUserCerts, jboolean onlyContainsCACerts, OrgSpongycastleAsn1X509ReasonFlags *onlySomeReasons, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509IssuingDistributionPoint, initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts)
}

void OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) {
  OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_withOrgSpongycastleAsn1X509ReasonFlags_withBoolean_withBoolean_(self, distributionPoint, false, false, nil, indirectCRL, onlyContainsAttributeCerts);
}

OrgSpongycastleAsn1X509IssuingDistributionPoint *new_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509IssuingDistributionPoint, initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_, distributionPoint, indirectCRL, onlyContainsAttributeCerts)
}

OrgSpongycastleAsn1X509IssuingDistributionPoint *create_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_(OrgSpongycastleAsn1X509DistributionPointName *distributionPoint, jboolean indirectCRL, jboolean onlyContainsAttributeCerts) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509IssuingDistributionPoint, initWithOrgSpongycastleAsn1X509DistributionPointName_withBoolean_withBoolean_, distributionPoint, indirectCRL, onlyContainsAttributeCerts)
}

void OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->seq_ = seq;
  for (jint i = 0; i != [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size]; i++) {
    OrgSpongycastleAsn1ASN1TaggedObject *o = OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithId_([seq getObjectAtWithInt:i]);
    switch ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo]) {
      case 0:
      self->distributionPoint_ = OrgSpongycastleAsn1X509DistributionPointName_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      break;
      case 1:
      self->onlyContainsUserCerts_ = [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(OrgSpongycastleAsn1ASN1Boolean_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false))) isTrue];
      break;
      case 2:
      self->onlyContainsCACerts_ = [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(OrgSpongycastleAsn1ASN1Boolean_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false))) isTrue];
      break;
      case 3:
      self->onlySomeReasons_ = new_OrgSpongycastleAsn1X509ReasonFlags_initWithOrgSpongycastleAsn1DERBitString_(OrgSpongycastleAsn1DERBitString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false));
      break;
      case 4:
      self->indirectCRL_ = [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(OrgSpongycastleAsn1ASN1Boolean_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false))) isTrue];
      break;
      case 5:
      self->onlyContainsAttributeCerts_ = [((OrgSpongycastleAsn1ASN1Boolean *) nil_chk(OrgSpongycastleAsn1ASN1Boolean_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false))) isTrue];
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown tag in IssuingDistributionPoint");
    }
  }
}

OrgSpongycastleAsn1X509IssuingDistributionPoint *new_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509IssuingDistributionPoint, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509IssuingDistributionPoint *create_OrgSpongycastleAsn1X509IssuingDistributionPoint_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509IssuingDistributionPoint, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1X509IssuingDistributionPoint_appendObjectWithJavaLangStringBuffer_withNSString_withNSString_withNSString_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, JavaLangStringBuffer *buf, NSString *sep, NSString *name, NSString *value) {
  NSString *indent = @"    ";
  (void) [((JavaLangStringBuffer *) nil_chk(buf)) appendWithNSString:indent];
  (void) [buf appendWithNSString:name];
  (void) [buf appendWithNSString:@":"];
  (void) [buf appendWithNSString:sep];
  (void) [buf appendWithNSString:indent];
  (void) [buf appendWithNSString:indent];
  (void) [buf appendWithNSString:value];
  (void) [buf appendWithNSString:sep];
}

NSString *OrgSpongycastleAsn1X509IssuingDistributionPoint_booleanToStringWithBoolean_(OrgSpongycastleAsn1X509IssuingDistributionPoint *self, jboolean value) {
  return value ? @"true" : @"false";
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509IssuingDistributionPoint)