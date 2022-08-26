//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/isismtt/x509/DeclarationOfMajority.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Boolean.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1GeneralizedTime.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERPrintableString.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERTaggedObject.h"
#include "org/spongycastle/asn1/isismtt/x509/DeclarationOfMajority.h"

@interface OrgSpongycastleAsn1IsismttX509DeclarationOfMajority () {
 @public
  OrgSpongycastleAsn1ASN1TaggedObject *declaration_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)o;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, declaration_, OrgSpongycastleAsn1ASN1TaggedObject *)

__attribute__((unused)) static void OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *self, OrgSpongycastleAsn1ASN1TaggedObject *o);

__attribute__((unused)) static OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *new_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *o) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *create_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *o);

@implementation OrgSpongycastleAsn1IsismttX509DeclarationOfMajority

- (instancetype)initWithInt:(jint)notYoungerThan {
  OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithInt_(self, notYoungerThan);
  return self;
}

- (instancetype)initWithBoolean:(jboolean)fullAge
                   withNSString:(NSString *)country {
  OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithBoolean_withNSString_(self, fullAge, country);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)dateOfBirth {
  OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1GeneralizedTime_(self, dateOfBirth);
  return self;
}

+ (OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)o {
  OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1TaggedObject_(self, o);
  return self;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return declaration_;
}

- (jint)getType {
  return [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(declaration_)) getTagNo];
}

- (jint)notYoungerThan {
  if ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(declaration_)) getTagNo] != 0) {
    return -1;
  }
  return [((JavaMathBigInteger *) nil_chk([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(OrgSpongycastleAsn1ASN1Integer_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(declaration_, false))) getValue])) intValue];
}

- (OrgSpongycastleAsn1ASN1Sequence *)fullAgeAtCountry {
  if ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(declaration_)) getTagNo] != 1) {
    return nil;
  }
  return OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(declaration_, false);
}

- (OrgSpongycastleAsn1ASN1GeneralizedTime *)getDateOfBirth {
  if ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(declaration_)) getTagNo] != 2) {
    return nil;
  }
  return OrgSpongycastleAsn1ASN1GeneralizedTime_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(declaration_, false);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1IsismttX509DeclarationOfMajority;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Sequence;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:);
  methods[1].selector = @selector(initWithBoolean:withNSString:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1GeneralizedTime:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1ASN1TaggedObject:);
  methods[5].selector = @selector(toASN1Primitive);
  methods[6].selector = @selector(getType);
  methods[7].selector = @selector(notYoungerThan);
  methods[8].selector = @selector(fullAgeAtCountry);
  methods[9].selector = @selector(getDateOfBirth);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "notYoungerThan_", "I", .constantValue.asInt = OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_notYoungerThan_, 0x19, 6, -1, -1, -1 },
    { "fullAgeAtCountry_", "I", .constantValue.asInt = OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_fullAgeAtCountry_, 0x19, 7, -1, -1, -1 },
    { "dateOfBirth", "I", .constantValue.asInt = OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_dateOfBirth, 0x19, -1, -1, -1, -1 },
    { "declaration_", "LOrgSpongycastleAsn1ASN1TaggedObject;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I", "ZLNSString;", "LOrgSpongycastleAsn1ASN1GeneralizedTime;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;", "notYoungerThan", "fullAgeAtCountry" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1IsismttX509DeclarationOfMajority = { "DeclarationOfMajority", "org.spongycastle.asn1.isismtt.x509", ptrTable, methods, fields, 7, 0x1, 10, 4, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority;
}

@end

void OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithInt_(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *self, jint notYoungerThan) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->declaration_ = new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, new_OrgSpongycastleAsn1ASN1Integer_initWithLong_(notYoungerThan));
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *new_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithInt_(jint notYoungerThan) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, initWithInt_, notYoungerThan)
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *create_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithInt_(jint notYoungerThan) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, initWithInt_, notYoungerThan)
}

void OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithBoolean_withNSString_(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *self, jboolean fullAge, NSString *country) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((NSString *) nil_chk(country)) java_length] > 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"country can only be 2 characters");
  }
  if (fullAge) {
    self->declaration_ = new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 1, new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(new_OrgSpongycastleAsn1DERPrintableString_initWithNSString_withBoolean_(country, true)));
  }
  else {
    OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
    [v addWithOrgSpongycastleAsn1ASN1Encodable:JreLoadStatic(OrgSpongycastleAsn1ASN1Boolean, FALSE)];
    [v addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERPrintableString_initWithNSString_withBoolean_(country, true)];
    self->declaration_ = new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 1, new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v));
  }
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *new_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithBoolean_withNSString_(jboolean fullAge, NSString *country) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, initWithBoolean_withNSString_, fullAge, country)
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *create_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithBoolean_withNSString_(jboolean fullAge, NSString *country) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, initWithBoolean_withNSString_, fullAge, country)
}

void OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1GeneralizedTime_(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *self, OrgSpongycastleAsn1ASN1GeneralizedTime *dateOfBirth) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->declaration_ = new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 2, dateOfBirth);
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *new_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1GeneralizedTime_(OrgSpongycastleAsn1ASN1GeneralizedTime *dateOfBirth) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, initWithOrgSpongycastleAsn1ASN1GeneralizedTime_, dateOfBirth)
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *create_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1GeneralizedTime_(OrgSpongycastleAsn1ASN1GeneralizedTime *dateOfBirth) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, initWithOrgSpongycastleAsn1ASN1GeneralizedTime_, dateOfBirth)
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initialize();
  if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1IsismttX509DeclarationOfMajority class]]) {
    return (OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *) cast_chk(obj, [OrgSpongycastleAsn1IsismttX509DeclarationOfMajority class]);
  }
  if ([obj isKindOfClass:[OrgSpongycastleAsn1ASN1TaggedObject class]]) {
    return new_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1TaggedObject_((OrgSpongycastleAsn1ASN1TaggedObject *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

void OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *self, OrgSpongycastleAsn1ASN1TaggedObject *o) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo] > 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad tag number: ", [o getTagNo]));
  }
  self->declaration_ = o;
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *new_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *o) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, initWithOrgSpongycastleAsn1ASN1TaggedObject_, o)
}

OrgSpongycastleAsn1IsismttX509DeclarationOfMajority *create_OrgSpongycastleAsn1IsismttX509DeclarationOfMajority_initWithOrgSpongycastleAsn1ASN1TaggedObject_(OrgSpongycastleAsn1ASN1TaggedObject *o) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority, initWithOrgSpongycastleAsn1ASN1TaggedObject_, o)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1IsismttX509DeclarationOfMajority)