//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/sigi/PersonalData.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"
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
#include "org/spongycastle/asn1/x500/DirectoryString.h"
#include "org/spongycastle/asn1/x509/sigi/NameOrPseudonym.h"
#include "org/spongycastle/asn1/x509/sigi/PersonalData.h"

@interface OrgSpongycastleAsn1X509SigiPersonalData () {
 @public
  OrgSpongycastleAsn1X509SigiNameOrPseudonym *nameOrPseudonym_;
  JavaMathBigInteger *nameDistinguisher_;
  OrgSpongycastleAsn1ASN1GeneralizedTime *dateOfBirth_;
  OrgSpongycastleAsn1X500DirectoryString *placeOfBirth_;
  NSString *gender_;
  OrgSpongycastleAsn1X500DirectoryString *postalAddress_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509SigiPersonalData, nameOrPseudonym_, OrgSpongycastleAsn1X509SigiNameOrPseudonym *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509SigiPersonalData, nameDistinguisher_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509SigiPersonalData, dateOfBirth_, OrgSpongycastleAsn1ASN1GeneralizedTime *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509SigiPersonalData, placeOfBirth_, OrgSpongycastleAsn1X500DirectoryString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509SigiPersonalData, gender_, NSString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509SigiPersonalData, postalAddress_, OrgSpongycastleAsn1X500DirectoryString *)

__attribute__((unused)) static void OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509SigiPersonalData *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X509SigiPersonalData *new_OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509SigiPersonalData *create_OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1X509SigiPersonalData

+ (OrgSpongycastleAsn1X509SigiPersonalData *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509SigiPersonalData_getInstanceWithId_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509SigiNameOrPseudonym:(OrgSpongycastleAsn1X509SigiNameOrPseudonym *)nameOrPseudonym
                                            withJavaMathBigInteger:(JavaMathBigInteger *)nameDistinguisher
                        withOrgSpongycastleAsn1ASN1GeneralizedTime:(OrgSpongycastleAsn1ASN1GeneralizedTime *)dateOfBirth
                        withOrgSpongycastleAsn1X500DirectoryString:(OrgSpongycastleAsn1X500DirectoryString *)placeOfBirth
                                                      withNSString:(NSString *)gender
                        withOrgSpongycastleAsn1X500DirectoryString:(OrgSpongycastleAsn1X500DirectoryString *)postalAddress {
  OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1X509SigiNameOrPseudonym_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X500DirectoryString_withNSString_withOrgSpongycastleAsn1X500DirectoryString_(self, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, postalAddress);
  return self;
}

- (OrgSpongycastleAsn1X509SigiNameOrPseudonym *)getNameOrPseudonym {
  return nameOrPseudonym_;
}

- (JavaMathBigInteger *)getNameDistinguisher {
  return nameDistinguisher_;
}

- (OrgSpongycastleAsn1ASN1GeneralizedTime *)getDateOfBirth {
  return dateOfBirth_;
}

- (OrgSpongycastleAsn1X500DirectoryString *)getPlaceOfBirth {
  return placeOfBirth_;
}

- (NSString *)getGender {
  return gender_;
}

- (OrgSpongycastleAsn1X500DirectoryString *)getPostalAddress {
  return postalAddress_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *vec = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [vec addWithOrgSpongycastleAsn1ASN1Encodable:nameOrPseudonym_];
  if (nameDistinguisher_ != nil) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 0, new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(nameDistinguisher_))];
  }
  if (dateOfBirth_ != nil) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 1, dateOfBirth_)];
  }
  if (placeOfBirth_ != nil) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 2, placeOfBirth_)];
  }
  if (gender_ != nil) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(false, 3, new_OrgSpongycastleAsn1DERPrintableString_initWithNSString_withBoolean_(gender_, true))];
  }
  if (postalAddress_ != nil) {
    [vec addWithOrgSpongycastleAsn1ASN1Encodable:new_OrgSpongycastleAsn1DERTaggedObject_initWithBoolean_withInt_withOrgSpongycastleAsn1ASN1Encodable_(true, 4, postalAddress_)];
  }
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(vec);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1X509SigiPersonalData;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509SigiNameOrPseudonym;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1GeneralizedTime;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X500DirectoryString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X500DirectoryString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1X509SigiNameOrPseudonym:withJavaMathBigInteger:withOrgSpongycastleAsn1ASN1GeneralizedTime:withOrgSpongycastleAsn1X500DirectoryString:withNSString:withOrgSpongycastleAsn1X500DirectoryString:);
  methods[3].selector = @selector(getNameOrPseudonym);
  methods[4].selector = @selector(getNameDistinguisher);
  methods[5].selector = @selector(getDateOfBirth);
  methods[6].selector = @selector(getPlaceOfBirth);
  methods[7].selector = @selector(getGender);
  methods[8].selector = @selector(getPostalAddress);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "nameOrPseudonym_", "LOrgSpongycastleAsn1X509SigiNameOrPseudonym;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "nameDistinguisher_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dateOfBirth_", "LOrgSpongycastleAsn1ASN1GeneralizedTime;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "placeOfBirth_", "LOrgSpongycastleAsn1X500DirectoryString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "gender_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "postalAddress_", "LOrgSpongycastleAsn1X500DirectoryString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1Sequence;", "LOrgSpongycastleAsn1X509SigiNameOrPseudonym;LJavaMathBigInteger;LOrgSpongycastleAsn1ASN1GeneralizedTime;LOrgSpongycastleAsn1X500DirectoryString;LNSString;LOrgSpongycastleAsn1X500DirectoryString;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509SigiPersonalData = { "PersonalData", "org.spongycastle.asn1.x509.sigi", ptrTable, methods, fields, 7, 0x1, 10, 6, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509SigiPersonalData;
}

@end

OrgSpongycastleAsn1X509SigiPersonalData *OrgSpongycastleAsn1X509SigiPersonalData_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509SigiPersonalData_initialize();
  if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1X509SigiPersonalData class]]) {
    return (OrgSpongycastleAsn1X509SigiPersonalData *) cast_chk(obj, [OrgSpongycastleAsn1X509SigiPersonalData class]);
  }
  if ([obj isKindOfClass:[OrgSpongycastleAsn1ASN1Sequence class]]) {
    return new_OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1ASN1Sequence_((OrgSpongycastleAsn1ASN1Sequence *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

void OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509SigiPersonalData *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  id<JavaUtilEnumeration> e = [seq getObjects];
  self->nameOrPseudonym_ = OrgSpongycastleAsn1X509SigiNameOrPseudonym_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement]);
  while ([e hasMoreElements]) {
    OrgSpongycastleAsn1ASN1TaggedObject *o = OrgSpongycastleAsn1ASN1TaggedObject_getInstanceWithId_([e nextElement]);
    jint tag = [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(o)) getTagNo];
    switch (tag) {
      case 0:
      self->nameDistinguisher_ = [((OrgSpongycastleAsn1ASN1Integer *) nil_chk(OrgSpongycastleAsn1ASN1Integer_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false))) getValue];
      break;
      case 1:
      self->dateOfBirth_ = OrgSpongycastleAsn1ASN1GeneralizedTime_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false);
      break;
      case 2:
      self->placeOfBirth_ = OrgSpongycastleAsn1X500DirectoryString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      break;
      case 3:
      self->gender_ = [((OrgSpongycastleAsn1DERPrintableString *) nil_chk(OrgSpongycastleAsn1DERPrintableString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, false))) getString];
      break;
      case 4:
      self->postalAddress_ = OrgSpongycastleAsn1X500DirectoryString_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(o, true);
      break;
      default:
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad tag number: ", [o getTagNo]));
    }
  }
}

OrgSpongycastleAsn1X509SigiPersonalData *new_OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509SigiPersonalData, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509SigiPersonalData *create_OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509SigiPersonalData, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1X509SigiNameOrPseudonym_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X500DirectoryString_withNSString_withOrgSpongycastleAsn1X500DirectoryString_(OrgSpongycastleAsn1X509SigiPersonalData *self, OrgSpongycastleAsn1X509SigiNameOrPseudonym *nameOrPseudonym, JavaMathBigInteger *nameDistinguisher, OrgSpongycastleAsn1ASN1GeneralizedTime *dateOfBirth, OrgSpongycastleAsn1X500DirectoryString *placeOfBirth, NSString *gender, OrgSpongycastleAsn1X500DirectoryString *postalAddress) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->nameOrPseudonym_ = nameOrPseudonym;
  self->dateOfBirth_ = dateOfBirth;
  self->gender_ = gender;
  self->nameDistinguisher_ = nameDistinguisher;
  self->postalAddress_ = postalAddress;
  self->placeOfBirth_ = placeOfBirth;
}

OrgSpongycastleAsn1X509SigiPersonalData *new_OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1X509SigiNameOrPseudonym_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X500DirectoryString_withNSString_withOrgSpongycastleAsn1X500DirectoryString_(OrgSpongycastleAsn1X509SigiNameOrPseudonym *nameOrPseudonym, JavaMathBigInteger *nameDistinguisher, OrgSpongycastleAsn1ASN1GeneralizedTime *dateOfBirth, OrgSpongycastleAsn1X500DirectoryString *placeOfBirth, NSString *gender, OrgSpongycastleAsn1X500DirectoryString *postalAddress) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509SigiPersonalData, initWithOrgSpongycastleAsn1X509SigiNameOrPseudonym_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X500DirectoryString_withNSString_withOrgSpongycastleAsn1X500DirectoryString_, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, postalAddress)
}

OrgSpongycastleAsn1X509SigiPersonalData *create_OrgSpongycastleAsn1X509SigiPersonalData_initWithOrgSpongycastleAsn1X509SigiNameOrPseudonym_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X500DirectoryString_withNSString_withOrgSpongycastleAsn1X500DirectoryString_(OrgSpongycastleAsn1X509SigiNameOrPseudonym *nameOrPseudonym, JavaMathBigInteger *nameDistinguisher, OrgSpongycastleAsn1ASN1GeneralizedTime *dateOfBirth, OrgSpongycastleAsn1X500DirectoryString *placeOfBirth, NSString *gender, OrgSpongycastleAsn1X500DirectoryString *postalAddress) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509SigiPersonalData, initWithOrgSpongycastleAsn1X509SigiNameOrPseudonym_withJavaMathBigInteger_withOrgSpongycastleAsn1ASN1GeneralizedTime_withOrgSpongycastleAsn1X500DirectoryString_withNSString_withOrgSpongycastleAsn1X500DirectoryString_, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, postalAddress)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509SigiPersonalData)