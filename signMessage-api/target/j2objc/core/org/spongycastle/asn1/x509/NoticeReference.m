//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/NoticeReference.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"
#include "java/util/Vector.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/x509/DisplayText.h"
#include "org/spongycastle/asn1/x509/NoticeReference.h"

@interface OrgSpongycastleAsn1X509NoticeReference () {
 @public
  OrgSpongycastleAsn1X509DisplayText *organization_;
  OrgSpongycastleAsn1ASN1Sequence *noticeNumbers_;
}

+ (OrgSpongycastleAsn1ASN1EncodableVector *)convertVectorWithJavaUtilVector:(JavaUtilVector *)numbers;

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)as;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509NoticeReference, organization_, OrgSpongycastleAsn1X509DisplayText *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1X509NoticeReference, noticeNumbers_, OrgSpongycastleAsn1ASN1Sequence *)

__attribute__((unused)) static OrgSpongycastleAsn1ASN1EncodableVector *OrgSpongycastleAsn1X509NoticeReference_convertVectorWithJavaUtilVector_(JavaUtilVector *numbers);

__attribute__((unused)) static void OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509NoticeReference *self, OrgSpongycastleAsn1ASN1Sequence *as);

__attribute__((unused)) static OrgSpongycastleAsn1X509NoticeReference *new_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *as) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509NoticeReference *create_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *as);

@implementation OrgSpongycastleAsn1X509NoticeReference

+ (OrgSpongycastleAsn1ASN1EncodableVector *)convertVectorWithJavaUtilVector:(JavaUtilVector *)numbers {
  return OrgSpongycastleAsn1X509NoticeReference_convertVectorWithJavaUtilVector_(numbers);
}

- (instancetype)initWithNSString:(NSString *)organization
              withJavaUtilVector:(JavaUtilVector *)numbers {
  OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(self, organization, numbers);
  return self;
}

- (instancetype)initWithNSString:(NSString *)organization
withOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)noticeNumbers {
  OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_(self, organization, noticeNumbers);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509DisplayText:(OrgSpongycastleAsn1X509DisplayText *)organization
                withOrgSpongycastleAsn1ASN1EncodableVector:(OrgSpongycastleAsn1ASN1EncodableVector *)noticeNumbers {
  OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_(self, organization, noticeNumbers);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)as {
  OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1ASN1Sequence_(self, as);
  return self;
}

+ (OrgSpongycastleAsn1X509NoticeReference *)getInstanceWithId:(id)as {
  return OrgSpongycastleAsn1X509NoticeReference_getInstanceWithId_(as);
}

- (OrgSpongycastleAsn1X509DisplayText *)getOrganization {
  return organization_;
}

- (IOSObjectArray *)getNoticeNumbers {
  IOSObjectArray *tmp = [IOSObjectArray newArrayWithLength:[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(noticeNumbers_)) size] type:OrgSpongycastleAsn1ASN1Integer_class_()];
  for (jint i = 0; i != [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(noticeNumbers_)) size]; i++) {
    (void) IOSObjectArray_Set(tmp, i, OrgSpongycastleAsn1ASN1Integer_getInstanceWithId_([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(noticeNumbers_)) getObjectAtWithInt:i]));
  }
  return tmp;
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *av = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [av addWithOrgSpongycastleAsn1ASN1Encodable:organization_];
  [av addWithOrgSpongycastleAsn1ASN1Encodable:noticeNumbers_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(av);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1ASN1EncodableVector;", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509NoticeReference;", 0x9, 6, 7, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509DisplayText;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(convertVectorWithJavaUtilVector:);
  methods[1].selector = @selector(initWithNSString:withJavaUtilVector:);
  methods[2].selector = @selector(initWithNSString:withOrgSpongycastleAsn1ASN1EncodableVector:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1X509DisplayText:withOrgSpongycastleAsn1ASN1EncodableVector:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(getInstanceWithId:);
  methods[6].selector = @selector(getOrganization);
  methods[7].selector = @selector(getNoticeNumbers);
  methods[8].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "organization_", "LOrgSpongycastleAsn1X509DisplayText;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "noticeNumbers_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "convertVector", "LJavaUtilVector;", "LNSString;LJavaUtilVector;", "LNSString;LOrgSpongycastleAsn1ASN1EncodableVector;", "LOrgSpongycastleAsn1X509DisplayText;LOrgSpongycastleAsn1ASN1EncodableVector;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509NoticeReference = { "NoticeReference", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 9, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509NoticeReference;
}

@end

OrgSpongycastleAsn1ASN1EncodableVector *OrgSpongycastleAsn1X509NoticeReference_convertVectorWithJavaUtilVector_(JavaUtilVector *numbers) {
  OrgSpongycastleAsn1X509NoticeReference_initialize();
  OrgSpongycastleAsn1ASN1EncodableVector *av = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  id<JavaUtilEnumeration> it = [((JavaUtilVector *) nil_chk(numbers)) elements];
  while ([((id<JavaUtilEnumeration>) nil_chk(it)) hasMoreElements]) {
    id o = [it nextElement];
    OrgSpongycastleAsn1ASN1Integer *di;
    if ([o isKindOfClass:[JavaMathBigInteger class]]) {
      di = new_OrgSpongycastleAsn1ASN1Integer_initWithJavaMathBigInteger_((JavaMathBigInteger *) o);
    }
    else if ([o isKindOfClass:[JavaLangInteger class]]) {
      di = new_OrgSpongycastleAsn1ASN1Integer_initWithLong_([((JavaLangInteger *) nil_chk(((JavaLangInteger *) o))) intValue]);
    }
    else {
      @throw new_JavaLangIllegalArgumentException_init();
    }
    [av addWithOrgSpongycastleAsn1ASN1Encodable:di];
  }
  return av;
}

void OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(OrgSpongycastleAsn1X509NoticeReference *self, NSString *organization, JavaUtilVector *numbers) {
  OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_(self, organization, OrgSpongycastleAsn1X509NoticeReference_convertVectorWithJavaUtilVector_(numbers));
}

OrgSpongycastleAsn1X509NoticeReference *new_OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(NSString *organization, JavaUtilVector *numbers) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509NoticeReference, initWithNSString_withJavaUtilVector_, organization, numbers)
}

OrgSpongycastleAsn1X509NoticeReference *create_OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(NSString *organization, JavaUtilVector *numbers) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509NoticeReference, initWithNSString_withJavaUtilVector_, organization, numbers)
}

void OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1X509NoticeReference *self, NSString *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers) {
  OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_(self, new_OrgSpongycastleAsn1X509DisplayText_initWithNSString_(organization), noticeNumbers);
}

OrgSpongycastleAsn1X509NoticeReference *new_OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_(NSString *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509NoticeReference, initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_, organization, noticeNumbers)
}

OrgSpongycastleAsn1X509NoticeReference *create_OrgSpongycastleAsn1X509NoticeReference_initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_(NSString *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509NoticeReference, initWithNSString_withOrgSpongycastleAsn1ASN1EncodableVector_, organization, noticeNumbers)
}

void OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1X509NoticeReference *self, OrgSpongycastleAsn1X509DisplayText *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->organization_ = organization;
  self->noticeNumbers_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(noticeNumbers);
}

OrgSpongycastleAsn1X509NoticeReference *new_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1X509DisplayText *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509NoticeReference, initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_, organization, noticeNumbers)
}

OrgSpongycastleAsn1X509NoticeReference *create_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_(OrgSpongycastleAsn1X509DisplayText *organization, OrgSpongycastleAsn1ASN1EncodableVector *noticeNumbers) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509NoticeReference, initWithOrgSpongycastleAsn1X509DisplayText_withOrgSpongycastleAsn1ASN1EncodableVector_, organization, noticeNumbers)
}

void OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509NoticeReference *self, OrgSpongycastleAsn1ASN1Sequence *as) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(as)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [as size]));
  }
  self->organization_ = OrgSpongycastleAsn1X509DisplayText_getInstanceWithId_([as getObjectAtWithInt:0]);
  self->noticeNumbers_ = OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_([as getObjectAtWithInt:1]);
}

OrgSpongycastleAsn1X509NoticeReference *new_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *as) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509NoticeReference, initWithOrgSpongycastleAsn1ASN1Sequence_, as)
}

OrgSpongycastleAsn1X509NoticeReference *create_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *as) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509NoticeReference, initWithOrgSpongycastleAsn1ASN1Sequence_, as)
}

OrgSpongycastleAsn1X509NoticeReference *OrgSpongycastleAsn1X509NoticeReference_getInstanceWithId_(id as) {
  OrgSpongycastleAsn1X509NoticeReference_initialize();
  if ([as isKindOfClass:[OrgSpongycastleAsn1X509NoticeReference class]]) {
    return (OrgSpongycastleAsn1X509NoticeReference *) as;
  }
  else if (as != nil) {
    return new_OrgSpongycastleAsn1X509NoticeReference_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(as));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509NoticeReference)
