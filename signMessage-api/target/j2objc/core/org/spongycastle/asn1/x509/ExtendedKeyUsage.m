//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/ExtendedKeyUsage.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"
#include "java/util/Vector.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/x509/ExtendedKeyUsage.h"
#include "org/spongycastle/asn1/x509/Extension.h"
#include "org/spongycastle/asn1/x509/Extensions.h"
#include "org/spongycastle/asn1/x509/KeyPurposeId.h"

@interface OrgSpongycastleAsn1X509ExtendedKeyUsage ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509ExtendedKeyUsage *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1X509ExtendedKeyUsage *new_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509ExtendedKeyUsage *create_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1X509ExtendedKeyUsage

+ (OrgSpongycastleAsn1X509ExtendedKeyUsage *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1X509ExtendedKeyUsage_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (OrgSpongycastleAsn1X509ExtendedKeyUsage *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1X509ExtendedKeyUsage *)fromExtensionsWithOrgSpongycastleAsn1X509Extensions:(OrgSpongycastleAsn1X509Extensions *)extensions {
  return OrgSpongycastleAsn1X509ExtendedKeyUsage_fromExtensionsWithOrgSpongycastleAsn1X509Extensions_(extensions);
}

- (instancetype)initWithOrgSpongycastleAsn1X509KeyPurposeId:(OrgSpongycastleAsn1X509KeyPurposeId *)usage {
  OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1X509KeyPurposeId_(self, usage);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1X509KeyPurposeIdArray:(IOSObjectArray *)usages {
  OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1X509KeyPurposeIdArray_(self, usages);
  return self;
}

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)usages {
  OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(self, usages);
  return self;
}

- (jboolean)hasKeyPurposeIdWithOrgSpongycastleAsn1X509KeyPurposeId:(OrgSpongycastleAsn1X509KeyPurposeId *)keyPurposeId {
  return ([((JavaUtilHashtable *) nil_chk(usageTable_)) getWithId:keyPurposeId] != nil);
}

- (IOSObjectArray *)getUsages {
  IOSObjectArray *temp = [IOSObjectArray newArrayWithLength:[((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq_)) size] type:OrgSpongycastleAsn1X509KeyPurposeId_class_()];
  jint i = 0;
  for (id<JavaUtilEnumeration> it = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq_)) getObjects]; [((id<JavaUtilEnumeration>) nil_chk(it)) hasMoreElements]; ) {
    (void) IOSObjectArray_Set(temp, i++, OrgSpongycastleAsn1X509KeyPurposeId_getInstanceWithId_([it nextElement]));
  }
  return temp;
}

- (jint)size {
  return [((JavaUtilHashtable *) nil_chk(usageTable_)) size];
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return seq_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1X509ExtendedKeyUsage;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509ExtendedKeyUsage;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509ExtendedKeyUsage;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 6, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 7, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 8, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 9, 5, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleAsn1X509KeyPurposeId;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(fromExtensionsWithOrgSpongycastleAsn1X509Extensions:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1X509KeyPurposeId:);
  methods[4].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(initWithOrgSpongycastleAsn1X509KeyPurposeIdArray:);
  methods[6].selector = @selector(initWithJavaUtilVector:);
  methods[7].selector = @selector(hasKeyPurposeIdWithOrgSpongycastleAsn1X509KeyPurposeId:);
  methods[8].selector = @selector(getUsages);
  methods[9].selector = @selector(size);
  methods[10].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "usageTable_", "LJavaUtilHashtable;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "seq_", "LOrgSpongycastleAsn1ASN1Sequence;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "fromExtensions", "LOrgSpongycastleAsn1X509Extensions;", "LOrgSpongycastleAsn1X509KeyPurposeId;", "LOrgSpongycastleAsn1ASN1Sequence;", "[LOrgSpongycastleAsn1X509KeyPurposeId;", "LJavaUtilVector;", "hasKeyPurposeId" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509ExtendedKeyUsage = { "ExtendedKeyUsage", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 11, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509ExtendedKeyUsage;
}

@end

OrgSpongycastleAsn1X509ExtendedKeyUsage *OrgSpongycastleAsn1X509ExtendedKeyUsage_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1X509ExtendedKeyUsage_initialize();
  return OrgSpongycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *OrgSpongycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509ExtendedKeyUsage_initialize();
  if ([obj isKindOfClass:[OrgSpongycastleAsn1X509ExtendedKeyUsage class]]) {
    return (OrgSpongycastleAsn1X509ExtendedKeyUsage *) obj;
  }
  else if (obj != nil) {
    return new_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *OrgSpongycastleAsn1X509ExtendedKeyUsage_fromExtensionsWithOrgSpongycastleAsn1X509Extensions_(OrgSpongycastleAsn1X509Extensions *extensions) {
  OrgSpongycastleAsn1X509ExtendedKeyUsage_initialize();
  return OrgSpongycastleAsn1X509ExtendedKeyUsage_getInstanceWithId_([((OrgSpongycastleAsn1X509Extensions *) nil_chk(extensions)) getExtensionParsedValueWithOrgSpongycastleAsn1ASN1ObjectIdentifier:JreLoadStatic(OrgSpongycastleAsn1X509Extension, extendedKeyUsage)]);
}

void OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1X509KeyPurposeId_(OrgSpongycastleAsn1X509ExtendedKeyUsage *self, OrgSpongycastleAsn1X509KeyPurposeId *usage) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->usageTable_ = new_JavaUtilHashtable_init();
  self->seq_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1Encodable_(usage);
  (void) [((JavaUtilHashtable *) nil_chk(self->usageTable_)) putWithId:usage withId:usage];
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *new_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1X509KeyPurposeId_(OrgSpongycastleAsn1X509KeyPurposeId *usage) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509ExtendedKeyUsage, initWithOrgSpongycastleAsn1X509KeyPurposeId_, usage)
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *create_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1X509KeyPurposeId_(OrgSpongycastleAsn1X509KeyPurposeId *usage) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509ExtendedKeyUsage, initWithOrgSpongycastleAsn1X509KeyPurposeId_, usage)
}

void OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1X509ExtendedKeyUsage *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->usageTable_ = new_JavaUtilHashtable_init();
  self->seq_ = seq;
  id<JavaUtilEnumeration> e = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    id<OrgSpongycastleAsn1ASN1Encodable> o = (id<OrgSpongycastleAsn1ASN1Encodable>) cast_check([e nextElement], OrgSpongycastleAsn1ASN1Encodable_class_());
    if (!([[((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk(o)) toASN1Primitive] isKindOfClass:[OrgSpongycastleAsn1ASN1ObjectIdentifier class]])) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Only ASN1ObjectIdentifiers allowed in ExtendedKeyUsage.");
    }
    (void) [((JavaUtilHashtable *) nil_chk(self->usageTable_)) putWithId:o withId:o];
  }
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *new_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509ExtendedKeyUsage, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *create_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509ExtendedKeyUsage, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

void OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1X509KeyPurposeIdArray_(OrgSpongycastleAsn1X509ExtendedKeyUsage *self, IOSObjectArray *usages) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->usageTable_ = new_JavaUtilHashtable_init();
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(usages))->size_; i++) {
    [v addWithOrgSpongycastleAsn1ASN1Encodable:IOSObjectArray_Get(usages, i)];
    (void) [((JavaUtilHashtable *) nil_chk(self->usageTable_)) putWithId:IOSObjectArray_Get(usages, i) withId:IOSObjectArray_Get(usages, i)];
  }
  self->seq_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *new_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1X509KeyPurposeIdArray_(IOSObjectArray *usages) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509ExtendedKeyUsage, initWithOrgSpongycastleAsn1X509KeyPurposeIdArray_, usages)
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *create_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithOrgSpongycastleAsn1X509KeyPurposeIdArray_(IOSObjectArray *usages) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509ExtendedKeyUsage, initWithOrgSpongycastleAsn1X509KeyPurposeIdArray_, usages)
}

void OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(OrgSpongycastleAsn1X509ExtendedKeyUsage *self, JavaUtilVector *usages) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->usageTable_ = new_JavaUtilHashtable_init();
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  id<JavaUtilEnumeration> e = [((JavaUtilVector *) nil_chk(usages)) elements];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    OrgSpongycastleAsn1X509KeyPurposeId *o = OrgSpongycastleAsn1X509KeyPurposeId_getInstanceWithId_([e nextElement]);
    [v addWithOrgSpongycastleAsn1ASN1Encodable:o];
    (void) [((JavaUtilHashtable *) nil_chk(self->usageTable_)) putWithId:o withId:o];
  }
  self->seq_ = new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *new_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(JavaUtilVector *usages) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509ExtendedKeyUsage, initWithJavaUtilVector_, usages)
}

OrgSpongycastleAsn1X509ExtendedKeyUsage *create_OrgSpongycastleAsn1X509ExtendedKeyUsage_initWithJavaUtilVector_(JavaUtilVector *usages) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509ExtendedKeyUsage, initWithJavaUtilVector_, usages)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509ExtendedKeyUsage)
