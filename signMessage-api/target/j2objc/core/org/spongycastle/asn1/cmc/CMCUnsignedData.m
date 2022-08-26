//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cmc/CMCUnsignedData.java
//

#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/cmc/BodyPartPath.h"
#include "org/spongycastle/asn1/cmc/CMCUnsignedData.h"

@interface OrgSpongycastleAsn1CmcCMCUnsignedData () {
 @public
  OrgSpongycastleAsn1CmcBodyPartPath *bodyPartPath_;
  OrgSpongycastleAsn1ASN1ObjectIdentifier *identifier_;
  id<OrgSpongycastleAsn1ASN1Encodable> content_;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcCMCUnsignedData, bodyPartPath_, OrgSpongycastleAsn1CmcBodyPartPath *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcCMCUnsignedData, identifier_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmcCMCUnsignedData, content_, id<OrgSpongycastleAsn1ASN1Encodable>)

__attribute__((unused)) static void OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcCMCUnsignedData *self, OrgSpongycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static OrgSpongycastleAsn1CmcCMCUnsignedData *new_OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1CmcCMCUnsignedData *create_OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq);

@implementation OrgSpongycastleAsn1CmcCMCUnsignedData

- (instancetype)initWithOrgSpongycastleAsn1CmcBodyPartPath:(OrgSpongycastleAsn1CmcBodyPartPath *)bodyPartPath
               withOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)identifier
                      withOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)content {
  OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1CmcBodyPartPath_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(self, bodyPartPath, identifier, content);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (OrgSpongycastleAsn1CmcCMCUnsignedData *)getInstanceWithId:(id)o {
  return OrgSpongycastleAsn1CmcCMCUnsignedData_getInstanceWithId_(o);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  OrgSpongycastleAsn1ASN1EncodableVector *v = new_OrgSpongycastleAsn1ASN1EncodableVector_init();
  [v addWithOrgSpongycastleAsn1ASN1Encodable:bodyPartPath_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:identifier_];
  [v addWithOrgSpongycastleAsn1ASN1Encodable:content_];
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_(v);
}

- (OrgSpongycastleAsn1CmcBodyPartPath *)getBodyPartPath {
  return bodyPartPath_;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getIdentifier {
  return identifier_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getContent {
  return content_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcCMCUnsignedData;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1CmcBodyPartPath;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1CmcBodyPartPath:withOrgSpongycastleAsn1ASN1ObjectIdentifier:withOrgSpongycastleAsn1ASN1Encodable:);
  methods[1].selector = @selector(initWithOrgSpongycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(toASN1Primitive);
  methods[4].selector = @selector(getBodyPartPath);
  methods[5].selector = @selector(getIdentifier);
  methods[6].selector = @selector(getContent);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bodyPartPath_", "LOrgSpongycastleAsn1CmcBodyPartPath;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "identifier_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "content_", "LOrgSpongycastleAsn1ASN1Encodable;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1CmcBodyPartPath;LOrgSpongycastleAsn1ASN1ObjectIdentifier;LOrgSpongycastleAsn1ASN1Encodable;", "LOrgSpongycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmcCMCUnsignedData = { "CMCUnsignedData", "org.spongycastle.asn1.cmc", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmcCMCUnsignedData;
}

@end

void OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1CmcBodyPartPath_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CmcCMCUnsignedData *self, OrgSpongycastleAsn1CmcBodyPartPath *bodyPartPath, OrgSpongycastleAsn1ASN1ObjectIdentifier *identifier, id<OrgSpongycastleAsn1ASN1Encodable> content) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->bodyPartPath_ = bodyPartPath;
  self->identifier_ = identifier;
  self->content_ = content;
}

OrgSpongycastleAsn1CmcCMCUnsignedData *new_OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1CmcBodyPartPath_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CmcBodyPartPath *bodyPartPath, OrgSpongycastleAsn1ASN1ObjectIdentifier *identifier, id<OrgSpongycastleAsn1ASN1Encodable> content) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcCMCUnsignedData, initWithOrgSpongycastleAsn1CmcBodyPartPath_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, bodyPartPath, identifier, content)
}

OrgSpongycastleAsn1CmcCMCUnsignedData *create_OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1CmcBodyPartPath_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1CmcBodyPartPath *bodyPartPath, OrgSpongycastleAsn1ASN1ObjectIdentifier *identifier, id<OrgSpongycastleAsn1ASN1Encodable> content) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcCMCUnsignedData, initWithOrgSpongycastleAsn1CmcBodyPartPath_withOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleAsn1ASN1Encodable_, bodyPartPath, identifier, content)
}

void OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1CmcCMCUnsignedData *self, OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"incorrect sequence size");
  }
  self->bodyPartPath_ = OrgSpongycastleAsn1CmcBodyPartPath_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->identifier_ = OrgSpongycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->content_ = [seq getObjectAtWithInt:2];
}

OrgSpongycastleAsn1CmcCMCUnsignedData *new_OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmcCMCUnsignedData, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcCMCUnsignedData *create_OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmcCMCUnsignedData, initWithOrgSpongycastleAsn1ASN1Sequence_, seq)
}

OrgSpongycastleAsn1CmcCMCUnsignedData *OrgSpongycastleAsn1CmcCMCUnsignedData_getInstanceWithId_(id o) {
  OrgSpongycastleAsn1CmcCMCUnsignedData_initialize();
  if ([o isKindOfClass:[OrgSpongycastleAsn1CmcCMCUnsignedData class]]) {
    return (OrgSpongycastleAsn1CmcCMCUnsignedData *) o;
  }
  if (o != nil) {
    return new_OrgSpongycastleAsn1CmcCMCUnsignedData_initWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmcCMCUnsignedData)