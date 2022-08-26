//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/cms/ContentInfoParser.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1SequenceParser.h"
#include "org/spongycastle/asn1/ASN1TaggedObjectParser.h"
#include "org/spongycastle/asn1/cms/ContentInfoParser.h"

@interface OrgSpongycastleAsn1CmsContentInfoParser () {
 @public
  OrgSpongycastleAsn1ASN1ObjectIdentifier *contentType_;
  id<OrgSpongycastleAsn1ASN1TaggedObjectParser> content_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsContentInfoParser, contentType_, OrgSpongycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1CmsContentInfoParser, content_, id<OrgSpongycastleAsn1ASN1TaggedObjectParser>)

@implementation OrgSpongycastleAsn1CmsContentInfoParser

- (instancetype)initWithOrgSpongycastleAsn1ASN1SequenceParser:(id<OrgSpongycastleAsn1ASN1SequenceParser>)seq {
  OrgSpongycastleAsn1CmsContentInfoParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(self, seq);
  return self;
}

- (OrgSpongycastleAsn1ASN1ObjectIdentifier *)getContentType {
  return contentType_;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)getContentWithInt:(jint)tag {
  if (content_ != nil) {
    return [content_ getObjectParserWithInt:tag withBoolean:true];
  }
  return nil;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, 2, 3, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1SequenceParser:);
  methods[1].selector = @selector(getContentType);
  methods[2].selector = @selector(getContentWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "contentType_", "LOrgSpongycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "content_", "LOrgSpongycastleAsn1ASN1TaggedObjectParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1SequenceParser;", "LJavaIoIOException;", "getContent", "I" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1CmsContentInfoParser = { "ContentInfoParser", "org.spongycastle.asn1.cms", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1CmsContentInfoParser;
}

@end

void OrgSpongycastleAsn1CmsContentInfoParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(OrgSpongycastleAsn1CmsContentInfoParser *self, id<OrgSpongycastleAsn1ASN1SequenceParser> seq) {
  NSObject_init(self);
  self->contentType_ = (OrgSpongycastleAsn1ASN1ObjectIdentifier *) cast_chk([((id<OrgSpongycastleAsn1ASN1SequenceParser>) nil_chk(seq)) readObject], [OrgSpongycastleAsn1ASN1ObjectIdentifier class]);
  self->content_ = (id<OrgSpongycastleAsn1ASN1TaggedObjectParser>) cast_check([seq readObject], OrgSpongycastleAsn1ASN1TaggedObjectParser_class_());
}

OrgSpongycastleAsn1CmsContentInfoParser *new_OrgSpongycastleAsn1CmsContentInfoParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(id<OrgSpongycastleAsn1ASN1SequenceParser> seq) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1CmsContentInfoParser, initWithOrgSpongycastleAsn1ASN1SequenceParser_, seq)
}

OrgSpongycastleAsn1CmsContentInfoParser *create_OrgSpongycastleAsn1CmsContentInfoParser_initWithOrgSpongycastleAsn1ASN1SequenceParser_(id<OrgSpongycastleAsn1ASN1SequenceParser> seq) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1CmsContentInfoParser, initWithOrgSpongycastleAsn1ASN1SequenceParser_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1CmsContentInfoParser)
