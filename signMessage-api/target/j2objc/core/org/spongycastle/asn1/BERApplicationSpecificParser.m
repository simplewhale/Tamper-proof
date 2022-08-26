//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/BERApplicationSpecificParser.java
//

#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1ParsingException.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1StreamParser.h"
#include "org/spongycastle/asn1/BERApplicationSpecific.h"
#include "org/spongycastle/asn1/BERApplicationSpecificParser.h"

@interface OrgSpongycastleAsn1BERApplicationSpecificParser () {
 @public
  jint tag_;
  OrgSpongycastleAsn1ASN1StreamParser *parser_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1BERApplicationSpecificParser, parser_, OrgSpongycastleAsn1ASN1StreamParser *)

@implementation OrgSpongycastleAsn1BERApplicationSpecificParser

- (instancetype)initWithInt:(jint)tag
withOrgSpongycastleAsn1ASN1StreamParser:(OrgSpongycastleAsn1ASN1StreamParser *)parser {
  OrgSpongycastleAsn1BERApplicationSpecificParser_initWithInt_withOrgSpongycastleAsn1ASN1StreamParser_(self, tag, parser);
  return self;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)readObject {
  return [((OrgSpongycastleAsn1ASN1StreamParser *) nil_chk(parser_)) readObject];
}

- (OrgSpongycastleAsn1ASN1Primitive *)getLoadedObject {
  return new_OrgSpongycastleAsn1BERApplicationSpecific_initWithInt_withOrgSpongycastleAsn1ASN1EncodableVector_(tag_, [((OrgSpongycastleAsn1ASN1StreamParser *) nil_chk(parser_)) readVector]);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  @try {
    return [self getLoadedObject];
  }
  @catch (JavaIoIOException *e) {
    @throw new_OrgSpongycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_([e getMessage], e);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Encodable;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withOrgSpongycastleAsn1ASN1StreamParser:);
  methods[1].selector = @selector(readObject);
  methods[2].selector = @selector(getLoadedObject);
  methods[3].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "tag_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "parser_", "LOrgSpongycastleAsn1ASN1StreamParser;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILOrgSpongycastleAsn1ASN1StreamParser;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1BERApplicationSpecificParser = { "BERApplicationSpecificParser", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1BERApplicationSpecificParser;
}

@end

void OrgSpongycastleAsn1BERApplicationSpecificParser_initWithInt_withOrgSpongycastleAsn1ASN1StreamParser_(OrgSpongycastleAsn1BERApplicationSpecificParser *self, jint tag, OrgSpongycastleAsn1ASN1StreamParser *parser) {
  NSObject_init(self);
  self->tag_ = tag;
  self->parser_ = parser;
}

OrgSpongycastleAsn1BERApplicationSpecificParser *new_OrgSpongycastleAsn1BERApplicationSpecificParser_initWithInt_withOrgSpongycastleAsn1ASN1StreamParser_(jint tag, OrgSpongycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1BERApplicationSpecificParser, initWithInt_withOrgSpongycastleAsn1ASN1StreamParser_, tag, parser)
}

OrgSpongycastleAsn1BERApplicationSpecificParser *create_OrgSpongycastleAsn1BERApplicationSpecificParser_initWithInt_withOrgSpongycastleAsn1ASN1StreamParser_(jint tag, OrgSpongycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1BERApplicationSpecificParser, initWithInt_withOrgSpongycastleAsn1ASN1StreamParser_, tag, parser)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1BERApplicationSpecificParser)