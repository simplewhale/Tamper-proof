//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/DERSequenceParser.java
//

#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalStateException.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1EncodableVector.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1StreamParser.h"
#include "org/spongycastle/asn1/DERSequence.h"
#include "org/spongycastle/asn1/DERSequenceParser.h"

@interface OrgSpongycastleAsn1DERSequenceParser () {
 @public
  OrgSpongycastleAsn1ASN1StreamParser *_parser_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DERSequenceParser, _parser_, OrgSpongycastleAsn1ASN1StreamParser *)

@implementation OrgSpongycastleAsn1DERSequenceParser

- (instancetype)initWithOrgSpongycastleAsn1ASN1StreamParser:(OrgSpongycastleAsn1ASN1StreamParser *)parser {
  OrgSpongycastleAsn1DERSequenceParser_initWithOrgSpongycastleAsn1ASN1StreamParser_(self, parser);
  return self;
}

- (id<OrgSpongycastleAsn1ASN1Encodable>)readObject {
  return [((OrgSpongycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readObject];
}

- (OrgSpongycastleAsn1ASN1Primitive *)getLoadedObject {
  return new_OrgSpongycastleAsn1DERSequence_initWithOrgSpongycastleAsn1ASN1EncodableVector_([((OrgSpongycastleAsn1ASN1StreamParser *) nil_chk(_parser_)) readVector]);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  @try {
    return [self getLoadedObject];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalStateException_initWithNSString_([e getMessage]);
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
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1ASN1StreamParser:);
  methods[1].selector = @selector(readObject);
  methods[2].selector = @selector(getLoadedObject);
  methods[3].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_parser_", "LOrgSpongycastleAsn1ASN1StreamParser;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1ASN1StreamParser;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1DERSequenceParser = { "DERSequenceParser", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1DERSequenceParser;
}

@end

void OrgSpongycastleAsn1DERSequenceParser_initWithOrgSpongycastleAsn1ASN1StreamParser_(OrgSpongycastleAsn1DERSequenceParser *self, OrgSpongycastleAsn1ASN1StreamParser *parser) {
  NSObject_init(self);
  self->_parser_ = parser;
}

OrgSpongycastleAsn1DERSequenceParser *new_OrgSpongycastleAsn1DERSequenceParser_initWithOrgSpongycastleAsn1ASN1StreamParser_(OrgSpongycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERSequenceParser, initWithOrgSpongycastleAsn1ASN1StreamParser_, parser)
}

OrgSpongycastleAsn1DERSequenceParser *create_OrgSpongycastleAsn1DERSequenceParser_initWithOrgSpongycastleAsn1ASN1StreamParser_(OrgSpongycastleAsn1ASN1StreamParser *parser) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERSequenceParser, initWithOrgSpongycastleAsn1ASN1StreamParser_, parser)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1DERSequenceParser)