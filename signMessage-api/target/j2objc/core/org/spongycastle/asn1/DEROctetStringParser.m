//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/DEROctetStringParser.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"
#include "org/spongycastle/asn1/ASN1ParsingException.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/DEROctetString.h"
#include "org/spongycastle/asn1/DEROctetStringParser.h"
#include "org/spongycastle/asn1/DefiniteLengthInputStream.h"

@interface OrgSpongycastleAsn1DEROctetStringParser () {
 @public
  OrgSpongycastleAsn1DefiniteLengthInputStream *stream_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DEROctetStringParser, stream_, OrgSpongycastleAsn1DefiniteLengthInputStream *)

@implementation OrgSpongycastleAsn1DEROctetStringParser

- (instancetype)initWithOrgSpongycastleAsn1DefiniteLengthInputStream:(OrgSpongycastleAsn1DefiniteLengthInputStream *)stream {
  OrgSpongycastleAsn1DEROctetStringParser_initWithOrgSpongycastleAsn1DefiniteLengthInputStream_(self, stream);
  return self;
}

- (JavaIoInputStream *)getOctetStream {
  return stream_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)getLoadedObject {
  return new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_([((OrgSpongycastleAsn1DefiniteLengthInputStream *) nil_chk(stream_)) toByteArray]);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  @try {
    return [self getLoadedObject];
  }
  @catch (JavaIoIOException *e) {
    @throw new_OrgSpongycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"IOException converting stream to byte array: ", [e getMessage]), e);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaIoInputStream;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleAsn1DefiniteLengthInputStream:);
  methods[1].selector = @selector(getOctetStream);
  methods[2].selector = @selector(getLoadedObject);
  methods[3].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "stream_", "LOrgSpongycastleAsn1DefiniteLengthInputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleAsn1DefiniteLengthInputStream;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1DEROctetStringParser = { "DEROctetStringParser", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1DEROctetStringParser;
}

@end

void OrgSpongycastleAsn1DEROctetStringParser_initWithOrgSpongycastleAsn1DefiniteLengthInputStream_(OrgSpongycastleAsn1DEROctetStringParser *self, OrgSpongycastleAsn1DefiniteLengthInputStream *stream) {
  NSObject_init(self);
  self->stream_ = stream;
}

OrgSpongycastleAsn1DEROctetStringParser *new_OrgSpongycastleAsn1DEROctetStringParser_initWithOrgSpongycastleAsn1DefiniteLengthInputStream_(OrgSpongycastleAsn1DefiniteLengthInputStream *stream) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DEROctetStringParser, initWithOrgSpongycastleAsn1DefiniteLengthInputStream_, stream)
}

OrgSpongycastleAsn1DEROctetStringParser *create_OrgSpongycastleAsn1DEROctetStringParser_initWithOrgSpongycastleAsn1DefiniteLengthInputStream_(OrgSpongycastleAsn1DefiniteLengthInputStream *stream) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DEROctetStringParser, initWithOrgSpongycastleAsn1DefiniteLengthInputStream_, stream)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1DEROctetStringParser)
