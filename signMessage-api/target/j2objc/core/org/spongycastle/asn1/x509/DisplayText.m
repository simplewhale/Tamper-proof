//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/x509/DisplayText.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1Object.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1String.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/DERBMPString.h"
#include "org/spongycastle/asn1/DERIA5String.h"
#include "org/spongycastle/asn1/DERUTF8String.h"
#include "org/spongycastle/asn1/DERVisibleString.h"
#include "org/spongycastle/asn1/x509/DisplayText.h"

@interface OrgSpongycastleAsn1X509DisplayText ()

- (instancetype)initWithOrgSpongycastleAsn1ASN1String:(id<OrgSpongycastleAsn1ASN1String>)de;

@end

__attribute__((unused)) static void OrgSpongycastleAsn1X509DisplayText_initWithOrgSpongycastleAsn1ASN1String_(OrgSpongycastleAsn1X509DisplayText *self, id<OrgSpongycastleAsn1ASN1String> de);

__attribute__((unused)) static OrgSpongycastleAsn1X509DisplayText *new_OrgSpongycastleAsn1X509DisplayText_initWithOrgSpongycastleAsn1ASN1String_(id<OrgSpongycastleAsn1ASN1String> de) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSpongycastleAsn1X509DisplayText *create_OrgSpongycastleAsn1X509DisplayText_initWithOrgSpongycastleAsn1ASN1String_(id<OrgSpongycastleAsn1ASN1String> de);

@implementation OrgSpongycastleAsn1X509DisplayText

- (instancetype)initWithInt:(jint)type
               withNSString:(NSString *)text {
  OrgSpongycastleAsn1X509DisplayText_initWithInt_withNSString_(self, type, text);
  return self;
}

- (instancetype)initWithNSString:(NSString *)text {
  OrgSpongycastleAsn1X509DisplayText_initWithNSString_(self, text);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1String:(id<OrgSpongycastleAsn1ASN1String>)de {
  OrgSpongycastleAsn1X509DisplayText_initWithOrgSpongycastleAsn1ASN1String_(self, de);
  return self;
}

+ (OrgSpongycastleAsn1X509DisplayText *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1X509DisplayText_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1X509DisplayText *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                               withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1X509DisplayText_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive {
  return (OrgSpongycastleAsn1ASN1Primitive *) cast_chk(contents_, [OrgSpongycastleAsn1ASN1Primitive class]);
}

- (NSString *)getString {
  return [((id<OrgSpongycastleAsn1ASN1String>) nil_chk(contents_)) getString];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 2, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509DisplayText;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1X509DisplayText;", 0x9, 3, 5, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withNSString:);
  methods[1].selector = @selector(initWithNSString:);
  methods[2].selector = @selector(initWithOrgSpongycastleAsn1ASN1String:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[5].selector = @selector(toASN1Primitive);
  methods[6].selector = @selector(getString);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "CONTENT_TYPE_IA5STRING", "I", .constantValue.asInt = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_IA5STRING, 0x19, -1, -1, -1, -1 },
    { "CONTENT_TYPE_BMPSTRING", "I", .constantValue.asInt = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_BMPSTRING, 0x19, -1, -1, -1, -1 },
    { "CONTENT_TYPE_UTF8STRING", "I", .constantValue.asInt = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_UTF8STRING, 0x19, -1, -1, -1, -1 },
    { "CONTENT_TYPE_VISIBLESTRING", "I", .constantValue.asInt = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_VISIBLESTRING, 0x19, -1, -1, -1, -1 },
    { "DISPLAY_TEXT_MAXIMUM_SIZE", "I", .constantValue.asInt = OrgSpongycastleAsn1X509DisplayText_DISPLAY_TEXT_MAXIMUM_SIZE, 0x19, -1, -1, -1, -1 },
    { "contentType_", "I", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "contents_", "LOrgSpongycastleAsn1ASN1String;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILNSString;", "LNSString;", "LOrgSpongycastleAsn1ASN1String;", "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1X509DisplayText = { "DisplayText", "org.spongycastle.asn1.x509", ptrTable, methods, fields, 7, 0x1, 7, 7, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1X509DisplayText;
}

@end

void OrgSpongycastleAsn1X509DisplayText_initWithInt_withNSString_(OrgSpongycastleAsn1X509DisplayText *self, jint type, NSString *text) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((NSString *) nil_chk(text)) java_length] > OrgSpongycastleAsn1X509DisplayText_DISPLAY_TEXT_MAXIMUM_SIZE) {
    text = [text java_substring:0 endIndex:OrgSpongycastleAsn1X509DisplayText_DISPLAY_TEXT_MAXIMUM_SIZE];
  }
  self->contentType_ = type;
  switch (type) {
    case OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_IA5STRING:
    self->contents_ = new_OrgSpongycastleAsn1DERIA5String_initWithNSString_(text);
    break;
    case OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_UTF8STRING:
    self->contents_ = new_OrgSpongycastleAsn1DERUTF8String_initWithNSString_(text);
    break;
    case OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_VISIBLESTRING:
    self->contents_ = new_OrgSpongycastleAsn1DERVisibleString_initWithNSString_(text);
    break;
    case OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_BMPSTRING:
    self->contents_ = new_OrgSpongycastleAsn1DERBMPString_initWithNSString_(text);
    break;
    default:
    self->contents_ = new_OrgSpongycastleAsn1DERUTF8String_initWithNSString_(text);
    break;
  }
}

OrgSpongycastleAsn1X509DisplayText *new_OrgSpongycastleAsn1X509DisplayText_initWithInt_withNSString_(jint type, NSString *text) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509DisplayText, initWithInt_withNSString_, type, text)
}

OrgSpongycastleAsn1X509DisplayText *create_OrgSpongycastleAsn1X509DisplayText_initWithInt_withNSString_(jint type, NSString *text) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509DisplayText, initWithInt_withNSString_, type, text)
}

void OrgSpongycastleAsn1X509DisplayText_initWithNSString_(OrgSpongycastleAsn1X509DisplayText *self, NSString *text) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  if ([((NSString *) nil_chk(text)) java_length] > OrgSpongycastleAsn1X509DisplayText_DISPLAY_TEXT_MAXIMUM_SIZE) {
    text = [text java_substring:0 endIndex:OrgSpongycastleAsn1X509DisplayText_DISPLAY_TEXT_MAXIMUM_SIZE];
  }
  self->contentType_ = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_UTF8STRING;
  self->contents_ = new_OrgSpongycastleAsn1DERUTF8String_initWithNSString_(text);
}

OrgSpongycastleAsn1X509DisplayText *new_OrgSpongycastleAsn1X509DisplayText_initWithNSString_(NSString *text) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509DisplayText, initWithNSString_, text)
}

OrgSpongycastleAsn1X509DisplayText *create_OrgSpongycastleAsn1X509DisplayText_initWithNSString_(NSString *text) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509DisplayText, initWithNSString_, text)
}

void OrgSpongycastleAsn1X509DisplayText_initWithOrgSpongycastleAsn1ASN1String_(OrgSpongycastleAsn1X509DisplayText *self, id<OrgSpongycastleAsn1ASN1String> de) {
  OrgSpongycastleAsn1ASN1Object_init(self);
  self->contents_ = de;
  if ([de isKindOfClass:[OrgSpongycastleAsn1DERUTF8String class]]) {
    self->contentType_ = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_UTF8STRING;
  }
  else if ([de isKindOfClass:[OrgSpongycastleAsn1DERBMPString class]]) {
    self->contentType_ = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_BMPSTRING;
  }
  else if ([de isKindOfClass:[OrgSpongycastleAsn1DERIA5String class]]) {
    self->contentType_ = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_IA5STRING;
  }
  else if ([de isKindOfClass:[OrgSpongycastleAsn1DERVisibleString class]]) {
    self->contentType_ = OrgSpongycastleAsn1X509DisplayText_CONTENT_TYPE_VISIBLESTRING;
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown STRING type in DisplayText");
  }
}

OrgSpongycastleAsn1X509DisplayText *new_OrgSpongycastleAsn1X509DisplayText_initWithOrgSpongycastleAsn1ASN1String_(id<OrgSpongycastleAsn1ASN1String> de) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1X509DisplayText, initWithOrgSpongycastleAsn1ASN1String_, de)
}

OrgSpongycastleAsn1X509DisplayText *create_OrgSpongycastleAsn1X509DisplayText_initWithOrgSpongycastleAsn1ASN1String_(id<OrgSpongycastleAsn1ASN1String> de) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1X509DisplayText, initWithOrgSpongycastleAsn1ASN1String_, de)
}

OrgSpongycastleAsn1X509DisplayText *OrgSpongycastleAsn1X509DisplayText_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1X509DisplayText_initialize();
  if ([OrgSpongycastleAsn1ASN1String_class_() isInstance:obj]) {
    return new_OrgSpongycastleAsn1X509DisplayText_initWithOrgSpongycastleAsn1ASN1String_((id<OrgSpongycastleAsn1ASN1String>) cast_check(obj, OrgSpongycastleAsn1ASN1String_class_()));
  }
  else if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1X509DisplayText class]]) {
    return (OrgSpongycastleAsn1X509DisplayText *) cast_chk(obj, [OrgSpongycastleAsn1X509DisplayText class]);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

OrgSpongycastleAsn1X509DisplayText *OrgSpongycastleAsn1X509DisplayText_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1X509DisplayText_initialize();
  return OrgSpongycastleAsn1X509DisplayText_getInstanceWithId_([((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1X509DisplayText)
