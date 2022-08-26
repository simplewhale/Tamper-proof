//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/DERUTF8String.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/asn1/ASN1OctetString.h"
#include "org/spongycastle/asn1/ASN1OutputStream.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1TaggedObject.h"
#include "org/spongycastle/asn1/BERTags.h"
#include "org/spongycastle/asn1/DERUTF8String.h"
#include "org/spongycastle/asn1/StreamUtil.h"
#include "org/spongycastle/util/Arrays.h"
#include "org/spongycastle/util/Strings.h"

@interface OrgSpongycastleAsn1DERUTF8String () {
 @public
  IOSByteArray *string_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1DERUTF8String, string_, IOSByteArray *)

@implementation OrgSpongycastleAsn1DERUTF8String

+ (OrgSpongycastleAsn1DERUTF8String *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1DERUTF8String_getInstanceWithId_(obj);
}

+ (OrgSpongycastleAsn1DERUTF8String *)getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:(OrgSpongycastleAsn1ASN1TaggedObject *)obj
                                                                             withBoolean:(jboolean)explicit_ {
  return OrgSpongycastleAsn1DERUTF8String_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithByteArray:(IOSByteArray *)string {
  OrgSpongycastleAsn1DERUTF8String_initWithByteArray_(self, string);
  return self;
}

- (instancetype)initWithNSString:(NSString *)string {
  OrgSpongycastleAsn1DERUTF8String_initWithNSString_(self, string);
  return self;
}

- (NSString *)getString {
  return OrgSpongycastleUtilStrings_fromUTF8ByteArrayWithByteArray_(string_);
}

- (NSString *)description {
  return [self getString];
}

- (NSUInteger)hash {
  return OrgSpongycastleUtilArrays_hashCodeWithByteArray_(string_);
}

- (jboolean)asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)o {
  if (!([o isKindOfClass:[OrgSpongycastleAsn1DERUTF8String class]])) {
    return false;
  }
  OrgSpongycastleAsn1DERUTF8String *s = (OrgSpongycastleAsn1DERUTF8String *) cast_chk(o, [OrgSpongycastleAsn1DERUTF8String class]);
  return OrgSpongycastleUtilArrays_areEqualWithByteArray_withByteArray_(string_, ((OrgSpongycastleAsn1DERUTF8String *) nil_chk(s))->string_);
}

- (jboolean)isConstructed {
  return false;
}

- (jint)encodedLength {
  return 1 + OrgSpongycastleAsn1StreamUtil_calculateBodyLengthWithInt_(((IOSByteArray *) nil_chk(string_))->size_) + string_->size_;
}

- (void)encodeWithOrgSpongycastleAsn1ASN1OutputStream:(OrgSpongycastleAsn1ASN1OutputStream *)outArg {
  [((OrgSpongycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeEncodedWithInt:OrgSpongycastleAsn1BERTags_UTF8_STRING withByteArray:string_];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSpongycastleAsn1DERUTF8String;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1DERUTF8String;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, 7, 8, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, 9, -1, -1, -1 },
    { NULL, "V", 0x0, 10, 11, 9, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithByteArray:);
  methods[3].selector = @selector(initWithNSString:);
  methods[4].selector = @selector(getString);
  methods[5].selector = @selector(description);
  methods[6].selector = @selector(hash);
  methods[7].selector = @selector(asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[8].selector = @selector(isConstructed);
  methods[9].selector = @selector(encodedLength);
  methods[10].selector = @selector(encodeWithOrgSpongycastleAsn1ASN1OutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "string_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LOrgSpongycastleAsn1ASN1TaggedObject;Z", "[B", "LNSString;", "toString", "hashCode", "asn1Equals", "LOrgSpongycastleAsn1ASN1Primitive;", "LJavaIoIOException;", "encode", "LOrgSpongycastleAsn1ASN1OutputStream;" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1DERUTF8String = { "DERUTF8String", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 11, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1DERUTF8String;
}

@end

OrgSpongycastleAsn1DERUTF8String *OrgSpongycastleAsn1DERUTF8String_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1DERUTF8String_initialize();
  if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1DERUTF8String class]]) {
    return (OrgSpongycastleAsn1DERUTF8String *) cast_chk(obj, [OrgSpongycastleAsn1DERUTF8String class]);
  }
  if ([obj isKindOfClass:[IOSByteArray class]]) {
    @try {
      return (OrgSpongycastleAsn1DERUTF8String *) cast_chk(OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])), [OrgSpongycastleAsn1DERUTF8String class]);
    }
    @catch (JavaLangException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"encoding error in getInstance: ", [e description]));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

OrgSpongycastleAsn1DERUTF8String *OrgSpongycastleAsn1DERUTF8String_getInstanceWithOrgSpongycastleAsn1ASN1TaggedObject_withBoolean_(OrgSpongycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  OrgSpongycastleAsn1DERUTF8String_initialize();
  OrgSpongycastleAsn1ASN1Primitive *o = [((OrgSpongycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject];
  if (explicit_ || [o isKindOfClass:[OrgSpongycastleAsn1DERUTF8String class]]) {
    return OrgSpongycastleAsn1DERUTF8String_getInstanceWithId_(o);
  }
  else {
    return new_OrgSpongycastleAsn1DERUTF8String_initWithByteArray_([((OrgSpongycastleAsn1ASN1OctetString *) nil_chk(OrgSpongycastleAsn1ASN1OctetString_getInstanceWithId_(o))) getOctets]);
  }
}

void OrgSpongycastleAsn1DERUTF8String_initWithByteArray_(OrgSpongycastleAsn1DERUTF8String *self, IOSByteArray *string) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  self->string_ = string;
}

OrgSpongycastleAsn1DERUTF8String *new_OrgSpongycastleAsn1DERUTF8String_initWithByteArray_(IOSByteArray *string) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERUTF8String, initWithByteArray_, string)
}

OrgSpongycastleAsn1DERUTF8String *create_OrgSpongycastleAsn1DERUTF8String_initWithByteArray_(IOSByteArray *string) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERUTF8String, initWithByteArray_, string)
}

void OrgSpongycastleAsn1DERUTF8String_initWithNSString_(OrgSpongycastleAsn1DERUTF8String *self, NSString *string) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  self->string_ = OrgSpongycastleUtilStrings_toUTF8ByteArrayWithNSString_(string);
}

OrgSpongycastleAsn1DERUTF8String *new_OrgSpongycastleAsn1DERUTF8String_initWithNSString_(NSString *string) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1DERUTF8String, initWithNSString_, string)
}

OrgSpongycastleAsn1DERUTF8String *create_OrgSpongycastleAsn1DERUTF8String_initWithNSString_(NSString *string) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1DERUTF8String, initWithNSString_, string)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1DERUTF8String)