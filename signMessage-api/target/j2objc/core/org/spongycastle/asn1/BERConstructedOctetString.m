//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/BERConstructedOctetString.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/lang/ClassCastException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/util/Enumeration.h"
#include "java/util/Vector.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/ASN1Sequence.h"
#include "org/spongycastle/asn1/BERConstructedOctetString.h"
#include "org/spongycastle/asn1/BEROctetString.h"
#include "org/spongycastle/asn1/DEROctetString.h"

@interface OrgSpongycastleAsn1BERConstructedOctetString () {
 @public
  JavaUtilVector *octs_BERConstructedOctetString_;
}

+ (IOSByteArray *)toBytesWithJavaUtilVector:(JavaUtilVector *)octs;

+ (IOSByteArray *)toByteArrayWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)obj;

- (JavaUtilVector *)generateOcts;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleAsn1BERConstructedOctetString, octs_BERConstructedOctetString_, JavaUtilVector *)

inline jint OrgSpongycastleAsn1BERConstructedOctetString_get_MAX_LENGTH(void);
#define OrgSpongycastleAsn1BERConstructedOctetString_MAX_LENGTH 1000
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleAsn1BERConstructedOctetString, MAX_LENGTH, jint)

__attribute__((unused)) static IOSByteArray *OrgSpongycastleAsn1BERConstructedOctetString_toBytesWithJavaUtilVector_(JavaUtilVector *octs);

__attribute__((unused)) static IOSByteArray *OrgSpongycastleAsn1BERConstructedOctetString_toByteArrayWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *obj);

__attribute__((unused)) static JavaUtilVector *OrgSpongycastleAsn1BERConstructedOctetString_generateOcts(OrgSpongycastleAsn1BERConstructedOctetString *self);

@implementation OrgSpongycastleAsn1BERConstructedOctetString

+ (IOSByteArray *)toBytesWithJavaUtilVector:(JavaUtilVector *)octs {
  return OrgSpongycastleAsn1BERConstructedOctetString_toBytesWithJavaUtilVector_(octs);
}

- (instancetype)initWithByteArray:(IOSByteArray *)string {
  OrgSpongycastleAsn1BERConstructedOctetString_initWithByteArray_(self, string);
  return self;
}

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)octs {
  OrgSpongycastleAsn1BERConstructedOctetString_initWithJavaUtilVector_(self, octs);
  return self;
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)obj {
  OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Primitive_(self, obj);
  return self;
}

+ (IOSByteArray *)toByteArrayWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)obj {
  return OrgSpongycastleAsn1BERConstructedOctetString_toByteArrayWithOrgSpongycastleAsn1ASN1Primitive_(obj);
}

- (instancetype)initWithOrgSpongycastleAsn1ASN1Encodable:(id<OrgSpongycastleAsn1ASN1Encodable>)obj {
  OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Encodable_(self, obj);
  return self;
}

- (IOSByteArray *)getOctets {
  return string_;
}

- (id<JavaUtilEnumeration>)getObjects {
  if (octs_BERConstructedOctetString_ == nil) {
    return [((JavaUtilVector *) nil_chk(OrgSpongycastleAsn1BERConstructedOctetString_generateOcts(self))) elements];
  }
  return [octs_BERConstructedOctetString_ elements];
}

- (JavaUtilVector *)generateOcts {
  return OrgSpongycastleAsn1BERConstructedOctetString_generateOcts(self);
}

+ (OrgSpongycastleAsn1BEROctetString *)fromSequenceWithOrgSpongycastleAsn1ASN1Sequence:(OrgSpongycastleAsn1ASN1Sequence *)seq {
  return OrgSpongycastleAsn1BERConstructedOctetString_fromSequenceWithOrgSpongycastleAsn1ASN1Sequence_(seq);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "[B", 0xa, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0xa, 4, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilVector;", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1BEROctetString;", 0x9, 6, 7, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(toBytesWithJavaUtilVector:);
  methods[1].selector = @selector(initWithByteArray:);
  methods[2].selector = @selector(initWithJavaUtilVector:);
  methods[3].selector = @selector(initWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[4].selector = @selector(toByteArrayWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[5].selector = @selector(initWithOrgSpongycastleAsn1ASN1Encodable:);
  methods[6].selector = @selector(getOctets);
  methods[7].selector = @selector(getObjects);
  methods[8].selector = @selector(generateOcts);
  methods[9].selector = @selector(fromSequenceWithOrgSpongycastleAsn1ASN1Sequence:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "MAX_LENGTH", "I", .constantValue.asInt = OrgSpongycastleAsn1BERConstructedOctetString_MAX_LENGTH, 0x1a, -1, -1, -1, -1 },
    { "octs_BERConstructedOctetString_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x2, 8, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "toBytes", "LJavaUtilVector;", "[B", "LOrgSpongycastleAsn1ASN1Primitive;", "toByteArray", "LOrgSpongycastleAsn1ASN1Encodable;", "fromSequence", "LOrgSpongycastleAsn1ASN1Sequence;", "octs" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1BERConstructedOctetString = { "BERConstructedOctetString", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x1, 10, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1BERConstructedOctetString;
}

@end

IOSByteArray *OrgSpongycastleAsn1BERConstructedOctetString_toBytesWithJavaUtilVector_(JavaUtilVector *octs) {
  OrgSpongycastleAsn1BERConstructedOctetString_initialize();
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  for (jint i = 0; i != [((JavaUtilVector *) nil_chk(octs)) size]; i++) {
    @try {
      OrgSpongycastleAsn1DEROctetString *o = (OrgSpongycastleAsn1DEROctetString *) cast_chk([octs elementAtWithInt:i], [OrgSpongycastleAsn1DEROctetString class]);
      [bOut writeWithByteArray:[((OrgSpongycastleAsn1DEROctetString *) nil_chk(o)) getOctets]];
    }
    @catch (JavaLangClassCastException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", [[nil_chk([octs elementAtWithInt:i]) java_getClass] getName], @" found in input should only contain DEROctetString"));
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"exception converting octets ", [e description]));
    }
  }
  return [bOut toByteArray];
}

void OrgSpongycastleAsn1BERConstructedOctetString_initWithByteArray_(OrgSpongycastleAsn1BERConstructedOctetString *self, IOSByteArray *string) {
  OrgSpongycastleAsn1BEROctetString_initWithByteArray_(self, string);
}

OrgSpongycastleAsn1BERConstructedOctetString *new_OrgSpongycastleAsn1BERConstructedOctetString_initWithByteArray_(IOSByteArray *string) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1BERConstructedOctetString, initWithByteArray_, string)
}

OrgSpongycastleAsn1BERConstructedOctetString *create_OrgSpongycastleAsn1BERConstructedOctetString_initWithByteArray_(IOSByteArray *string) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1BERConstructedOctetString, initWithByteArray_, string)
}

void OrgSpongycastleAsn1BERConstructedOctetString_initWithJavaUtilVector_(OrgSpongycastleAsn1BERConstructedOctetString *self, JavaUtilVector *octs) {
  OrgSpongycastleAsn1BEROctetString_initWithByteArray_(self, OrgSpongycastleAsn1BERConstructedOctetString_toBytesWithJavaUtilVector_(octs));
  self->octs_BERConstructedOctetString_ = octs;
}

OrgSpongycastleAsn1BERConstructedOctetString *new_OrgSpongycastleAsn1BERConstructedOctetString_initWithJavaUtilVector_(JavaUtilVector *octs) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1BERConstructedOctetString, initWithJavaUtilVector_, octs)
}

OrgSpongycastleAsn1BERConstructedOctetString *create_OrgSpongycastleAsn1BERConstructedOctetString_initWithJavaUtilVector_(JavaUtilVector *octs) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1BERConstructedOctetString, initWithJavaUtilVector_, octs)
}

void OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1BERConstructedOctetString *self, OrgSpongycastleAsn1ASN1Primitive *obj) {
  OrgSpongycastleAsn1BEROctetString_initWithByteArray_(self, OrgSpongycastleAsn1BERConstructedOctetString_toByteArrayWithOrgSpongycastleAsn1ASN1Primitive_(obj));
}

OrgSpongycastleAsn1BERConstructedOctetString *new_OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *obj) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1BERConstructedOctetString, initWithOrgSpongycastleAsn1ASN1Primitive_, obj)
}

OrgSpongycastleAsn1BERConstructedOctetString *create_OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *obj) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1BERConstructedOctetString, initWithOrgSpongycastleAsn1ASN1Primitive_, obj)
}

IOSByteArray *OrgSpongycastleAsn1BERConstructedOctetString_toByteArrayWithOrgSpongycastleAsn1ASN1Primitive_(OrgSpongycastleAsn1ASN1Primitive *obj) {
  OrgSpongycastleAsn1BERConstructedOctetString_initialize();
  @try {
    return [((OrgSpongycastleAsn1ASN1Primitive *) nil_chk(obj)) getEncoded];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Unable to encode object");
  }
}

void OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Encodable_(OrgSpongycastleAsn1BERConstructedOctetString *self, id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Primitive_(self, [((id<OrgSpongycastleAsn1ASN1Encodable>) nil_chk(obj)) toASN1Primitive]);
}

OrgSpongycastleAsn1BERConstructedOctetString *new_OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Encodable_(id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  J2OBJC_NEW_IMPL(OrgSpongycastleAsn1BERConstructedOctetString, initWithOrgSpongycastleAsn1ASN1Encodable_, obj)
}

OrgSpongycastleAsn1BERConstructedOctetString *create_OrgSpongycastleAsn1BERConstructedOctetString_initWithOrgSpongycastleAsn1ASN1Encodable_(id<OrgSpongycastleAsn1ASN1Encodable> obj) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleAsn1BERConstructedOctetString, initWithOrgSpongycastleAsn1ASN1Encodable_, obj)
}

JavaUtilVector *OrgSpongycastleAsn1BERConstructedOctetString_generateOcts(OrgSpongycastleAsn1BERConstructedOctetString *self) {
  JavaUtilVector *vec = new_JavaUtilVector_init();
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(self->string_))->size_; i += OrgSpongycastleAsn1BERConstructedOctetString_MAX_LENGTH) {
    jint end;
    if (i + OrgSpongycastleAsn1BERConstructedOctetString_MAX_LENGTH > self->string_->size_) {
      end = self->string_->size_;
    }
    else {
      end = i + OrgSpongycastleAsn1BERConstructedOctetString_MAX_LENGTH;
    }
    IOSByteArray *nStr = [IOSByteArray newArrayWithLength:end - i];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(self->string_, i, nStr, 0, nStr->size_);
    [vec addElementWithId:new_OrgSpongycastleAsn1DEROctetString_initWithByteArray_(nStr)];
  }
  return vec;
}

OrgSpongycastleAsn1BEROctetString *OrgSpongycastleAsn1BERConstructedOctetString_fromSequenceWithOrgSpongycastleAsn1ASN1Sequence_(OrgSpongycastleAsn1ASN1Sequence *seq) {
  OrgSpongycastleAsn1BERConstructedOctetString_initialize();
  JavaUtilVector *v = new_JavaUtilVector_init();
  id<JavaUtilEnumeration> e = [((OrgSpongycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  while ([((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements]) {
    [v addElementWithId:[e nextElement]];
  }
  return new_OrgSpongycastleAsn1BERConstructedOctetString_initWithJavaUtilVector_(v);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1BERConstructedOctetString)
