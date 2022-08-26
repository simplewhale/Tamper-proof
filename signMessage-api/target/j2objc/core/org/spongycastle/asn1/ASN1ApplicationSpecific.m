//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/ASN1ApplicationSpecific.java
//

#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "org/spongycastle/asn1/ASN1ApplicationSpecific.h"
#include "org/spongycastle/asn1/ASN1OutputStream.h"
#include "org/spongycastle/asn1/ASN1ParsingException.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/BERTags.h"
#include "org/spongycastle/asn1/StreamUtil.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleAsn1ASN1ApplicationSpecific ()

- (IOSByteArray *)replaceTagNumberWithInt:(jint)newTag
                            withByteArray:(IOSByteArray *)input;

@end

__attribute__((unused)) static IOSByteArray *OrgSpongycastleAsn1ASN1ApplicationSpecific_replaceTagNumberWithInt_withByteArray_(OrgSpongycastleAsn1ASN1ApplicationSpecific *self, jint newTag, IOSByteArray *input);

@implementation OrgSpongycastleAsn1ASN1ApplicationSpecific

- (instancetype)initWithBoolean:(jboolean)isConstructed
                        withInt:(jint)tag
                  withByteArray:(IOSByteArray *)octets {
  OrgSpongycastleAsn1ASN1ApplicationSpecific_initWithBoolean_withInt_withByteArray_(self, isConstructed, tag, octets);
  return self;
}

+ (OrgSpongycastleAsn1ASN1ApplicationSpecific *)getInstanceWithId:(id)obj {
  return OrgSpongycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_(obj);
}

+ (jint)getLengthOfHeaderWithByteArray:(IOSByteArray *)data {
  return OrgSpongycastleAsn1ASN1ApplicationSpecific_getLengthOfHeaderWithByteArray_(data);
}

- (jboolean)isConstructed {
  return isConstructed_;
}

- (IOSByteArray *)getContents {
  return OrgSpongycastleUtilArrays_cloneWithByteArray_(octets_);
}

- (jint)getApplicationTag {
  return tag_;
}

- (OrgSpongycastleAsn1ASN1Primitive *)getObject {
  return OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_([self getContents]);
}

- (OrgSpongycastleAsn1ASN1Primitive *)getObjectWithInt:(jint)derTagNo {
  if (derTagNo >= (jint) 0x1f) {
    @throw new_JavaIoIOException_initWithNSString_(@"unsupported tag number");
  }
  IOSByteArray *orig = [self getEncoded];
  IOSByteArray *tmp = OrgSpongycastleAsn1ASN1ApplicationSpecific_replaceTagNumberWithInt_withByteArray_(self, derTagNo, orig);
  if ((IOSByteArray_Get(nil_chk(orig), 0) & OrgSpongycastleAsn1BERTags_CONSTRUCTED) != 0) {
    *IOSByteArray_GetRef(nil_chk(tmp), 0) |= OrgSpongycastleAsn1BERTags_CONSTRUCTED;
  }
  return OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(tmp);
}

- (jint)encodedLength {
  return OrgSpongycastleAsn1StreamUtil_calculateTagLengthWithInt_(tag_) + OrgSpongycastleAsn1StreamUtil_calculateBodyLengthWithInt_(((IOSByteArray *) nil_chk(octets_))->size_) + octets_->size_;
}

- (void)encodeWithOrgSpongycastleAsn1ASN1OutputStream:(OrgSpongycastleAsn1ASN1OutputStream *)outArg {
  jint classBits = OrgSpongycastleAsn1BERTags_APPLICATION;
  if (isConstructed_) {
    classBits |= OrgSpongycastleAsn1BERTags_CONSTRUCTED;
  }
  [((OrgSpongycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeEncodedWithInt:classBits withInt:tag_ withByteArray:octets_];
}

- (jboolean)asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:(OrgSpongycastleAsn1ASN1Primitive *)o {
  if (!([o isKindOfClass:[OrgSpongycastleAsn1ASN1ApplicationSpecific class]])) {
    return false;
  }
  OrgSpongycastleAsn1ASN1ApplicationSpecific *other = (OrgSpongycastleAsn1ASN1ApplicationSpecific *) cast_chk(o, [OrgSpongycastleAsn1ASN1ApplicationSpecific class]);
  return isConstructed_ == ((OrgSpongycastleAsn1ASN1ApplicationSpecific *) nil_chk(other))->isConstructed_ && tag_ == other->tag_ && OrgSpongycastleUtilArrays_areEqualWithByteArray_withByteArray_(octets_, other->octets_);
}

- (NSUInteger)hash {
  return (isConstructed_ ? 1 : 0) ^ tag_ ^ OrgSpongycastleUtilArrays_hashCodeWithByteArray_(octets_);
}

- (IOSByteArray *)replaceTagNumberWithInt:(jint)newTag
                            withByteArray:(IOSByteArray *)input {
  return OrgSpongycastleAsn1ASN1ApplicationSpecific_replaceTagNumberWithInt_withByteArray_(self, newTag, input);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1ApplicationSpecific;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0xc, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, -1, -1, 5, -1, -1, -1 },
    { NULL, "LOrgSpongycastleAsn1ASN1Primitive;", 0x1, 6, 7, 5, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, 5, -1, -1, -1 },
    { NULL, "V", 0x0, 8, 9, 5, -1, -1, -1 },
    { NULL, "Z", 0x0, 10, 11, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 12, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 13, 14, 5, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withInt:withByteArray:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(getLengthOfHeaderWithByteArray:);
  methods[3].selector = @selector(isConstructed);
  methods[4].selector = @selector(getContents);
  methods[5].selector = @selector(getApplicationTag);
  methods[6].selector = @selector(getObject);
  methods[7].selector = @selector(getObjectWithInt:);
  methods[8].selector = @selector(encodedLength);
  methods[9].selector = @selector(encodeWithOrgSpongycastleAsn1ASN1OutputStream:);
  methods[10].selector = @selector(asn1EqualsWithOrgSpongycastleAsn1ASN1Primitive:);
  methods[11].selector = @selector(hash);
  methods[12].selector = @selector(replaceTagNumberWithInt:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "isConstructed_", "Z", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "tag_", "I", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "octets_", "[B", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZI[B", "getInstance", "LNSObject;", "getLengthOfHeader", "[B", "LJavaIoIOException;", "getObject", "I", "encode", "LOrgSpongycastleAsn1ASN1OutputStream;", "asn1Equals", "LOrgSpongycastleAsn1ASN1Primitive;", "hashCode", "replaceTagNumber", "I[B" };
  static const J2ObjcClassInfo _OrgSpongycastleAsn1ASN1ApplicationSpecific = { "ASN1ApplicationSpecific", "org.spongycastle.asn1", ptrTable, methods, fields, 7, 0x401, 13, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleAsn1ASN1ApplicationSpecific;
}

@end

void OrgSpongycastleAsn1ASN1ApplicationSpecific_initWithBoolean_withInt_withByteArray_(OrgSpongycastleAsn1ASN1ApplicationSpecific *self, jboolean isConstructed, jint tag, IOSByteArray *octets) {
  OrgSpongycastleAsn1ASN1Primitive_init(self);
  self->isConstructed_ = isConstructed;
  self->tag_ = tag;
  self->octets_ = OrgSpongycastleUtilArrays_cloneWithByteArray_(octets);
}

OrgSpongycastleAsn1ASN1ApplicationSpecific *OrgSpongycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_(id obj) {
  OrgSpongycastleAsn1ASN1ApplicationSpecific_initialize();
  if (obj == nil || [obj isKindOfClass:[OrgSpongycastleAsn1ASN1ApplicationSpecific class]]) {
    return (OrgSpongycastleAsn1ASN1ApplicationSpecific *) cast_chk(obj, [OrgSpongycastleAsn1ASN1ApplicationSpecific class]);
  }
  else if ([obj isKindOfClass:[IOSByteArray class]]) {
    @try {
      return OrgSpongycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_(OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])));
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Failed to construct object from byte[]: ", [e getMessage]));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"unknown object in getInstance: ", [[obj java_getClass] getName]));
}

jint OrgSpongycastleAsn1ASN1ApplicationSpecific_getLengthOfHeaderWithByteArray_(IOSByteArray *data) {
  OrgSpongycastleAsn1ASN1ApplicationSpecific_initialize();
  jint length = IOSByteArray_Get(nil_chk(data), 1) & (jint) 0xff;
  if (length == (jint) 0x80) {
    return 2;
  }
  if (length > 127) {
    jint size = length & (jint) 0x7f;
    if (size > 4) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$I", @"DER length more than 4 bytes: ", size));
    }
    return size + 2;
  }
  return 2;
}

IOSByteArray *OrgSpongycastleAsn1ASN1ApplicationSpecific_replaceTagNumberWithInt_withByteArray_(OrgSpongycastleAsn1ASN1ApplicationSpecific *self, jint newTag, IOSByteArray *input) {
  jint tagNo = IOSByteArray_Get(nil_chk(input), 0) & (jint) 0x1f;
  jint index = 1;
  if (tagNo == (jint) 0x1f) {
    tagNo = 0;
    jint b = IOSByteArray_Get(input, index++) & (jint) 0xff;
    if ((b & (jint) 0x7f) == 0) {
      @throw new_OrgSpongycastleAsn1ASN1ParsingException_initWithNSString_(@"corrupted stream - invalid high tag number found");
    }
    while ((b >= 0) && ((b & (jint) 0x80) != 0)) {
      tagNo |= (b & (jint) 0x7f);
      JreLShiftAssignInt(&tagNo, 7);
      b = IOSByteArray_Get(input, index++) & (jint) 0xff;
    }
  }
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:input->size_ - index + 1];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(input, index, tmp, 1, tmp->size_ - 1);
  *IOSByteArray_GetRef(tmp, 0) = (jbyte) newTag;
  return tmp;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleAsn1ASN1ApplicationSpecific)
