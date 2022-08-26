//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/commons-codec/org/apache/commons/codec/binary/Base32InputStream.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/InputStream.h"
#include "org/apache/commons/codec/binary/Base32.h"
#include "org/apache/commons/codec/binary/Base32InputStream.h"
#include "org/apache/commons/codec/binary/BaseNCodecInputStream.h"

@implementation OrgApacheCommonsCodecBinaryBase32InputStream

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
                              withBoolean:(jboolean)doEncode {
  OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_(self, inArg, doEncode);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
                              withBoolean:(jboolean)doEncode
                                  withInt:(jint)lineLength
                            withByteArray:(IOSByteArray *)lineSeparator {
  OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_withInt_withByteArray_(self, inArg, doEncode, lineLength, lineSeparator);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoInputStream:);
  methods[1].selector = @selector(initWithJavaIoInputStream:withBoolean:);
  methods[2].selector = @selector(initWithJavaIoInputStream:withBoolean:withInt:withByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LJavaIoInputStream;", "LJavaIoInputStream;Z", "LJavaIoInputStream;ZI[B" };
  static const J2ObjcClassInfo _OrgApacheCommonsCodecBinaryBase32InputStream = { "Base32InputStream", "org.apache.commons.codec.binary", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_OrgApacheCommonsCodecBinaryBase32InputStream;
}

@end

void OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_(OrgApacheCommonsCodecBinaryBase32InputStream *self, JavaIoInputStream *inArg) {
  OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_(self, inArg, false);
}

OrgApacheCommonsCodecBinaryBase32InputStream *new_OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  J2OBJC_NEW_IMPL(OrgApacheCommonsCodecBinaryBase32InputStream, initWithJavaIoInputStream_, inArg)
}

OrgApacheCommonsCodecBinaryBase32InputStream *create_OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  J2OBJC_CREATE_IMPL(OrgApacheCommonsCodecBinaryBase32InputStream, initWithJavaIoInputStream_, inArg)
}

void OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_(OrgApacheCommonsCodecBinaryBase32InputStream *self, JavaIoInputStream *inArg, jboolean doEncode) {
  OrgApacheCommonsCodecBinaryBaseNCodecInputStream_initWithJavaIoInputStream_withOrgApacheCommonsCodecBinaryBaseNCodec_withBoolean_(self, inArg, new_OrgApacheCommonsCodecBinaryBase32_initWithBoolean_(false), doEncode);
}

OrgApacheCommonsCodecBinaryBase32InputStream *new_OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_(JavaIoInputStream *inArg, jboolean doEncode) {
  J2OBJC_NEW_IMPL(OrgApacheCommonsCodecBinaryBase32InputStream, initWithJavaIoInputStream_withBoolean_, inArg, doEncode)
}

OrgApacheCommonsCodecBinaryBase32InputStream *create_OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_(JavaIoInputStream *inArg, jboolean doEncode) {
  J2OBJC_CREATE_IMPL(OrgApacheCommonsCodecBinaryBase32InputStream, initWithJavaIoInputStream_withBoolean_, inArg, doEncode)
}

void OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_withInt_withByteArray_(OrgApacheCommonsCodecBinaryBase32InputStream *self, JavaIoInputStream *inArg, jboolean doEncode, jint lineLength, IOSByteArray *lineSeparator) {
  OrgApacheCommonsCodecBinaryBaseNCodecInputStream_initWithJavaIoInputStream_withOrgApacheCommonsCodecBinaryBaseNCodec_withBoolean_(self, inArg, new_OrgApacheCommonsCodecBinaryBase32_initWithInt_withByteArray_(lineLength, lineSeparator), doEncode);
}

OrgApacheCommonsCodecBinaryBase32InputStream *new_OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_withInt_withByteArray_(JavaIoInputStream *inArg, jboolean doEncode, jint lineLength, IOSByteArray *lineSeparator) {
  J2OBJC_NEW_IMPL(OrgApacheCommonsCodecBinaryBase32InputStream, initWithJavaIoInputStream_withBoolean_withInt_withByteArray_, inArg, doEncode, lineLength, lineSeparator)
}

OrgApacheCommonsCodecBinaryBase32InputStream *create_OrgApacheCommonsCodecBinaryBase32InputStream_initWithJavaIoInputStream_withBoolean_withInt_withByteArray_(JavaIoInputStream *inArg, jboolean doEncode, jint lineLength, IOSByteArray *lineSeparator) {
  J2OBJC_CREATE_IMPL(OrgApacheCommonsCodecBinaryBase32InputStream, initWithJavaIoInputStream_withBoolean_withInt_withByteArray_, inArg, doEncode, lineLength, lineSeparator)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgApacheCommonsCodecBinaryBase32InputStream)
