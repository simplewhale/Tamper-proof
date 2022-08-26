//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/io/pem/PemReader.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/BufferedReader.h"
#include "java/io/IOException.h"
#include "java/io/Reader.h"
#include "java/lang/StringBuffer.h"
#include "java/util/ArrayList.h"
#include "java/util/List.h"
#include "org/spongycastle/util/encoders/Base64.h"
#include "org/spongycastle/util/io/pem/PemHeader.h"
#include "org/spongycastle/util/io/pem/PemObject.h"
#include "org/spongycastle/util/io/pem/PemReader.h"

@interface OrgSpongycastleUtilIoPemPemReader ()

- (OrgSpongycastleUtilIoPemPemObject *)loadObjectWithNSString:(NSString *)type;

@end

inline NSString *OrgSpongycastleUtilIoPemPemReader_get_BEGIN(void);
static NSString *OrgSpongycastleUtilIoPemPemReader_BEGIN = @"-----BEGIN ";
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleUtilIoPemPemReader, BEGIN, NSString *)

inline NSString *OrgSpongycastleUtilIoPemPemReader_get_END(void);
static NSString *OrgSpongycastleUtilIoPemPemReader_END = @"-----END ";
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleUtilIoPemPemReader, END, NSString *)

__attribute__((unused)) static OrgSpongycastleUtilIoPemPemObject *OrgSpongycastleUtilIoPemPemReader_loadObjectWithNSString_(OrgSpongycastleUtilIoPemPemReader *self, NSString *type);

@implementation OrgSpongycastleUtilIoPemPemReader

- (instancetype)initWithJavaIoReader:(JavaIoReader *)reader {
  OrgSpongycastleUtilIoPemPemReader_initWithJavaIoReader_(self, reader);
  return self;
}

- (OrgSpongycastleUtilIoPemPemObject *)readPemObject {
  NSString *line = [self readLine];
  while (line != nil && ![line java_hasPrefix:OrgSpongycastleUtilIoPemPemReader_BEGIN]) {
    line = [self readLine];
  }
  if (line != nil) {
    line = [line java_substring:[((NSString *) nil_chk(OrgSpongycastleUtilIoPemPemReader_BEGIN)) java_length]];
    jint index = [((NSString *) nil_chk(line)) java_indexOf:'-'];
    NSString *type = [line java_substring:0 endIndex:index];
    if (index > 0) {
      return OrgSpongycastleUtilIoPemPemReader_loadObjectWithNSString_(self, type);
    }
  }
  return nil;
}

- (OrgSpongycastleUtilIoPemPemObject *)loadObjectWithNSString:(NSString *)type {
  return OrgSpongycastleUtilIoPemPemReader_loadObjectWithNSString_(self, type);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleUtilIoPemPemObject;", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleUtilIoPemPemObject;", 0x2, 2, 3, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaIoReader:);
  methods[1].selector = @selector(readPemObject);
  methods[2].selector = @selector(loadObjectWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "BEGIN", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 4, -1, -1 },
    { "END", "LNSString;", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoReader;", "LJavaIoIOException;", "loadObject", "LNSString;", &OrgSpongycastleUtilIoPemPemReader_BEGIN, &OrgSpongycastleUtilIoPemPemReader_END };
  static const J2ObjcClassInfo _OrgSpongycastleUtilIoPemPemReader = { "PemReader", "org.spongycastle.util.io.pem", ptrTable, methods, fields, 7, 0x1, 3, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilIoPemPemReader;
}

@end

void OrgSpongycastleUtilIoPemPemReader_initWithJavaIoReader_(OrgSpongycastleUtilIoPemPemReader *self, JavaIoReader *reader) {
  JavaIoBufferedReader_initWithJavaIoReader_(self, reader);
}

OrgSpongycastleUtilIoPemPemReader *new_OrgSpongycastleUtilIoPemPemReader_initWithJavaIoReader_(JavaIoReader *reader) {
  J2OBJC_NEW_IMPL(OrgSpongycastleUtilIoPemPemReader, initWithJavaIoReader_, reader)
}

OrgSpongycastleUtilIoPemPemReader *create_OrgSpongycastleUtilIoPemPemReader_initWithJavaIoReader_(JavaIoReader *reader) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleUtilIoPemPemReader, initWithJavaIoReader_, reader)
}

OrgSpongycastleUtilIoPemPemObject *OrgSpongycastleUtilIoPemPemReader_loadObjectWithNSString_(OrgSpongycastleUtilIoPemPemReader *self, NSString *type) {
  NSString *line;
  NSString *endMarker = JreStrcat("$$", OrgSpongycastleUtilIoPemPemReader_END, type);
  JavaLangStringBuffer *buf = new_JavaLangStringBuffer_init();
  id<JavaUtilList> headers = new_JavaUtilArrayList_init();
  while ((line = [self readLine]) != nil) {
    if ([((NSString *) nil_chk(line)) java_indexOfString:@":"] >= 0) {
      jint index = [line java_indexOf:':'];
      NSString *hdr = [line java_substring:0 endIndex:index];
      NSString *value = [((NSString *) nil_chk([line java_substring:index + 1])) java_trim];
      [headers addWithId:new_OrgSpongycastleUtilIoPemPemHeader_initWithNSString_withNSString_(hdr, value)];
      continue;
    }
    if ([line java_indexOfString:endMarker] != -1) {
      break;
    }
    (void) [buf appendWithNSString:[line java_trim]];
  }
  if (line == nil) {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", endMarker, @" not found"));
  }
  return new_OrgSpongycastleUtilIoPemPemObject_initWithNSString_withJavaUtilList_withByteArray_(type, headers, OrgSpongycastleUtilEncodersBase64_decodeWithNSString_([buf description]));
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilIoPemPemReader)
