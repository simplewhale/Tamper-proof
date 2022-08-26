//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/commons-codec/org/apache/commons/codec/net/RFC1522Codec.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/StringBuffer.h"
#include "org/apache/commons/codec/DecoderException.h"
#include "org/apache/commons/codec/binary/StringUtils.h"
#include "org/apache/commons/codec/net/RFC1522Codec.h"

NSString *OrgApacheCommonsCodecNetRFC1522Codec_POSTFIX = @"?=";
NSString *OrgApacheCommonsCodecNetRFC1522Codec_PREFIX = @"=?";

@implementation OrgApacheCommonsCodecNetRFC1522Codec

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgApacheCommonsCodecNetRFC1522Codec_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (NSString *)encodeTextWithNSString:(NSString *)text
                        withNSString:(NSString *)charset {
  if (text == nil) {
    return nil;
  }
  JavaLangStringBuffer *buffer = new_JavaLangStringBuffer_init();
  (void) [buffer appendWithNSString:OrgApacheCommonsCodecNetRFC1522Codec_PREFIX];
  (void) [buffer appendWithNSString:charset];
  (void) [buffer appendWithChar:OrgApacheCommonsCodecNetRFC1522Codec_SEP];
  (void) [buffer appendWithNSString:[self getEncoding]];
  (void) [buffer appendWithChar:OrgApacheCommonsCodecNetRFC1522Codec_SEP];
  IOSByteArray *rawdata = [self doEncodingWithByteArray:[text java_getBytesWithCharsetName:charset]];
  (void) [buffer appendWithNSString:OrgApacheCommonsCodecBinaryStringUtils_newStringUsAsciiWithByteArray_(rawdata)];
  (void) [buffer appendWithNSString:OrgApacheCommonsCodecNetRFC1522Codec_POSTFIX];
  return [buffer description];
}

- (NSString *)decodeTextWithNSString:(NSString *)text {
  if (text == nil) {
    return nil;
  }
  if ((![text java_hasPrefix:OrgApacheCommonsCodecNetRFC1522Codec_PREFIX]) || (![text java_hasSuffix:OrgApacheCommonsCodecNetRFC1522Codec_POSTFIX])) {
    @throw new_OrgApacheCommonsCodecDecoderException_initWithNSString_(@"RFC 1522 violation: malformed encoded content");
  }
  jint terminator = [text java_length] - 2;
  jint from = 2;
  jint to = [text java_indexOf:OrgApacheCommonsCodecNetRFC1522Codec_SEP fromIndex:from];
  if (to == terminator) {
    @throw new_OrgApacheCommonsCodecDecoderException_initWithNSString_(@"RFC 1522 violation: charset token not found");
  }
  NSString *charset = [text java_substring:from endIndex:to];
  if ([((NSString *) nil_chk(charset)) isEqual:@""]) {
    @throw new_OrgApacheCommonsCodecDecoderException_initWithNSString_(@"RFC 1522 violation: charset not specified");
  }
  from = to + 1;
  to = [text java_indexOf:OrgApacheCommonsCodecNetRFC1522Codec_SEP fromIndex:from];
  if (to == terminator) {
    @throw new_OrgApacheCommonsCodecDecoderException_initWithNSString_(@"RFC 1522 violation: encoding token not found");
  }
  NSString *encoding = [text java_substring:from endIndex:to];
  if (![((NSString *) nil_chk([self getEncoding])) java_equalsIgnoreCase:encoding]) {
    @throw new_OrgApacheCommonsCodecDecoderException_initWithNSString_(JreStrcat("$$$", @"This codec cannot decode ", encoding, @" encoded content"));
  }
  from = to + 1;
  to = [text java_indexOf:OrgApacheCommonsCodecNetRFC1522Codec_SEP fromIndex:from];
  IOSByteArray *data = OrgApacheCommonsCodecBinaryStringUtils_getBytesUsAsciiWithNSString_([text java_substring:from endIndex:to]);
  data = [self doDecodingWithByteArray:data];
  return [NSString java_stringWithBytes:data charsetName:charset];
}

- (NSString *)getEncoding {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (IOSByteArray *)doEncodingWithByteArray:(IOSByteArray *)bytes {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (IOSByteArray *)doDecodingWithByteArray:(IOSByteArray *)bytes {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, 0, 1, 2, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, 3, 4, 5, -1, -1, -1 },
    { NULL, "LNSString;", 0x404, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x404, 6, 7, 8, -1, -1, -1 },
    { NULL, "[B", 0x404, 9, 7, 10, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(encodeTextWithNSString:withNSString:);
  methods[2].selector = @selector(decodeTextWithNSString:);
  methods[3].selector = @selector(getEncoding);
  methods[4].selector = @selector(doEncodingWithByteArray:);
  methods[5].selector = @selector(doDecodingWithByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SEP", "C", .constantValue.asUnichar = OrgApacheCommonsCodecNetRFC1522Codec_SEP, 0x1c, -1, -1, -1, -1 },
    { "POSTFIX", "LNSString;", .constantValue.asLong = 0, 0x1c, -1, 11, -1, -1 },
    { "PREFIX", "LNSString;", .constantValue.asLong = 0, 0x1c, -1, 12, -1, -1 },
  };
  static const void *ptrTable[] = { "encodeText", "LNSString;LNSString;", "LOrgApacheCommonsCodecEncoderException;LJavaIoUnsupportedEncodingException;", "decodeText", "LNSString;", "LOrgApacheCommonsCodecDecoderException;LJavaIoUnsupportedEncodingException;", "doEncoding", "[B", "LOrgApacheCommonsCodecEncoderException;", "doDecoding", "LOrgApacheCommonsCodecDecoderException;", &OrgApacheCommonsCodecNetRFC1522Codec_POSTFIX, &OrgApacheCommonsCodecNetRFC1522Codec_PREFIX };
  static const J2ObjcClassInfo _OrgApacheCommonsCodecNetRFC1522Codec = { "RFC1522Codec", "org.apache.commons.codec.net", ptrTable, methods, fields, 7, 0x400, 6, 3, -1, -1, -1, -1, -1 };
  return &_OrgApacheCommonsCodecNetRFC1522Codec;
}

@end

void OrgApacheCommonsCodecNetRFC1522Codec_init(OrgApacheCommonsCodecNetRFC1522Codec *self) {
  NSObject_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgApacheCommonsCodecNetRFC1522Codec)