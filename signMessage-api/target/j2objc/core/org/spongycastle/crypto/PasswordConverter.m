//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/PasswordConverter.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Enum.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/spongycastle/crypto/PBEParametersGenerator.h"
#include "org/spongycastle/crypto/PasswordConverter.h"

#pragma clang diagnostic ignored "-Wprotocol"

__attribute__((unused)) static void OrgSpongycastleCryptoPasswordConverter_initWithNSString_withInt_(OrgSpongycastleCryptoPasswordConverter *self, NSString *__name, jint __ordinal);

__attribute__((unused)) static OrgSpongycastleCryptoPasswordConverter *new_OrgSpongycastleCryptoPasswordConverter_initWithNSString_withInt_(NSString *__name, jint __ordinal) NS_RETURNS_RETAINED;

@interface OrgSpongycastleCryptoPasswordConverter_1 : OrgSpongycastleCryptoPasswordConverter

- (NSString *)getType;

- (IOSByteArray *)convertWithCharArray:(IOSCharArray *)password;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPasswordConverter_1)

__attribute__((unused)) static void OrgSpongycastleCryptoPasswordConverter_1_initWithNSString_withInt_(OrgSpongycastleCryptoPasswordConverter_1 *self, NSString *__name, jint __ordinal);

__attribute__((unused)) static OrgSpongycastleCryptoPasswordConverter_1 *new_OrgSpongycastleCryptoPasswordConverter_1_initWithNSString_withInt_(NSString *__name, jint __ordinal) NS_RETURNS_RETAINED;

@interface OrgSpongycastleCryptoPasswordConverter_2 : OrgSpongycastleCryptoPasswordConverter

- (NSString *)getType;

- (IOSByteArray *)convertWithCharArray:(IOSCharArray *)password;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPasswordConverter_2)

__attribute__((unused)) static void OrgSpongycastleCryptoPasswordConverter_2_initWithNSString_withInt_(OrgSpongycastleCryptoPasswordConverter_2 *self, NSString *__name, jint __ordinal);

__attribute__((unused)) static OrgSpongycastleCryptoPasswordConverter_2 *new_OrgSpongycastleCryptoPasswordConverter_2_initWithNSString_withInt_(NSString *__name, jint __ordinal) NS_RETURNS_RETAINED;

@interface OrgSpongycastleCryptoPasswordConverter_3 : OrgSpongycastleCryptoPasswordConverter

- (NSString *)getType;

- (IOSByteArray *)convertWithCharArray:(IOSCharArray *)password;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPasswordConverter_3)

__attribute__((unused)) static void OrgSpongycastleCryptoPasswordConverter_3_initWithNSString_withInt_(OrgSpongycastleCryptoPasswordConverter_3 *self, NSString *__name, jint __ordinal);

__attribute__((unused)) static OrgSpongycastleCryptoPasswordConverter_3 *new_OrgSpongycastleCryptoPasswordConverter_3_initWithNSString_withInt_(NSString *__name, jint __ordinal) NS_RETURNS_RETAINED;

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoPasswordConverter)

OrgSpongycastleCryptoPasswordConverter *OrgSpongycastleCryptoPasswordConverter_values_[3];

@implementation OrgSpongycastleCryptoPasswordConverter

+ (IOSObjectArray *)values {
  return OrgSpongycastleCryptoPasswordConverter_values();
}

+ (OrgSpongycastleCryptoPasswordConverter *)valueOfWithNSString:(NSString *)name {
  return OrgSpongycastleCryptoPasswordConverter_valueOfWithNSString_(name);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "[LOrgSpongycastleCryptoPasswordConverter;", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoPasswordConverter;", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(values);
  methods[1].selector = @selector(valueOfWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ASCII", "LOrgSpongycastleCryptoPasswordConverter;", .constantValue.asLong = 0, 0x4019, -1, 2, -1, -1 },
    { "UTF8", "LOrgSpongycastleCryptoPasswordConverter;", .constantValue.asLong = 0, 0x4019, -1, 3, -1, -1 },
    { "PKCS12", "LOrgSpongycastleCryptoPasswordConverter;", .constantValue.asLong = 0, 0x4019, -1, 4, -1, -1 },
  };
  static const void *ptrTable[] = { "valueOf", "LNSString;", &JreEnum(OrgSpongycastleCryptoPasswordConverter, ASCII), &JreEnum(OrgSpongycastleCryptoPasswordConverter, UTF8), &JreEnum(OrgSpongycastleCryptoPasswordConverter, PKCS12), "Ljava/lang/Enum<Lorg/spongycastle/crypto/PasswordConverter;>;Lorg/spongycastle/crypto/CharToByteConverter;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoPasswordConverter = { "PasswordConverter", "org.spongycastle.crypto", ptrTable, methods, fields, 7, 0x4401, 2, 3, -1, -1, -1, 5, -1 };
  return &_OrgSpongycastleCryptoPasswordConverter;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoPasswordConverter class]) {
    JreEnum(OrgSpongycastleCryptoPasswordConverter, ASCII) = new_OrgSpongycastleCryptoPasswordConverter_1_initWithNSString_withInt_(JreEnumConstantName(OrgSpongycastleCryptoPasswordConverter_class_(), 0), 0);
    JreEnum(OrgSpongycastleCryptoPasswordConverter, UTF8) = new_OrgSpongycastleCryptoPasswordConverter_2_initWithNSString_withInt_(JreEnumConstantName(OrgSpongycastleCryptoPasswordConverter_class_(), 1), 1);
    JreEnum(OrgSpongycastleCryptoPasswordConverter, PKCS12) = new_OrgSpongycastleCryptoPasswordConverter_3_initWithNSString_withInt_(JreEnumConstantName(OrgSpongycastleCryptoPasswordConverter_class_(), 2), 2);
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoPasswordConverter)
  }
}

@end

void OrgSpongycastleCryptoPasswordConverter_initWithNSString_withInt_(OrgSpongycastleCryptoPasswordConverter *self, NSString *__name, jint __ordinal) {
  JavaLangEnum_initWithNSString_withInt_(self, __name, __ordinal);
}

OrgSpongycastleCryptoPasswordConverter *new_OrgSpongycastleCryptoPasswordConverter_initWithNSString_withInt_(NSString *__name, jint __ordinal) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoPasswordConverter, initWithNSString_withInt_, __name, __ordinal)
}

IOSObjectArray *OrgSpongycastleCryptoPasswordConverter_values() {
  OrgSpongycastleCryptoPasswordConverter_initialize();
  return [IOSObjectArray arrayWithObjects:OrgSpongycastleCryptoPasswordConverter_values_ count:3 type:OrgSpongycastleCryptoPasswordConverter_class_()];
}

OrgSpongycastleCryptoPasswordConverter *OrgSpongycastleCryptoPasswordConverter_valueOfWithNSString_(NSString *name) {
  OrgSpongycastleCryptoPasswordConverter_initialize();
  for (int i = 0; i < 3; i++) {
    OrgSpongycastleCryptoPasswordConverter *e = OrgSpongycastleCryptoPasswordConverter_values_[i];
    if ([name isEqual:[e name]]) {
      return e;
    }
  }
  @throw create_JavaLangIllegalArgumentException_initWithNSString_(name);
  return nil;
}

OrgSpongycastleCryptoPasswordConverter *OrgSpongycastleCryptoPasswordConverter_fromOrdinal(NSUInteger ordinal) {
  OrgSpongycastleCryptoPasswordConverter_initialize();
  if (ordinal >= 3) {
    return nil;
  }
  return OrgSpongycastleCryptoPasswordConverter_values_[ordinal];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoPasswordConverter)

@implementation OrgSpongycastleCryptoPasswordConverter_1

- (NSString *)getType {
  return @"ASCII";
}

- (IOSByteArray *)convertWithCharArray:(IOSCharArray *)password {
  return OrgSpongycastleCryptoPBEParametersGenerator_PKCS5PasswordToBytesWithCharArray_(password);
}

- (void)dealloc {
  JreCheckFinalize(self, [OrgSpongycastleCryptoPasswordConverter_1 class]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getType);
  methods[1].selector = @selector(convertWithCharArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "convert", "[C", "LOrgSpongycastleCryptoPasswordConverter;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoPasswordConverter_1 = { "", "org.spongycastle.crypto", ptrTable, methods, NULL, 7, 0xc018, 2, 0, 2, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoPasswordConverter_1;
}

@end

void OrgSpongycastleCryptoPasswordConverter_1_initWithNSString_withInt_(OrgSpongycastleCryptoPasswordConverter_1 *self, NSString *__name, jint __ordinal) {
  OrgSpongycastleCryptoPasswordConverter_initWithNSString_withInt_(self, __name, __ordinal);
}

OrgSpongycastleCryptoPasswordConverter_1 *new_OrgSpongycastleCryptoPasswordConverter_1_initWithNSString_withInt_(NSString *__name, jint __ordinal) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoPasswordConverter_1, initWithNSString_withInt_, __name, __ordinal)
}

@implementation OrgSpongycastleCryptoPasswordConverter_2

- (NSString *)getType {
  return @"UTF8";
}

- (IOSByteArray *)convertWithCharArray:(IOSCharArray *)password {
  return OrgSpongycastleCryptoPBEParametersGenerator_PKCS5PasswordToUTF8BytesWithCharArray_(password);
}

- (void)dealloc {
  JreCheckFinalize(self, [OrgSpongycastleCryptoPasswordConverter_2 class]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getType);
  methods[1].selector = @selector(convertWithCharArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "convert", "[C", "LOrgSpongycastleCryptoPasswordConverter;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoPasswordConverter_2 = { "", "org.spongycastle.crypto", ptrTable, methods, NULL, 7, 0xc018, 2, 0, 2, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoPasswordConverter_2;
}

@end

void OrgSpongycastleCryptoPasswordConverter_2_initWithNSString_withInt_(OrgSpongycastleCryptoPasswordConverter_2 *self, NSString *__name, jint __ordinal) {
  OrgSpongycastleCryptoPasswordConverter_initWithNSString_withInt_(self, __name, __ordinal);
}

OrgSpongycastleCryptoPasswordConverter_2 *new_OrgSpongycastleCryptoPasswordConverter_2_initWithNSString_withInt_(NSString *__name, jint __ordinal) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoPasswordConverter_2, initWithNSString_withInt_, __name, __ordinal)
}

@implementation OrgSpongycastleCryptoPasswordConverter_3

- (NSString *)getType {
  return @"PKCS12";
}

- (IOSByteArray *)convertWithCharArray:(IOSCharArray *)password {
  return OrgSpongycastleCryptoPBEParametersGenerator_PKCS12PasswordToBytesWithCharArray_(password);
}

- (void)dealloc {
  JreCheckFinalize(self, [OrgSpongycastleCryptoPasswordConverter_3 class]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getType);
  methods[1].selector = @selector(convertWithCharArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "convert", "[C", "LOrgSpongycastleCryptoPasswordConverter;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoPasswordConverter_3 = { "", "org.spongycastle.crypto", ptrTable, methods, NULL, 7, 0xc018, 2, 0, 2, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoPasswordConverter_3;
}

@end

void OrgSpongycastleCryptoPasswordConverter_3_initWithNSString_withInt_(OrgSpongycastleCryptoPasswordConverter_3 *self, NSString *__name, jint __ordinal) {
  OrgSpongycastleCryptoPasswordConverter_initWithNSString_withInt_(self, __name, __ordinal);
}

OrgSpongycastleCryptoPasswordConverter_3 *new_OrgSpongycastleCryptoPasswordConverter_3_initWithNSString_withInt_(NSString *__name, jint __ordinal) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoPasswordConverter_3, initWithNSString_withInt_, __name, __ordinal)
}