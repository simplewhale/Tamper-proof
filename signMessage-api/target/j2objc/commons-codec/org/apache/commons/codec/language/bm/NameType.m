//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/commons-codec/org/apache/commons/codec/language/bm/NameType.java
//

#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Enum.h"
#include "java/lang/IllegalArgumentException.h"
#include "org/apache/commons/codec/language/bm/NameType.h"

@interface OrgApacheCommonsCodecLanguageBmNameType () {
 @public
  NSString *name_NameType_;
}

@end

J2OBJC_FIELD_SETTER(OrgApacheCommonsCodecLanguageBmNameType, name_NameType_, NSString *)

__attribute__((unused)) static void OrgApacheCommonsCodecLanguageBmNameType_initWithNSString_withNSString_withInt_(OrgApacheCommonsCodecLanguageBmNameType *self, NSString *name, NSString *__name, jint __ordinal);

__attribute__((unused)) static OrgApacheCommonsCodecLanguageBmNameType *new_OrgApacheCommonsCodecLanguageBmNameType_initWithNSString_withNSString_withInt_(NSString *name, NSString *__name, jint __ordinal) NS_RETURNS_RETAINED;

J2OBJC_INITIALIZED_DEFN(OrgApacheCommonsCodecLanguageBmNameType)

OrgApacheCommonsCodecLanguageBmNameType *OrgApacheCommonsCodecLanguageBmNameType_values_[3];

@implementation OrgApacheCommonsCodecLanguageBmNameType

- (NSString *)getName {
  return self->name_NameType_;
}

+ (IOSObjectArray *)values {
  return OrgApacheCommonsCodecLanguageBmNameType_values();
}

+ (OrgApacheCommonsCodecLanguageBmNameType *)valueOfWithNSString:(NSString *)name {
  return OrgApacheCommonsCodecLanguageBmNameType_valueOfWithNSString_(name);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgApacheCommonsCodecLanguageBmNameType;", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgApacheCommonsCodecLanguageBmNameType;", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getName);
  methods[1].selector = @selector(values);
  methods[2].selector = @selector(valueOfWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ASHKENAZI", "LOrgApacheCommonsCodecLanguageBmNameType;", .constantValue.asLong = 0, 0x4019, -1, 2, -1, -1 },
    { "GENERIC", "LOrgApacheCommonsCodecLanguageBmNameType;", .constantValue.asLong = 0, 0x4019, -1, 3, -1, -1 },
    { "SEPHARDIC", "LOrgApacheCommonsCodecLanguageBmNameType;", .constantValue.asLong = 0, 0x4019, -1, 4, -1, -1 },
    { "name_NameType_", "LNSString;", .constantValue.asLong = 0, 0x12, 5, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "valueOf", "LNSString;", &JreEnum(OrgApacheCommonsCodecLanguageBmNameType, ASHKENAZI), &JreEnum(OrgApacheCommonsCodecLanguageBmNameType, GENERIC), &JreEnum(OrgApacheCommonsCodecLanguageBmNameType, SEPHARDIC), "name", "Ljava/lang/Enum<Lorg/apache/commons/codec/language/bm/NameType;>;" };
  static const J2ObjcClassInfo _OrgApacheCommonsCodecLanguageBmNameType = { "NameType", "org.apache.commons.codec.language.bm", ptrTable, methods, fields, 7, 0x4011, 3, 4, -1, -1, -1, 6, -1 };
  return &_OrgApacheCommonsCodecLanguageBmNameType;
}

+ (void)initialize {
  if (self == [OrgApacheCommonsCodecLanguageBmNameType class]) {
    JreEnum(OrgApacheCommonsCodecLanguageBmNameType, ASHKENAZI) = new_OrgApacheCommonsCodecLanguageBmNameType_initWithNSString_withNSString_withInt_(@"ash", JreEnumConstantName(OrgApacheCommonsCodecLanguageBmNameType_class_(), 0), 0);
    JreEnum(OrgApacheCommonsCodecLanguageBmNameType, GENERIC) = new_OrgApacheCommonsCodecLanguageBmNameType_initWithNSString_withNSString_withInt_(@"gen", JreEnumConstantName(OrgApacheCommonsCodecLanguageBmNameType_class_(), 1), 1);
    JreEnum(OrgApacheCommonsCodecLanguageBmNameType, SEPHARDIC) = new_OrgApacheCommonsCodecLanguageBmNameType_initWithNSString_withNSString_withInt_(@"sep", JreEnumConstantName(OrgApacheCommonsCodecLanguageBmNameType_class_(), 2), 2);
    J2OBJC_SET_INITIALIZED(OrgApacheCommonsCodecLanguageBmNameType)
  }
}

@end

void OrgApacheCommonsCodecLanguageBmNameType_initWithNSString_withNSString_withInt_(OrgApacheCommonsCodecLanguageBmNameType *self, NSString *name, NSString *__name, jint __ordinal) {
  JavaLangEnum_initWithNSString_withInt_(self, __name, __ordinal);
  self->name_NameType_ = name;
}

OrgApacheCommonsCodecLanguageBmNameType *new_OrgApacheCommonsCodecLanguageBmNameType_initWithNSString_withNSString_withInt_(NSString *name, NSString *__name, jint __ordinal) {
  J2OBJC_NEW_IMPL(OrgApacheCommonsCodecLanguageBmNameType, initWithNSString_withNSString_withInt_, name, __name, __ordinal)
}

IOSObjectArray *OrgApacheCommonsCodecLanguageBmNameType_values() {
  OrgApacheCommonsCodecLanguageBmNameType_initialize();
  return [IOSObjectArray arrayWithObjects:OrgApacheCommonsCodecLanguageBmNameType_values_ count:3 type:OrgApacheCommonsCodecLanguageBmNameType_class_()];
}

OrgApacheCommonsCodecLanguageBmNameType *OrgApacheCommonsCodecLanguageBmNameType_valueOfWithNSString_(NSString *name) {
  OrgApacheCommonsCodecLanguageBmNameType_initialize();
  for (int i = 0; i < 3; i++) {
    OrgApacheCommonsCodecLanguageBmNameType *e = OrgApacheCommonsCodecLanguageBmNameType_values_[i];
    if ([name isEqual:[e name]]) {
      return e;
    }
  }
  @throw create_JavaLangIllegalArgumentException_initWithNSString_(name);
  return nil;
}

OrgApacheCommonsCodecLanguageBmNameType *OrgApacheCommonsCodecLanguageBmNameType_fromOrdinal(NSUInteger ordinal) {
  OrgApacheCommonsCodecLanguageBmNameType_initialize();
  if (ordinal >= 3) {
    return nil;
  }
  return OrgApacheCommonsCodecLanguageBmNameType_values_[ordinal];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgApacheCommonsCodecLanguageBmNameType)
