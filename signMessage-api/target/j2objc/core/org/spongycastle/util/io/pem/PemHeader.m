//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/io/pem/PemHeader.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/util/io/pem/PemHeader.h"

@interface OrgSpongycastleUtilIoPemPemHeader () {
 @public
  NSString *name_;
  NSString *value_;
}

- (jint)getHashCodeWithNSString:(NSString *)s;

- (jboolean)isEqualWithNSString:(NSString *)s1
                   withNSString:(NSString *)s2;

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleUtilIoPemPemHeader, name_, NSString *)
J2OBJC_FIELD_SETTER(OrgSpongycastleUtilIoPemPemHeader, value_, NSString *)

__attribute__((unused)) static jint OrgSpongycastleUtilIoPemPemHeader_getHashCodeWithNSString_(OrgSpongycastleUtilIoPemPemHeader *self, NSString *s);

__attribute__((unused)) static jboolean OrgSpongycastleUtilIoPemPemHeader_isEqualWithNSString_withNSString_(OrgSpongycastleUtilIoPemPemHeader *self, NSString *s1, NSString *s2);

@implementation OrgSpongycastleUtilIoPemPemHeader

- (instancetype)initWithNSString:(NSString *)name
                    withNSString:(NSString *)value {
  OrgSpongycastleUtilIoPemPemHeader_initWithNSString_withNSString_(self, name, value);
  return self;
}

- (NSString *)getName {
  return name_;
}

- (NSString *)getValue {
  return value_;
}

- (NSUInteger)hash {
  return OrgSpongycastleUtilIoPemPemHeader_getHashCodeWithNSString_(self, self->name_) + 31 * OrgSpongycastleUtilIoPemPemHeader_getHashCodeWithNSString_(self, self->value_);
}

- (jboolean)isEqual:(id)o {
  if (!([o isKindOfClass:[OrgSpongycastleUtilIoPemPemHeader class]])) {
    return false;
  }
  OrgSpongycastleUtilIoPemPemHeader *other = (OrgSpongycastleUtilIoPemPemHeader *) cast_chk(o, [OrgSpongycastleUtilIoPemPemHeader class]);
  return other == self || (OrgSpongycastleUtilIoPemPemHeader_isEqualWithNSString_withNSString_(self, self->name_, ((OrgSpongycastleUtilIoPemPemHeader *) nil_chk(other))->name_) && OrgSpongycastleUtilIoPemPemHeader_isEqualWithNSString_withNSString_(self, self->value_, other->value_));
}

- (jint)getHashCodeWithNSString:(NSString *)s {
  return OrgSpongycastleUtilIoPemPemHeader_getHashCodeWithNSString_(self, s);
}

- (jboolean)isEqualWithNSString:(NSString *)s1
                   withNSString:(NSString *)s2 {
  return OrgSpongycastleUtilIoPemPemHeader_isEqualWithNSString_withNSString_(self, s1, s2);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 4, 5, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 6, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withNSString:);
  methods[1].selector = @selector(getName);
  methods[2].selector = @selector(getValue);
  methods[3].selector = @selector(hash);
  methods[4].selector = @selector(isEqual:);
  methods[5].selector = @selector(getHashCodeWithNSString:);
  methods[6].selector = @selector(isEqualWithNSString:withNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "name_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "value_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LNSString;", "hashCode", "equals", "LNSObject;", "getHashCode", "LNSString;", "isEqual" };
  static const J2ObjcClassInfo _OrgSpongycastleUtilIoPemPemHeader = { "PemHeader", "org.spongycastle.util.io.pem", ptrTable, methods, fields, 7, 0x1, 7, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilIoPemPemHeader;
}

@end

void OrgSpongycastleUtilIoPemPemHeader_initWithNSString_withNSString_(OrgSpongycastleUtilIoPemPemHeader *self, NSString *name, NSString *value) {
  NSObject_init(self);
  self->name_ = name;
  self->value_ = value;
}

OrgSpongycastleUtilIoPemPemHeader *new_OrgSpongycastleUtilIoPemPemHeader_initWithNSString_withNSString_(NSString *name, NSString *value) {
  J2OBJC_NEW_IMPL(OrgSpongycastleUtilIoPemPemHeader, initWithNSString_withNSString_, name, value)
}

OrgSpongycastleUtilIoPemPemHeader *create_OrgSpongycastleUtilIoPemPemHeader_initWithNSString_withNSString_(NSString *name, NSString *value) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleUtilIoPemPemHeader, initWithNSString_withNSString_, name, value)
}

jint OrgSpongycastleUtilIoPemPemHeader_getHashCodeWithNSString_(OrgSpongycastleUtilIoPemPemHeader *self, NSString *s) {
  if (s == nil) {
    return 1;
  }
  return ((jint) [s hash]);
}

jboolean OrgSpongycastleUtilIoPemPemHeader_isEqualWithNSString_withNSString_(OrgSpongycastleUtilIoPemPemHeader *self, NSString *s1, NSString *s2) {
  if (s1 == s2) {
    return true;
  }
  if (s1 == nil || s2 == nil) {
    return false;
  }
  return [s1 isEqual:s2];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilIoPemPemHeader)
