//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/Shorts.java
//

#include "J2ObjC_source.h"
#include "java/lang/Short.h"
#include "org/spongycastle/util/Shorts.h"

@implementation OrgSpongycastleUtilShorts

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleUtilShorts_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (JavaLangShort *)valueOfWithShort:(jshort)value {
  return OrgSpongycastleUtilShorts_valueOfWithShort_(value);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaLangShort;", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(valueOfWithShort:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "valueOf", "S" };
  static const J2ObjcClassInfo _OrgSpongycastleUtilShorts = { "Shorts", "org.spongycastle.util", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilShorts;
}

@end

void OrgSpongycastleUtilShorts_init(OrgSpongycastleUtilShorts *self) {
  NSObject_init(self);
}

OrgSpongycastleUtilShorts *new_OrgSpongycastleUtilShorts_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleUtilShorts, init)
}

OrgSpongycastleUtilShorts *create_OrgSpongycastleUtilShorts_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleUtilShorts, init)
}

JavaLangShort *OrgSpongycastleUtilShorts_valueOfWithShort_(jshort value) {
  OrgSpongycastleUtilShorts_initialize();
  return JavaLangShort_valueOfWithShort_(value);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilShorts)
