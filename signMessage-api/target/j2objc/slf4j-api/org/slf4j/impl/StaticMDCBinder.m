//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/impl/StaticMDCBinder.java
//

#include "J2ObjC_source.h"
#include "java/lang/UnsupportedOperationException.h"
#include "org/slf4j/impl/StaticMDCBinder.h"
#include "org/slf4j/spi/MDCAdapter.h"

@interface OrgSlf4jImplStaticMDCBinder ()

- (instancetype)init;

@end

__attribute__((unused)) static void OrgSlf4jImplStaticMDCBinder_init(OrgSlf4jImplStaticMDCBinder *self);

__attribute__((unused)) static OrgSlf4jImplStaticMDCBinder *new_OrgSlf4jImplStaticMDCBinder_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSlf4jImplStaticMDCBinder *create_OrgSlf4jImplStaticMDCBinder_init(void);

J2OBJC_INITIALIZED_DEFN(OrgSlf4jImplStaticMDCBinder)

OrgSlf4jImplStaticMDCBinder *OrgSlf4jImplStaticMDCBinder_SINGLETON;

@implementation OrgSlf4jImplStaticMDCBinder

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSlf4jImplStaticMDCBinder_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (OrgSlf4jImplStaticMDCBinder *)getSingleton {
  return OrgSlf4jImplStaticMDCBinder_getSingleton();
}

- (id<OrgSlf4jSpiMDCAdapter>)getMDCA {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"This code should never make it into the jar");
}

- (NSString *)getMDCAdapterClassStr {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"This code should never make it into the jar");
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSlf4jImplStaticMDCBinder;", 0x19, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSlf4jSpiMDCAdapter;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getSingleton);
  methods[2].selector = @selector(getMDCA);
  methods[3].selector = @selector(getMDCAdapterClassStr);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SINGLETON", "LOrgSlf4jImplStaticMDCBinder;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
  };
  static const void *ptrTable[] = { &OrgSlf4jImplStaticMDCBinder_SINGLETON };
  static const J2ObjcClassInfo _OrgSlf4jImplStaticMDCBinder = { "StaticMDCBinder", "org.slf4j.impl", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_OrgSlf4jImplStaticMDCBinder;
}

+ (void)initialize {
  if (self == [OrgSlf4jImplStaticMDCBinder class]) {
    OrgSlf4jImplStaticMDCBinder_SINGLETON = new_OrgSlf4jImplStaticMDCBinder_init();
    J2OBJC_SET_INITIALIZED(OrgSlf4jImplStaticMDCBinder)
  }
}

@end

void OrgSlf4jImplStaticMDCBinder_init(OrgSlf4jImplStaticMDCBinder *self) {
  NSObject_init(self);
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"This code should never make it into the jar");
}

OrgSlf4jImplStaticMDCBinder *new_OrgSlf4jImplStaticMDCBinder_init() {
  J2OBJC_NEW_IMPL(OrgSlf4jImplStaticMDCBinder, init)
}

OrgSlf4jImplStaticMDCBinder *create_OrgSlf4jImplStaticMDCBinder_init() {
  J2OBJC_CREATE_IMPL(OrgSlf4jImplStaticMDCBinder, init)
}

OrgSlf4jImplStaticMDCBinder *OrgSlf4jImplStaticMDCBinder_getSingleton() {
  OrgSlf4jImplStaticMDCBinder_initialize();
  return OrgSlf4jImplStaticMDCBinder_SINGLETON;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSlf4jImplStaticMDCBinder)
