//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/impl/StaticMarkerBinder.java
//

#include "J2ObjC_source.h"
#include "java/lang/UnsupportedOperationException.h"
#include "org/slf4j/IMarkerFactory.h"
#include "org/slf4j/impl/StaticMarkerBinder.h"

@interface OrgSlf4jImplStaticMarkerBinder ()

- (instancetype)init;

@end

__attribute__((unused)) static void OrgSlf4jImplStaticMarkerBinder_init(OrgSlf4jImplStaticMarkerBinder *self);

__attribute__((unused)) static OrgSlf4jImplStaticMarkerBinder *new_OrgSlf4jImplStaticMarkerBinder_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSlf4jImplStaticMarkerBinder *create_OrgSlf4jImplStaticMarkerBinder_init(void);

J2OBJC_INITIALIZED_DEFN(OrgSlf4jImplStaticMarkerBinder)

OrgSlf4jImplStaticMarkerBinder *OrgSlf4jImplStaticMarkerBinder_SINGLETON;

@implementation OrgSlf4jImplStaticMarkerBinder

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSlf4jImplStaticMarkerBinder_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (OrgSlf4jImplStaticMarkerBinder *)getSingleton {
  return OrgSlf4jImplStaticMarkerBinder_getSingleton();
}

- (id<OrgSlf4jIMarkerFactory>)getMarkerFactory {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"This code should never make it into the jar");
}

- (NSString *)getMarkerFactoryClassStr {
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"This code should never make it into the jar");
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSlf4jImplStaticMarkerBinder;", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSlf4jIMarkerFactory;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getSingleton);
  methods[2].selector = @selector(getMarkerFactory);
  methods[3].selector = @selector(getMarkerFactoryClassStr);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SINGLETON", "LOrgSlf4jImplStaticMarkerBinder;", .constantValue.asLong = 0, 0x19, -1, 0, -1, -1 },
  };
  static const void *ptrTable[] = { &OrgSlf4jImplStaticMarkerBinder_SINGLETON };
  static const J2ObjcClassInfo _OrgSlf4jImplStaticMarkerBinder = { "StaticMarkerBinder", "org.slf4j.impl", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_OrgSlf4jImplStaticMarkerBinder;
}

+ (void)initialize {
  if (self == [OrgSlf4jImplStaticMarkerBinder class]) {
    OrgSlf4jImplStaticMarkerBinder_SINGLETON = new_OrgSlf4jImplStaticMarkerBinder_init();
    J2OBJC_SET_INITIALIZED(OrgSlf4jImplStaticMarkerBinder)
  }
}

@end

void OrgSlf4jImplStaticMarkerBinder_init(OrgSlf4jImplStaticMarkerBinder *self) {
  NSObject_init(self);
  @throw new_JavaLangUnsupportedOperationException_initWithNSString_(@"This code should never make it into the jar");
}

OrgSlf4jImplStaticMarkerBinder *new_OrgSlf4jImplStaticMarkerBinder_init() {
  J2OBJC_NEW_IMPL(OrgSlf4jImplStaticMarkerBinder, init)
}

OrgSlf4jImplStaticMarkerBinder *create_OrgSlf4jImplStaticMarkerBinder_init() {
  J2OBJC_CREATE_IMPL(OrgSlf4jImplStaticMarkerBinder, init)
}

OrgSlf4jImplStaticMarkerBinder *OrgSlf4jImplStaticMarkerBinder_getSingleton() {
  OrgSlf4jImplStaticMarkerBinder_initialize();
  return OrgSlf4jImplStaticMarkerBinder_SINGLETON;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSlf4jImplStaticMarkerBinder)
