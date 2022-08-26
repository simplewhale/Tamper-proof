//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/MDC.java
//

#include "J2ObjC_source.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/NoClassDefFoundError.h"
#include "java/lang/NoSuchMethodError.h"
#include "java/util/Map.h"
#include "org/slf4j/MDC.h"
#include "org/slf4j/helpers/NOPMDCAdapter.h"
#include "org/slf4j/helpers/Util.h"
#include "org/slf4j/impl/StaticMDCBinder.h"
#include "org/slf4j/spi/MDCAdapter.h"

@interface OrgSlf4jMDC ()

- (instancetype)init;

+ (id<OrgSlf4jSpiMDCAdapter>)bwCompatibleGetMDCAdapterFromBinder;

@end

__attribute__((unused)) static void OrgSlf4jMDC_init(OrgSlf4jMDC *self);

__attribute__((unused)) static OrgSlf4jMDC *new_OrgSlf4jMDC_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSlf4jMDC *create_OrgSlf4jMDC_init(void);

__attribute__((unused)) static id<OrgSlf4jSpiMDCAdapter> OrgSlf4jMDC_bwCompatibleGetMDCAdapterFromBinder(void);

@interface OrgSlf4jMDC_MDCCloseable () {
 @public
  NSString *key_;
}

- (instancetype)initWithNSString:(NSString *)key;

@end

J2OBJC_FIELD_SETTER(OrgSlf4jMDC_MDCCloseable, key_, NSString *)

__attribute__((unused)) static void OrgSlf4jMDC_MDCCloseable_initWithNSString_(OrgSlf4jMDC_MDCCloseable *self, NSString *key);

__attribute__((unused)) static OrgSlf4jMDC_MDCCloseable *new_OrgSlf4jMDC_MDCCloseable_initWithNSString_(NSString *key) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSlf4jMDC_MDCCloseable *create_OrgSlf4jMDC_MDCCloseable_initWithNSString_(NSString *key);

J2OBJC_INITIALIZED_DEFN(OrgSlf4jMDC)

NSString *OrgSlf4jMDC_NULL_MDCA_URL = @"http://www.slf4j.org/codes.html#null_MDCA";
NSString *OrgSlf4jMDC_NO_STATIC_MDC_BINDER_URL = @"http://www.slf4j.org/codes.html#no_static_mdc_binder";
id<OrgSlf4jSpiMDCAdapter> OrgSlf4jMDC_mdcAdapter;

@implementation OrgSlf4jMDC

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSlf4jMDC_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (id<OrgSlf4jSpiMDCAdapter>)bwCompatibleGetMDCAdapterFromBinder {
  return OrgSlf4jMDC_bwCompatibleGetMDCAdapterFromBinder();
}

+ (void)putWithNSString:(NSString *)key
           withNSString:(NSString *)val {
  OrgSlf4jMDC_putWithNSString_withNSString_(key, val);
}

+ (OrgSlf4jMDC_MDCCloseable *)putCloseableWithNSString:(NSString *)key
                                          withNSString:(NSString *)val {
  return OrgSlf4jMDC_putCloseableWithNSString_withNSString_(key, val);
}

+ (NSString *)getWithNSString:(NSString *)key {
  return OrgSlf4jMDC_getWithNSString_(key);
}

+ (void)removeWithNSString:(NSString *)key {
  OrgSlf4jMDC_removeWithNSString_(key);
}

+ (void)clear {
  OrgSlf4jMDC_clear();
}

+ (id<JavaUtilMap>)getCopyOfContextMap {
  return OrgSlf4jMDC_getCopyOfContextMap();
}

+ (void)setContextMapWithJavaUtilMap:(id<JavaUtilMap>)contextMap {
  OrgSlf4jMDC_setContextMapWithJavaUtilMap_(contextMap);
}

+ (id<OrgSlf4jSpiMDCAdapter>)getMDCAdapter {
  return OrgSlf4jMDC_getMDCAdapter();
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSlf4jSpiMDCAdapter;", 0xa, -1, -1, 0, -1, -1, -1 },
    { NULL, "V", 0x9, 1, 2, 3, -1, -1, -1 },
    { NULL, "LOrgSlf4jMDC_MDCCloseable;", 0x9, 4, 2, 3, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 5, 6, 3, -1, -1, -1 },
    { NULL, "V", 0x9, 7, 6, 3, -1, -1, -1 },
    { NULL, "V", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilMap;", 0x9, -1, -1, -1, 8, -1, -1 },
    { NULL, "V", 0x9, 9, 10, -1, 11, -1, -1 },
    { NULL, "LOrgSlf4jSpiMDCAdapter;", 0x9, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(bwCompatibleGetMDCAdapterFromBinder);
  methods[2].selector = @selector(putWithNSString:withNSString:);
  methods[3].selector = @selector(putCloseableWithNSString:withNSString:);
  methods[4].selector = @selector(getWithNSString:);
  methods[5].selector = @selector(removeWithNSString:);
  methods[6].selector = @selector(clear);
  methods[7].selector = @selector(getCopyOfContextMap);
  methods[8].selector = @selector(setContextMapWithJavaUtilMap:);
  methods[9].selector = @selector(getMDCAdapter);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "NULL_MDCA_URL", "LNSString;", .constantValue.asLong = 0, 0x18, -1, 12, -1, -1 },
    { "NO_STATIC_MDC_BINDER_URL", "LNSString;", .constantValue.asLong = 0, 0x18, -1, 13, -1, -1 },
    { "mdcAdapter", "LOrgSlf4jSpiMDCAdapter;", .constantValue.asLong = 0, 0x8, -1, 14, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaLangNoClassDefFoundError;", "put", "LNSString;LNSString;", "LJavaLangIllegalArgumentException;", "putCloseable", "get", "LNSString;", "remove", "()Ljava/util/Map<Ljava/lang/String;Ljava/lang/String;>;", "setContextMap", "LJavaUtilMap;", "(Ljava/util/Map<Ljava/lang/String;Ljava/lang/String;>;)V", &OrgSlf4jMDC_NULL_MDCA_URL, &OrgSlf4jMDC_NO_STATIC_MDC_BINDER_URL, &OrgSlf4jMDC_mdcAdapter, "LOrgSlf4jMDC_MDCCloseable;" };
  static const J2ObjcClassInfo _OrgSlf4jMDC = { "MDC", "org.slf4j", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, 15, -1, -1, -1 };
  return &_OrgSlf4jMDC;
}

+ (void)initialize {
  if (self == [OrgSlf4jMDC class]) {
    {
      @try {
        OrgSlf4jMDC_mdcAdapter = OrgSlf4jMDC_bwCompatibleGetMDCAdapterFromBinder();
      }
      @catch (JavaLangNoClassDefFoundError *ncde) {
        OrgSlf4jMDC_mdcAdapter = new_OrgSlf4jHelpersNOPMDCAdapter_init();
        NSString *msg = [ncde getMessage];
        if (msg != nil && [msg java_contains:@"StaticMDCBinder"]) {
          OrgSlf4jHelpersUtil_reportWithNSString_(@"Failed to load class \"org.slf4j.impl.StaticMDCBinder\".");
          OrgSlf4jHelpersUtil_reportWithNSString_(@"Defaulting to no-operation MDCAdapter implementation.");
          OrgSlf4jHelpersUtil_reportWithNSString_(JreStrcat("$$$", @"See ", OrgSlf4jMDC_NO_STATIC_MDC_BINDER_URL, @" for further details."));
        }
        else {
          @throw ncde;
        }
      }
      @catch (JavaLangException *e) {
        OrgSlf4jHelpersUtil_reportWithNSString_withJavaLangThrowable_(@"MDC binding unsuccessful.", e);
      }
    }
    J2OBJC_SET_INITIALIZED(OrgSlf4jMDC)
  }
}

@end

void OrgSlf4jMDC_init(OrgSlf4jMDC *self) {
  NSObject_init(self);
}

OrgSlf4jMDC *new_OrgSlf4jMDC_init() {
  J2OBJC_NEW_IMPL(OrgSlf4jMDC, init)
}

OrgSlf4jMDC *create_OrgSlf4jMDC_init() {
  J2OBJC_CREATE_IMPL(OrgSlf4jMDC, init)
}

id<OrgSlf4jSpiMDCAdapter> OrgSlf4jMDC_bwCompatibleGetMDCAdapterFromBinder() {
  OrgSlf4jMDC_initialize();
  @try {
    return [((OrgSlf4jImplStaticMDCBinder *) nil_chk(OrgSlf4jImplStaticMDCBinder_getSingleton())) getMDCA];
  }
  @catch (JavaLangNoSuchMethodError *nsme) {
    return [((OrgSlf4jImplStaticMDCBinder *) nil_chk(JreLoadStatic(OrgSlf4jImplStaticMDCBinder, SINGLETON))) getMDCA];
  }
}

void OrgSlf4jMDC_putWithNSString_withNSString_(NSString *key, NSString *val) {
  OrgSlf4jMDC_initialize();
  if (key == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key parameter cannot be null");
  }
  if (OrgSlf4jMDC_mdcAdapter == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", @"MDCAdapter cannot be null. See also ", OrgSlf4jMDC_NULL_MDCA_URL));
  }
  [OrgSlf4jMDC_mdcAdapter putWithNSString:key withNSString:val];
}

OrgSlf4jMDC_MDCCloseable *OrgSlf4jMDC_putCloseableWithNSString_withNSString_(NSString *key, NSString *val) {
  OrgSlf4jMDC_initialize();
  OrgSlf4jMDC_putWithNSString_withNSString_(key, val);
  return new_OrgSlf4jMDC_MDCCloseable_initWithNSString_(key);
}

NSString *OrgSlf4jMDC_getWithNSString_(NSString *key) {
  OrgSlf4jMDC_initialize();
  if (key == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key parameter cannot be null");
  }
  if (OrgSlf4jMDC_mdcAdapter == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", @"MDCAdapter cannot be null. See also ", OrgSlf4jMDC_NULL_MDCA_URL));
  }
  return [OrgSlf4jMDC_mdcAdapter getWithNSString:key];
}

void OrgSlf4jMDC_removeWithNSString_(NSString *key) {
  OrgSlf4jMDC_initialize();
  if (key == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key parameter cannot be null");
  }
  if (OrgSlf4jMDC_mdcAdapter == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", @"MDCAdapter cannot be null. See also ", OrgSlf4jMDC_NULL_MDCA_URL));
  }
  [OrgSlf4jMDC_mdcAdapter removeWithNSString:key];
}

void OrgSlf4jMDC_clear() {
  OrgSlf4jMDC_initialize();
  if (OrgSlf4jMDC_mdcAdapter == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", @"MDCAdapter cannot be null. See also ", OrgSlf4jMDC_NULL_MDCA_URL));
  }
  [OrgSlf4jMDC_mdcAdapter clear];
}

id<JavaUtilMap> OrgSlf4jMDC_getCopyOfContextMap() {
  OrgSlf4jMDC_initialize();
  if (OrgSlf4jMDC_mdcAdapter == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", @"MDCAdapter cannot be null. See also ", OrgSlf4jMDC_NULL_MDCA_URL));
  }
  return [OrgSlf4jMDC_mdcAdapter getCopyOfContextMap];
}

void OrgSlf4jMDC_setContextMapWithJavaUtilMap_(id<JavaUtilMap> contextMap) {
  OrgSlf4jMDC_initialize();
  if (OrgSlf4jMDC_mdcAdapter == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$$", @"MDCAdapter cannot be null. See also ", OrgSlf4jMDC_NULL_MDCA_URL));
  }
  [OrgSlf4jMDC_mdcAdapter setContextMapWithJavaUtilMap:contextMap];
}

id<OrgSlf4jSpiMDCAdapter> OrgSlf4jMDC_getMDCAdapter() {
  OrgSlf4jMDC_initialize();
  return OrgSlf4jMDC_mdcAdapter;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSlf4jMDC)

@implementation OrgSlf4jMDC_MDCCloseable

- (instancetype)initWithNSString:(NSString *)key {
  OrgSlf4jMDC_MDCCloseable_initWithNSString_(self, key);
  return self;
}

- (void)close {
  OrgSlf4jMDC_removeWithNSString_(self->key_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "key_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "LOrgSlf4jMDC;" };
  static const J2ObjcClassInfo _OrgSlf4jMDC_MDCCloseable = { "MDCCloseable", "org.slf4j", ptrTable, methods, fields, 7, 0x9, 2, 1, 1, -1, -1, -1, -1 };
  return &_OrgSlf4jMDC_MDCCloseable;
}

@end

void OrgSlf4jMDC_MDCCloseable_initWithNSString_(OrgSlf4jMDC_MDCCloseable *self, NSString *key) {
  NSObject_init(self);
  self->key_ = key;
}

OrgSlf4jMDC_MDCCloseable *new_OrgSlf4jMDC_MDCCloseable_initWithNSString_(NSString *key) {
  J2OBJC_NEW_IMPL(OrgSlf4jMDC_MDCCloseable, initWithNSString_, key)
}

OrgSlf4jMDC_MDCCloseable *create_OrgSlf4jMDC_MDCCloseable_initWithNSString_(NSString *key) {
  J2OBJC_CREATE_IMPL(OrgSlf4jMDC_MDCCloseable, initWithNSString_, key)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSlf4jMDC_MDCCloseable)
