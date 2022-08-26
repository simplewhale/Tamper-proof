//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/helpers/Util.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/io/PrintStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/SecurityException.h"
#include "java/lang/SecurityManager.h"
#include "java/lang/System.h"
#include "java/lang/Throwable.h"
#include "org/slf4j/helpers/Util.h"

@class OrgSlf4jHelpersUtil_ClassContextSecurityManager;

@interface OrgSlf4jHelpersUtil ()

- (instancetype)init;

+ (OrgSlf4jHelpersUtil_ClassContextSecurityManager *)getSecurityManager;

+ (OrgSlf4jHelpersUtil_ClassContextSecurityManager *)safeCreateSecurityManager;

@end

inline OrgSlf4jHelpersUtil_ClassContextSecurityManager *OrgSlf4jHelpersUtil_get_SECURITY_MANAGER(void);
inline OrgSlf4jHelpersUtil_ClassContextSecurityManager *OrgSlf4jHelpersUtil_set_SECURITY_MANAGER(OrgSlf4jHelpersUtil_ClassContextSecurityManager *value);
static OrgSlf4jHelpersUtil_ClassContextSecurityManager *OrgSlf4jHelpersUtil_SECURITY_MANAGER;
J2OBJC_STATIC_FIELD_OBJ(OrgSlf4jHelpersUtil, SECURITY_MANAGER, OrgSlf4jHelpersUtil_ClassContextSecurityManager *)

inline jboolean OrgSlf4jHelpersUtil_get_SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED(void);
inline jboolean OrgSlf4jHelpersUtil_set_SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED(jboolean value);
inline jboolean *OrgSlf4jHelpersUtil_getRef_SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED(void);
static jboolean OrgSlf4jHelpersUtil_SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED = false;
J2OBJC_STATIC_FIELD_PRIMITIVE(OrgSlf4jHelpersUtil, SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED, jboolean)

__attribute__((unused)) static void OrgSlf4jHelpersUtil_init(OrgSlf4jHelpersUtil *self);

__attribute__((unused)) static OrgSlf4jHelpersUtil *new_OrgSlf4jHelpersUtil_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSlf4jHelpersUtil *create_OrgSlf4jHelpersUtil_init(void);

__attribute__((unused)) static OrgSlf4jHelpersUtil_ClassContextSecurityManager *OrgSlf4jHelpersUtil_getSecurityManager(void);

__attribute__((unused)) static OrgSlf4jHelpersUtil_ClassContextSecurityManager *OrgSlf4jHelpersUtil_safeCreateSecurityManager(void);

@interface OrgSlf4jHelpersUtil_ClassContextSecurityManager : JavaLangSecurityManager

- (instancetype)init;

- (IOSObjectArray *)getClassContext;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSlf4jHelpersUtil_ClassContextSecurityManager)

__attribute__((unused)) static void OrgSlf4jHelpersUtil_ClassContextSecurityManager_init(OrgSlf4jHelpersUtil_ClassContextSecurityManager *self);

__attribute__((unused)) static OrgSlf4jHelpersUtil_ClassContextSecurityManager *new_OrgSlf4jHelpersUtil_ClassContextSecurityManager_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static OrgSlf4jHelpersUtil_ClassContextSecurityManager *create_OrgSlf4jHelpersUtil_ClassContextSecurityManager_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSlf4jHelpersUtil_ClassContextSecurityManager)

@implementation OrgSlf4jHelpersUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSlf4jHelpersUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (NSString *)safeGetSystemPropertyWithNSString:(NSString *)key {
  return OrgSlf4jHelpersUtil_safeGetSystemPropertyWithNSString_(key);
}

+ (jboolean)safeGetBooleanSystemPropertyWithNSString:(NSString *)key {
  return OrgSlf4jHelpersUtil_safeGetBooleanSystemPropertyWithNSString_(key);
}

+ (OrgSlf4jHelpersUtil_ClassContextSecurityManager *)getSecurityManager {
  return OrgSlf4jHelpersUtil_getSecurityManager();
}

+ (OrgSlf4jHelpersUtil_ClassContextSecurityManager *)safeCreateSecurityManager {
  return OrgSlf4jHelpersUtil_safeCreateSecurityManager();
}

+ (IOSClass *)getCallingClass {
  return OrgSlf4jHelpersUtil_getCallingClass();
}

+ (void)reportWithNSString:(NSString *)msg
     withJavaLangThrowable:(JavaLangThrowable *)t {
  OrgSlf4jHelpersUtil_reportWithNSString_withJavaLangThrowable_(msg, t);
}

+ (void)reportWithNSString:(NSString *)msg {
  OrgSlf4jHelpersUtil_reportWithNSString_(msg);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 2, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSlf4jHelpersUtil_ClassContextSecurityManager;", 0xa, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSlf4jHelpersUtil_ClassContextSecurityManager;", 0xa, -1, -1, -1, -1, -1, -1 },
    { NULL, "LIOSClass;", 0x9, -1, -1, -1, 3, -1, -1 },
    { NULL, "V", 0x19, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x19, 4, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(safeGetSystemPropertyWithNSString:);
  methods[2].selector = @selector(safeGetBooleanSystemPropertyWithNSString:);
  methods[3].selector = @selector(getSecurityManager);
  methods[4].selector = @selector(safeCreateSecurityManager);
  methods[5].selector = @selector(getCallingClass);
  methods[6].selector = @selector(reportWithNSString:withJavaLangThrowable:);
  methods[7].selector = @selector(reportWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "SECURITY_MANAGER", "LOrgSlf4jHelpersUtil_ClassContextSecurityManager;", .constantValue.asLong = 0, 0xa, -1, 6, -1, -1 },
    { "SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED", "Z", .constantValue.asLong = 0, 0xa, -1, 7, -1, -1 },
  };
  static const void *ptrTable[] = { "safeGetSystemProperty", "LNSString;", "safeGetBooleanSystemProperty", "()Ljava/lang/Class<*>;", "report", "LNSString;LJavaLangThrowable;", &OrgSlf4jHelpersUtil_SECURITY_MANAGER, &OrgSlf4jHelpersUtil_SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED, "LOrgSlf4jHelpersUtil_ClassContextSecurityManager;" };
  static const J2ObjcClassInfo _OrgSlf4jHelpersUtil = { "Util", "org.slf4j.helpers", ptrTable, methods, fields, 7, 0x11, 8, 2, -1, 8, -1, -1, -1 };
  return &_OrgSlf4jHelpersUtil;
}

@end

void OrgSlf4jHelpersUtil_init(OrgSlf4jHelpersUtil *self) {
  NSObject_init(self);
}

OrgSlf4jHelpersUtil *new_OrgSlf4jHelpersUtil_init() {
  J2OBJC_NEW_IMPL(OrgSlf4jHelpersUtil, init)
}

OrgSlf4jHelpersUtil *create_OrgSlf4jHelpersUtil_init() {
  J2OBJC_CREATE_IMPL(OrgSlf4jHelpersUtil, init)
}

NSString *OrgSlf4jHelpersUtil_safeGetSystemPropertyWithNSString_(NSString *key) {
  OrgSlf4jHelpersUtil_initialize();
  if (key == nil) @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"null input");
  NSString *result = nil;
  @try {
    result = JavaLangSystem_getPropertyWithNSString_(key);
  }
  @catch (JavaLangSecurityException *sm) {
    
    ;
  }
  return result;
}

jboolean OrgSlf4jHelpersUtil_safeGetBooleanSystemPropertyWithNSString_(NSString *key) {
  OrgSlf4jHelpersUtil_initialize();
  NSString *value = OrgSlf4jHelpersUtil_safeGetSystemPropertyWithNSString_(key);
  if (value == nil) return false;
  else return [value java_equalsIgnoreCase:@"true"];
}

OrgSlf4jHelpersUtil_ClassContextSecurityManager *OrgSlf4jHelpersUtil_getSecurityManager() {
  OrgSlf4jHelpersUtil_initialize();
  if (OrgSlf4jHelpersUtil_SECURITY_MANAGER != nil) return OrgSlf4jHelpersUtil_SECURITY_MANAGER;
  else if (OrgSlf4jHelpersUtil_SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED) return nil;
  else {
    OrgSlf4jHelpersUtil_SECURITY_MANAGER = OrgSlf4jHelpersUtil_safeCreateSecurityManager();
    OrgSlf4jHelpersUtil_SECURITY_MANAGER_CREATION_ALREADY_ATTEMPTED = true;
    return OrgSlf4jHelpersUtil_SECURITY_MANAGER;
  }
}

OrgSlf4jHelpersUtil_ClassContextSecurityManager *OrgSlf4jHelpersUtil_safeCreateSecurityManager() {
  OrgSlf4jHelpersUtil_initialize();
  @try {
    return new_OrgSlf4jHelpersUtil_ClassContextSecurityManager_init();
  }
  @catch (JavaLangSecurityException *sm) {
    return nil;
  }
}

IOSClass *OrgSlf4jHelpersUtil_getCallingClass() {
  OrgSlf4jHelpersUtil_initialize();
  OrgSlf4jHelpersUtil_ClassContextSecurityManager *securityManager = OrgSlf4jHelpersUtil_getSecurityManager();
  if (securityManager == nil) return nil;
  IOSObjectArray *trace = [securityManager getClassContext];
  NSString *thisClassName = [OrgSlf4jHelpersUtil_class_() getName];
  jint i;
  for (i = 0; i < ((IOSObjectArray *) nil_chk(trace))->size_; i++) {
    if ([((NSString *) nil_chk(thisClassName)) isEqual:[((IOSClass *) nil_chk(IOSObjectArray_Get(trace, i))) getName]]) break;
  }
  if (i >= trace->size_ || i + 2 >= trace->size_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Failed to find org.slf4j.helpers.Util or its caller in the stack; this should not happen");
  }
  return IOSObjectArray_Get(trace, i + 2);
}

void OrgSlf4jHelpersUtil_reportWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *t) {
  OrgSlf4jHelpersUtil_initialize();
  [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:msg];
  [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:@"Reported exception:"];
  [((JavaLangThrowable *) nil_chk(t)) printStackTrace];
}

void OrgSlf4jHelpersUtil_reportWithNSString_(NSString *msg) {
  OrgSlf4jHelpersUtil_initialize();
  [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:JreStrcat("$$", @"SLF4J: ", msg)];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSlf4jHelpersUtil)

@implementation OrgSlf4jHelpersUtil_ClassContextSecurityManager

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSlf4jHelpersUtil_ClassContextSecurityManager_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSObjectArray *)getClassContext {
  return [super getClassContext];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LIOSClass;", 0x4, -1, -1, -1, 0, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getClassContext);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "()[Ljava/lang/Class<*>;", "LOrgSlf4jHelpersUtil;" };
  static const J2ObjcClassInfo _OrgSlf4jHelpersUtil_ClassContextSecurityManager = { "ClassContextSecurityManager", "org.slf4j.helpers", ptrTable, methods, NULL, 7, 0x1a, 2, 0, 1, -1, -1, -1, -1 };
  return &_OrgSlf4jHelpersUtil_ClassContextSecurityManager;
}

@end

void OrgSlf4jHelpersUtil_ClassContextSecurityManager_init(OrgSlf4jHelpersUtil_ClassContextSecurityManager *self) {
  JavaLangSecurityManager_init(self);
}

OrgSlf4jHelpersUtil_ClassContextSecurityManager *new_OrgSlf4jHelpersUtil_ClassContextSecurityManager_init() {
  J2OBJC_NEW_IMPL(OrgSlf4jHelpersUtil_ClassContextSecurityManager, init)
}

OrgSlf4jHelpersUtil_ClassContextSecurityManager *create_OrgSlf4jHelpersUtil_ClassContextSecurityManager_init() {
  J2OBJC_CREATE_IMPL(OrgSlf4jHelpersUtil_ClassContextSecurityManager, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSlf4jHelpersUtil_ClassContextSecurityManager)