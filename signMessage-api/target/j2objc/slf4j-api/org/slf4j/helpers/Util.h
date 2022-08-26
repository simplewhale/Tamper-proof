//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/helpers/Util.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSlf4jHelpersUtil")
#ifdef RESTRICT_OrgSlf4jHelpersUtil
#define INCLUDE_ALL_OrgSlf4jHelpersUtil 0
#else
#define INCLUDE_ALL_OrgSlf4jHelpersUtil 1
#endif
#undef RESTRICT_OrgSlf4jHelpersUtil

#if !defined (OrgSlf4jHelpersUtil_) && (INCLUDE_ALL_OrgSlf4jHelpersUtil || defined(INCLUDE_OrgSlf4jHelpersUtil))
#define OrgSlf4jHelpersUtil_

@class IOSClass;
@class JavaLangThrowable;

@interface OrgSlf4jHelpersUtil : NSObject

#pragma mark Public

+ (IOSClass *)getCallingClass;

+ (void)reportWithNSString:(NSString *)msg;

+ (void)reportWithNSString:(NSString *)msg
     withJavaLangThrowable:(JavaLangThrowable *)t;

+ (jboolean)safeGetBooleanSystemPropertyWithNSString:(NSString *)key;

+ (NSString *)safeGetSystemPropertyWithNSString:(NSString *)key;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSlf4jHelpersUtil)

FOUNDATION_EXPORT NSString *OrgSlf4jHelpersUtil_safeGetSystemPropertyWithNSString_(NSString *key);

FOUNDATION_EXPORT jboolean OrgSlf4jHelpersUtil_safeGetBooleanSystemPropertyWithNSString_(NSString *key);

FOUNDATION_EXPORT IOSClass *OrgSlf4jHelpersUtil_getCallingClass(void);

FOUNDATION_EXPORT void OrgSlf4jHelpersUtil_reportWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *t);

FOUNDATION_EXPORT void OrgSlf4jHelpersUtil_reportWithNSString_(NSString *msg);

J2OBJC_TYPE_LITERAL_HEADER(OrgSlf4jHelpersUtil)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSlf4jHelpersUtil")
