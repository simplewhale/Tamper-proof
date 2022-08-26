//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/helpers/SubstituteLoggerFactory.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSlf4jHelpersSubstituteLoggerFactory")
#ifdef RESTRICT_OrgSlf4jHelpersSubstituteLoggerFactory
#define INCLUDE_ALL_OrgSlf4jHelpersSubstituteLoggerFactory 0
#else
#define INCLUDE_ALL_OrgSlf4jHelpersSubstituteLoggerFactory 1
#endif
#undef RESTRICT_OrgSlf4jHelpersSubstituteLoggerFactory

#if !defined (OrgSlf4jHelpersSubstituteLoggerFactory_) && (INCLUDE_ALL_OrgSlf4jHelpersSubstituteLoggerFactory || defined(INCLUDE_OrgSlf4jHelpersSubstituteLoggerFactory))
#define OrgSlf4jHelpersSubstituteLoggerFactory_

#define RESTRICT_OrgSlf4jILoggerFactory 1
#define INCLUDE_OrgSlf4jILoggerFactory 1
#include "org/slf4j/ILoggerFactory.h"

@class JavaUtilConcurrentLinkedBlockingQueue;
@protocol JavaUtilList;
@protocol JavaUtilMap;
@protocol OrgSlf4jLogger;

@interface OrgSlf4jHelpersSubstituteLoggerFactory : NSObject < OrgSlf4jILoggerFactory > {
 @public
  jboolean postInitialization_;
  id<JavaUtilMap> loggers_;
  JavaUtilConcurrentLinkedBlockingQueue *eventQueue_;
}

#pragma mark Public

- (instancetype)init;

- (void)clear;

- (JavaUtilConcurrentLinkedBlockingQueue *)getEventQueue;

- (id<OrgSlf4jLogger>)getLoggerWithNSString:(NSString *)name;

- (id<JavaUtilList>)getLoggerNames;

- (id<JavaUtilList>)getLoggers;

- (void)postInitialization;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSlf4jHelpersSubstituteLoggerFactory)

J2OBJC_FIELD_SETTER(OrgSlf4jHelpersSubstituteLoggerFactory, loggers_, id<JavaUtilMap>)
J2OBJC_FIELD_SETTER(OrgSlf4jHelpersSubstituteLoggerFactory, eventQueue_, JavaUtilConcurrentLinkedBlockingQueue *)

FOUNDATION_EXPORT void OrgSlf4jHelpersSubstituteLoggerFactory_init(OrgSlf4jHelpersSubstituteLoggerFactory *self);

FOUNDATION_EXPORT OrgSlf4jHelpersSubstituteLoggerFactory *new_OrgSlf4jHelpersSubstituteLoggerFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSlf4jHelpersSubstituteLoggerFactory *create_OrgSlf4jHelpersSubstituteLoggerFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSlf4jHelpersSubstituteLoggerFactory)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSlf4jHelpersSubstituteLoggerFactory")