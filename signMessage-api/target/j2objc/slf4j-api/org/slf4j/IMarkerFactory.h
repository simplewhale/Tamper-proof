//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/IMarkerFactory.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSlf4jIMarkerFactory")
#ifdef RESTRICT_OrgSlf4jIMarkerFactory
#define INCLUDE_ALL_OrgSlf4jIMarkerFactory 0
#else
#define INCLUDE_ALL_OrgSlf4jIMarkerFactory 1
#endif
#undef RESTRICT_OrgSlf4jIMarkerFactory

#if !defined (OrgSlf4jIMarkerFactory_) && (INCLUDE_ALL_OrgSlf4jIMarkerFactory || defined(INCLUDE_OrgSlf4jIMarkerFactory))
#define OrgSlf4jIMarkerFactory_

@protocol OrgSlf4jMarker;

@protocol OrgSlf4jIMarkerFactory < JavaObject >

- (id<OrgSlf4jMarker>)getMarkerWithNSString:(NSString *)name;

- (jboolean)existsWithNSString:(NSString *)name;

- (jboolean)detachMarkerWithNSString:(NSString *)name;

- (id<OrgSlf4jMarker>)getDetachedMarkerWithNSString:(NSString *)name;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSlf4jIMarkerFactory)

J2OBJC_TYPE_LITERAL_HEADER(OrgSlf4jIMarkerFactory)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSlf4jIMarkerFactory")