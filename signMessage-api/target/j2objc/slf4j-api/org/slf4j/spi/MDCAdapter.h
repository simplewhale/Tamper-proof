//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/spi/MDCAdapter.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSlf4jSpiMDCAdapter")
#ifdef RESTRICT_OrgSlf4jSpiMDCAdapter
#define INCLUDE_ALL_OrgSlf4jSpiMDCAdapter 0
#else
#define INCLUDE_ALL_OrgSlf4jSpiMDCAdapter 1
#endif
#undef RESTRICT_OrgSlf4jSpiMDCAdapter

#if !defined (OrgSlf4jSpiMDCAdapter_) && (INCLUDE_ALL_OrgSlf4jSpiMDCAdapter || defined(INCLUDE_OrgSlf4jSpiMDCAdapter))
#define OrgSlf4jSpiMDCAdapter_

@protocol JavaUtilMap;

@protocol OrgSlf4jSpiMDCAdapter < JavaObject >

- (void)putWithNSString:(NSString *)key
           withNSString:(NSString *)val;

- (NSString *)getWithNSString:(NSString *)key;

- (void)removeWithNSString:(NSString *)key;

- (void)clear;

- (id<JavaUtilMap>)getCopyOfContextMap;

- (void)setContextMapWithJavaUtilMap:(id<JavaUtilMap>)contextMap;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSlf4jSpiMDCAdapter)

J2OBJC_TYPE_LITERAL_HEADER(OrgSlf4jSpiMDCAdapter)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSlf4jSpiMDCAdapter")
