//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/slf4j-api/org/slf4j/spi/MarkerFactoryBinder.java
//

#include "J2ObjC_source.h"
#include "org/slf4j/spi/MarkerFactoryBinder.h"

@interface OrgSlf4jSpiMarkerFactoryBinder : NSObject

@end

@implementation OrgSlf4jSpiMarkerFactoryBinder

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LOrgSlf4jIMarkerFactory;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getMarkerFactory);
  methods[1].selector = @selector(getMarkerFactoryClassStr);
  #pragma clang diagnostic pop
  static const J2ObjcClassInfo _OrgSlf4jSpiMarkerFactoryBinder = { "MarkerFactoryBinder", "org.slf4j.spi", NULL, methods, NULL, 7, 0x609, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSlf4jSpiMarkerFactoryBinder;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSlf4jSpiMarkerFactoryBinder)
