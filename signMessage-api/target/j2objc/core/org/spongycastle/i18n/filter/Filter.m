//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/i18n/filter/Filter.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/i18n/filter/Filter.h"

@interface OrgSpongycastleI18nFilterFilter : NSObject

@end

@implementation OrgSpongycastleI18nFilterFilter

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LNSString;", 0x401, 0, 1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x401, 2, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(doFilterWithNSString:);
  methods[1].selector = @selector(doFilterUrlWithNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "doFilter", "LNSString;", "doFilterUrl" };
  static const J2ObjcClassInfo _OrgSpongycastleI18nFilterFilter = { "Filter", "org.spongycastle.i18n.filter", ptrTable, methods, NULL, 7, 0x609, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleI18nFilterFilter;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleI18nFilterFilter)
