//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/test/TestResult.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/util/test/TestResult.h"

@interface OrgSpongycastleUtilTestTestResult : NSObject

@end

@implementation OrgSpongycastleUtilTestTestResult

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "Z", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x401, 0, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(isSuccessful);
  methods[1].selector = @selector(getException);
  methods[2].selector = @selector(description);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "toString" };
  static const J2ObjcClassInfo _OrgSpongycastleUtilTestTestResult = { "TestResult", "org.spongycastle.util.test", ptrTable, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilTestTestResult;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilTestTestResult)