//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/test/TestFailedException.java
//

#include "J2ObjC_source.h"
#include "java/lang/RuntimeException.h"
#include "org/spongycastle/util/test/TestFailedException.h"
#include "org/spongycastle/util/test/TestResult.h"

@interface OrgSpongycastleUtilTestTestFailedException () {
 @public
  id<OrgSpongycastleUtilTestTestResult> _result_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleUtilTestTestFailedException, _result_, id<OrgSpongycastleUtilTestTestResult>)

@implementation OrgSpongycastleUtilTestTestFailedException

- (instancetype)initWithOrgSpongycastleUtilTestTestResult:(id<OrgSpongycastleUtilTestTestResult>)result {
  OrgSpongycastleUtilTestTestFailedException_initWithOrgSpongycastleUtilTestTestResult_(self, result);
  return self;
}

- (id<OrgSpongycastleUtilTestTestResult>)getResult {
  return _result_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleUtilTestTestResult;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleUtilTestTestResult:);
  methods[1].selector = @selector(getResult);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_result_", "LOrgSpongycastleUtilTestTestResult;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleUtilTestTestResult;" };
  static const J2ObjcClassInfo _OrgSpongycastleUtilTestTestFailedException = { "TestFailedException", "org.spongycastle.util.test", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilTestTestFailedException;
}

@end

void OrgSpongycastleUtilTestTestFailedException_initWithOrgSpongycastleUtilTestTestResult_(OrgSpongycastleUtilTestTestFailedException *self, id<OrgSpongycastleUtilTestTestResult> result) {
  JavaLangRuntimeException_init(self);
  self->_result_ = result;
}

OrgSpongycastleUtilTestTestFailedException *new_OrgSpongycastleUtilTestTestFailedException_initWithOrgSpongycastleUtilTestTestResult_(id<OrgSpongycastleUtilTestTestResult> result) {
  J2OBJC_NEW_IMPL(OrgSpongycastleUtilTestTestFailedException, initWithOrgSpongycastleUtilTestTestResult_, result)
}

OrgSpongycastleUtilTestTestFailedException *create_OrgSpongycastleUtilTestTestFailedException_initWithOrgSpongycastleUtilTestTestResult_(id<OrgSpongycastleUtilTestTestResult> result) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleUtilTestTestFailedException, initWithOrgSpongycastleUtilTestTestResult_, result)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilTestTestFailedException)
