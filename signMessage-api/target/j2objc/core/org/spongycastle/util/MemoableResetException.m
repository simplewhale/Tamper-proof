//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/MemoableResetException.java
//

#include "J2ObjC_source.h"
#include "java/lang/ClassCastException.h"
#include "org/spongycastle/util/MemoableResetException.h"

@implementation OrgSpongycastleUtilMemoableResetException

- (instancetype)initWithNSString:(NSString *)msg {
  OrgSpongycastleUtilMemoableResetException_initWithNSString_(self, msg);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LNSString;" };
  static const J2ObjcClassInfo _OrgSpongycastleUtilMemoableResetException = { "MemoableResetException", "org.spongycastle.util", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilMemoableResetException;
}

@end

void OrgSpongycastleUtilMemoableResetException_initWithNSString_(OrgSpongycastleUtilMemoableResetException *self, NSString *msg) {
  JavaLangClassCastException_initWithNSString_(self, msg);
}

OrgSpongycastleUtilMemoableResetException *new_OrgSpongycastleUtilMemoableResetException_initWithNSString_(NSString *msg) {
  J2OBJC_NEW_IMPL(OrgSpongycastleUtilMemoableResetException, initWithNSString_, msg)
}

OrgSpongycastleUtilMemoableResetException *create_OrgSpongycastleUtilMemoableResetException_initWithNSString_(NSString *msg) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleUtilMemoableResetException, initWithNSString_, msg)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilMemoableResetException)
