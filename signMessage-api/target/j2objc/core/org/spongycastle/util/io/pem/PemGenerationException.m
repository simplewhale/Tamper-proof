//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/io/pem/PemGenerationException.java
//

#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/Throwable.h"
#include "org/spongycastle/util/io/pem/PemGenerationException.h"

@interface OrgSpongycastleUtilIoPemPemGenerationException () {
 @public
  JavaLangThrowable *cause_PemGenerationException_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleUtilIoPemPemGenerationException, cause_PemGenerationException_, JavaLangThrowable *)

@implementation OrgSpongycastleUtilIoPemPemGenerationException

- (instancetype)initWithNSString:(NSString *)message
           withJavaLangThrowable:(JavaLangThrowable *)cause {
  OrgSpongycastleUtilIoPemPemGenerationException_initWithNSString_withJavaLangThrowable_(self, message, cause);
  return self;
}

- (instancetype)initWithNSString:(NSString *)message {
  OrgSpongycastleUtilIoPemPemGenerationException_initWithNSString_(self, message);
  return self;
}

- (JavaLangThrowable *)getCause {
  return cause_PemGenerationException_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withJavaLangThrowable:);
  methods[1].selector = @selector(initWithNSString:);
  methods[2].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cause_PemGenerationException_", "LJavaLangThrowable;", .constantValue.asLong = 0, 0x2, 2, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LJavaLangThrowable;", "LNSString;", "cause" };
  static const J2ObjcClassInfo _OrgSpongycastleUtilIoPemPemGenerationException = { "PemGenerationException", "org.spongycastle.util.io.pem", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleUtilIoPemPemGenerationException;
}

@end

void OrgSpongycastleUtilIoPemPemGenerationException_initWithNSString_withJavaLangThrowable_(OrgSpongycastleUtilIoPemPemGenerationException *self, NSString *message, JavaLangThrowable *cause) {
  JavaIoIOException_initWithNSString_(self, message);
  self->cause_PemGenerationException_ = cause;
}

OrgSpongycastleUtilIoPemPemGenerationException *new_OrgSpongycastleUtilIoPemPemGenerationException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(OrgSpongycastleUtilIoPemPemGenerationException, initWithNSString_withJavaLangThrowable_, message, cause)
}

OrgSpongycastleUtilIoPemPemGenerationException *create_OrgSpongycastleUtilIoPemPemGenerationException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleUtilIoPemPemGenerationException, initWithNSString_withJavaLangThrowable_, message, cause)
}

void OrgSpongycastleUtilIoPemPemGenerationException_initWithNSString_(OrgSpongycastleUtilIoPemPemGenerationException *self, NSString *message) {
  JavaIoIOException_initWithNSString_(self, message);
}

OrgSpongycastleUtilIoPemPemGenerationException *new_OrgSpongycastleUtilIoPemPemGenerationException_initWithNSString_(NSString *message) {
  J2OBJC_NEW_IMPL(OrgSpongycastleUtilIoPemPemGenerationException, initWithNSString_, message)
}

OrgSpongycastleUtilIoPemPemGenerationException *create_OrgSpongycastleUtilIoPemPemGenerationException_initWithNSString_(NSString *message) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleUtilIoPemPemGenerationException, initWithNSString_, message)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleUtilIoPemPemGenerationException)
