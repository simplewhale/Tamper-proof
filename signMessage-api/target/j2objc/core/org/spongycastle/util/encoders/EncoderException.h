//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/encoders/EncoderException.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleUtilEncodersEncoderException")
#ifdef RESTRICT_OrgSpongycastleUtilEncodersEncoderException
#define INCLUDE_ALL_OrgSpongycastleUtilEncodersEncoderException 0
#else
#define INCLUDE_ALL_OrgSpongycastleUtilEncodersEncoderException 1
#endif
#undef RESTRICT_OrgSpongycastleUtilEncodersEncoderException

#if !defined (OrgSpongycastleUtilEncodersEncoderException_) && (INCLUDE_ALL_OrgSpongycastleUtilEncodersEncoderException || defined(INCLUDE_OrgSpongycastleUtilEncodersEncoderException))
#define OrgSpongycastleUtilEncodersEncoderException_

#define RESTRICT_JavaLangIllegalStateException 1
#define INCLUDE_JavaLangIllegalStateException 1
#include "java/lang/IllegalStateException.h"

@class JavaLangThrowable;

@interface OrgSpongycastleUtilEncodersEncoderException : JavaLangIllegalStateException

#pragma mark Public

- (JavaLangThrowable *)getCause;

#pragma mark Package-Private

- (instancetype)initWithNSString:(NSString *)msg
           withJavaLangThrowable:(JavaLangThrowable *)cause;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleUtilEncodersEncoderException)

FOUNDATION_EXPORT void OrgSpongycastleUtilEncodersEncoderException_initWithNSString_withJavaLangThrowable_(OrgSpongycastleUtilEncodersEncoderException *self, NSString *msg, JavaLangThrowable *cause);

FOUNDATION_EXPORT OrgSpongycastleUtilEncodersEncoderException *new_OrgSpongycastleUtilEncodersEncoderException_initWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *cause) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleUtilEncodersEncoderException *create_OrgSpongycastleUtilEncodersEncoderException_initWithNSString_withJavaLangThrowable_(NSString *msg, JavaLangThrowable *cause);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleUtilEncodersEncoderException)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleUtilEncodersEncoderException")
