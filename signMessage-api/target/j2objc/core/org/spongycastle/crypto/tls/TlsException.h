//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsException.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsException")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsTlsException
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsException 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsException 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsTlsException

#if !defined (OrgSpongycastleCryptoTlsTlsException_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsException || defined(INCLUDE_OrgSpongycastleCryptoTlsTlsException))
#define OrgSpongycastleCryptoTlsTlsException_

#define RESTRICT_JavaIoIOException 1
#define INCLUDE_JavaIoIOException 1
#include "java/io/IOException.h"

@class JavaLangThrowable;

@interface OrgSpongycastleCryptoTlsTlsException : JavaIoIOException {
 @public
  JavaLangThrowable *cause_TlsException_;
}

#pragma mark Public

- (instancetype)initWithNSString:(NSString *)message
           withJavaLangThrowable:(JavaLangThrowable *)cause;

- (JavaLangThrowable *)getCause;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsTlsException)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsTlsException, cause_TlsException_, JavaLangThrowable *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsTlsException_initWithNSString_withJavaLangThrowable_(OrgSpongycastleCryptoTlsTlsException *self, NSString *message, JavaLangThrowable *cause);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsTlsException *new_OrgSpongycastleCryptoTlsTlsException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsTlsException *create_OrgSpongycastleCryptoTlsTlsException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsTlsException)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsException")
