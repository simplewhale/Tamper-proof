//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/SHA256/io/github/novacrypto/hashing/Sha256.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_IoGithubNovacryptoHashingSha256")
#ifdef RESTRICT_IoGithubNovacryptoHashingSha256
#define INCLUDE_ALL_IoGithubNovacryptoHashingSha256 0
#else
#define INCLUDE_ALL_IoGithubNovacryptoHashingSha256 1
#endif
#undef RESTRICT_IoGithubNovacryptoHashingSha256

#if !defined (IoGithubNovacryptoHashingSha256_) && (INCLUDE_ALL_IoGithubNovacryptoHashingSha256 || defined(INCLUDE_IoGithubNovacryptoHashingSha256))
#define IoGithubNovacryptoHashingSha256_

@class IOSByteArray;

@interface IoGithubNovacryptoHashingSha256 : NSObject

#pragma mark Public

+ (IOSByteArray *)sha256WithByteArray:(IOSByteArray *)bytes;

+ (IOSByteArray *)sha256WithByteArray:(IOSByteArray *)bytes
                              withInt:(jint)offset
                              withInt:(jint)length;

+ (IOSByteArray *)sha256TwiceWithByteArray:(IOSByteArray *)bytes;

+ (IOSByteArray *)sha256TwiceWithByteArray:(IOSByteArray *)bytes
                                   withInt:(jint)offset
                                   withInt:(jint)length;

#pragma mark Package-Private

- (instancetype)init;

@end

J2OBJC_EMPTY_STATIC_INIT(IoGithubNovacryptoHashingSha256)

FOUNDATION_EXPORT void IoGithubNovacryptoHashingSha256_init(IoGithubNovacryptoHashingSha256 *self);

FOUNDATION_EXPORT IoGithubNovacryptoHashingSha256 *new_IoGithubNovacryptoHashingSha256_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT IoGithubNovacryptoHashingSha256 *create_IoGithubNovacryptoHashingSha256_init(void);

FOUNDATION_EXPORT IOSByteArray *IoGithubNovacryptoHashingSha256_sha256WithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT IOSByteArray *IoGithubNovacryptoHashingSha256_sha256WithByteArray_withInt_withInt_(IOSByteArray *bytes, jint offset, jint length);

FOUNDATION_EXPORT IOSByteArray *IoGithubNovacryptoHashingSha256_sha256TwiceWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT IOSByteArray *IoGithubNovacryptoHashingSha256_sha256TwiceWithByteArray_withInt_withInt_(IOSByteArray *bytes, jint offset, jint length);

J2OBJC_TYPE_LITERAL_HEADER(IoGithubNovacryptoHashingSha256)

#endif

#pragma pop_macro("INCLUDE_ALL_IoGithubNovacryptoHashingSha256")