//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/BIP39/io/github/novacrypto/bip39/wordlists/French.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsFrench")
#ifdef RESTRICT_IoGithubNovacryptoBip39WordlistsFrench
#define INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsFrench 0
#else
#define INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsFrench 1
#endif
#undef RESTRICT_IoGithubNovacryptoBip39WordlistsFrench

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#if !defined (IoGithubNovacryptoBip39WordlistsFrench_) && (INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsFrench || defined(INCLUDE_IoGithubNovacryptoBip39WordlistsFrench))
#define IoGithubNovacryptoBip39WordlistsFrench_

#define RESTRICT_JavaLangEnum 1
#define INCLUDE_JavaLangEnum 1
#include "java/lang/Enum.h"

#define RESTRICT_IoGithubNovacryptoBip39WordList 1
#define INCLUDE_IoGithubNovacryptoBip39WordList 1
#include "io/github/novacrypto/bip39/WordList.h"

@class IOSObjectArray;

typedef NS_ENUM(NSUInteger, IoGithubNovacryptoBip39WordlistsFrench_Enum) {
  IoGithubNovacryptoBip39WordlistsFrench_Enum_INSTANCE = 0,
};

@interface IoGithubNovacryptoBip39WordlistsFrench : JavaLangEnum < IoGithubNovacryptoBip39WordList >

#pragma mark Public

- (jchar)getSpace;

- (NSString *)getWordWithInt:(jint)index;

+ (IoGithubNovacryptoBip39WordlistsFrench *)valueOfWithNSString:(NSString *)name;

+ (IOSObjectArray *)values;

@end

J2OBJC_STATIC_INIT(IoGithubNovacryptoBip39WordlistsFrench)

/*! INTERNAL ONLY - Use enum accessors declared below. */
FOUNDATION_EXPORT IoGithubNovacryptoBip39WordlistsFrench *IoGithubNovacryptoBip39WordlistsFrench_values_[];

inline IoGithubNovacryptoBip39WordlistsFrench *IoGithubNovacryptoBip39WordlistsFrench_get_INSTANCE(void);
J2OBJC_ENUM_CONSTANT(IoGithubNovacryptoBip39WordlistsFrench, INSTANCE)

FOUNDATION_EXPORT IOSObjectArray *IoGithubNovacryptoBip39WordlistsFrench_values(void);

FOUNDATION_EXPORT IoGithubNovacryptoBip39WordlistsFrench *IoGithubNovacryptoBip39WordlistsFrench_valueOfWithNSString_(NSString *name);

FOUNDATION_EXPORT IoGithubNovacryptoBip39WordlistsFrench *IoGithubNovacryptoBip39WordlistsFrench_fromOrdinal(NSUInteger ordinal);

J2OBJC_TYPE_LITERAL_HEADER(IoGithubNovacryptoBip39WordlistsFrench)

#endif


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#pragma pop_macro("INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsFrench")
