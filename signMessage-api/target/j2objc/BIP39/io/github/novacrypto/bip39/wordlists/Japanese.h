//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/BIP39/io/github/novacrypto/bip39/wordlists/Japanese.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsJapanese")
#ifdef RESTRICT_IoGithubNovacryptoBip39WordlistsJapanese
#define INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsJapanese 0
#else
#define INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsJapanese 1
#endif
#undef RESTRICT_IoGithubNovacryptoBip39WordlistsJapanese

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#if !defined (IoGithubNovacryptoBip39WordlistsJapanese_) && (INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsJapanese || defined(INCLUDE_IoGithubNovacryptoBip39WordlistsJapanese))
#define IoGithubNovacryptoBip39WordlistsJapanese_

#define RESTRICT_JavaLangEnum 1
#define INCLUDE_JavaLangEnum 1
#include "java/lang/Enum.h"

#define RESTRICT_IoGithubNovacryptoBip39WordList 1
#define INCLUDE_IoGithubNovacryptoBip39WordList 1
#include "io/github/novacrypto/bip39/WordList.h"

@class IOSObjectArray;

typedef NS_ENUM(NSUInteger, IoGithubNovacryptoBip39WordlistsJapanese_Enum) {
  IoGithubNovacryptoBip39WordlistsJapanese_Enum_INSTANCE = 0,
};

@interface IoGithubNovacryptoBip39WordlistsJapanese : JavaLangEnum < IoGithubNovacryptoBip39WordList >

#pragma mark Public

- (jchar)getSpace;

- (NSString *)getWordWithInt:(jint)index;

+ (IoGithubNovacryptoBip39WordlistsJapanese *)valueOfWithNSString:(NSString *)name;

+ (IOSObjectArray *)values;

@end

J2OBJC_STATIC_INIT(IoGithubNovacryptoBip39WordlistsJapanese)

/*! INTERNAL ONLY - Use enum accessors declared below. */
FOUNDATION_EXPORT IoGithubNovacryptoBip39WordlistsJapanese *IoGithubNovacryptoBip39WordlistsJapanese_values_[];

inline IoGithubNovacryptoBip39WordlistsJapanese *IoGithubNovacryptoBip39WordlistsJapanese_get_INSTANCE(void);
J2OBJC_ENUM_CONSTANT(IoGithubNovacryptoBip39WordlistsJapanese, INSTANCE)

FOUNDATION_EXPORT IOSObjectArray *IoGithubNovacryptoBip39WordlistsJapanese_values(void);

FOUNDATION_EXPORT IoGithubNovacryptoBip39WordlistsJapanese *IoGithubNovacryptoBip39WordlistsJapanese_valueOfWithNSString_(NSString *name);

FOUNDATION_EXPORT IoGithubNovacryptoBip39WordlistsJapanese *IoGithubNovacryptoBip39WordlistsJapanese_fromOrdinal(NSUInteger ordinal);

J2OBJC_TYPE_LITERAL_HEADER(IoGithubNovacryptoBip39WordlistsJapanese)

#endif


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#pragma pop_macro("INCLUDE_ALL_IoGithubNovacryptoBip39WordlistsJapanese")
