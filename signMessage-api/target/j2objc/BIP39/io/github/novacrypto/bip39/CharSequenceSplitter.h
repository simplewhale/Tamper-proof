//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/BIP39/io/github/novacrypto/bip39/CharSequenceSplitter.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_IoGithubNovacryptoBip39CharSequenceSplitter")
#ifdef RESTRICT_IoGithubNovacryptoBip39CharSequenceSplitter
#define INCLUDE_ALL_IoGithubNovacryptoBip39CharSequenceSplitter 0
#else
#define INCLUDE_ALL_IoGithubNovacryptoBip39CharSequenceSplitter 1
#endif
#undef RESTRICT_IoGithubNovacryptoBip39CharSequenceSplitter

#if !defined (IoGithubNovacryptoBip39CharSequenceSplitter_) && (INCLUDE_ALL_IoGithubNovacryptoBip39CharSequenceSplitter || defined(INCLUDE_IoGithubNovacryptoBip39CharSequenceSplitter))
#define IoGithubNovacryptoBip39CharSequenceSplitter_

@protocol JavaLangCharSequence;
@protocol JavaUtilList;

@interface IoGithubNovacryptoBip39CharSequenceSplitter : NSObject

#pragma mark Package-Private

- (instancetype)initWithChar:(jchar)separator1
                    withChar:(jchar)separator2;

- (id<JavaUtilList>)splitWithJavaLangCharSequence:(id<JavaLangCharSequence>)charSequence;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(IoGithubNovacryptoBip39CharSequenceSplitter)

FOUNDATION_EXPORT void IoGithubNovacryptoBip39CharSequenceSplitter_initWithChar_withChar_(IoGithubNovacryptoBip39CharSequenceSplitter *self, jchar separator1, jchar separator2);

FOUNDATION_EXPORT IoGithubNovacryptoBip39CharSequenceSplitter *new_IoGithubNovacryptoBip39CharSequenceSplitter_initWithChar_withChar_(jchar separator1, jchar separator2) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT IoGithubNovacryptoBip39CharSequenceSplitter *create_IoGithubNovacryptoBip39CharSequenceSplitter_initWithChar_withChar_(jchar separator1, jchar separator2);

J2OBJC_TYPE_LITERAL_HEADER(IoGithubNovacryptoBip39CharSequenceSplitter)

#endif

#pragma pop_macro("INCLUDE_ALL_IoGithubNovacryptoBip39CharSequenceSplitter")