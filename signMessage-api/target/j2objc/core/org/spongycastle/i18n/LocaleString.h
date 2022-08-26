//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/i18n/LocaleString.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleI18nLocaleString")
#ifdef RESTRICT_OrgSpongycastleI18nLocaleString
#define INCLUDE_ALL_OrgSpongycastleI18nLocaleString 0
#else
#define INCLUDE_ALL_OrgSpongycastleI18nLocaleString 1
#endif
#undef RESTRICT_OrgSpongycastleI18nLocaleString

#if !defined (OrgSpongycastleI18nLocaleString_) && (INCLUDE_ALL_OrgSpongycastleI18nLocaleString || defined(INCLUDE_OrgSpongycastleI18nLocaleString))
#define OrgSpongycastleI18nLocaleString_

#define RESTRICT_OrgSpongycastleI18nLocalizedMessage 1
#define INCLUDE_OrgSpongycastleI18nLocalizedMessage 1
#include "org/spongycastle/i18n/LocalizedMessage.h"

@class IOSObjectArray;
@class JavaUtilLocale;

@interface OrgSpongycastleI18nLocaleString : OrgSpongycastleI18nLocalizedMessage

#pragma mark Public

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_;

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
                    withNSString:(NSString *)encoding;

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
                    withNSString:(NSString *)encoding
               withNSObjectArray:(IOSObjectArray *)arguments;

- (NSString *)getLocaleStringWithJavaUtilLocale:(JavaUtilLocale *)locale;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithNSString:(NSString *)arg0
                    withNSString:(NSString *)arg1
               withNSObjectArray:(IOSObjectArray *)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleI18nLocaleString)

FOUNDATION_EXPORT void OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_(OrgSpongycastleI18nLocaleString *self, NSString *resource, NSString *id_);

FOUNDATION_EXPORT OrgSpongycastleI18nLocaleString *new_OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_(NSString *resource, NSString *id_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleI18nLocaleString *create_OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_(NSString *resource, NSString *id_);

FOUNDATION_EXPORT void OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_withNSString_(OrgSpongycastleI18nLocaleString *self, NSString *resource, NSString *id_, NSString *encoding);

FOUNDATION_EXPORT OrgSpongycastleI18nLocaleString *new_OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleI18nLocaleString *create_OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding);

FOUNDATION_EXPORT void OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_withNSString_withNSObjectArray_(OrgSpongycastleI18nLocaleString *self, NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments);

FOUNDATION_EXPORT OrgSpongycastleI18nLocaleString *new_OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleI18nLocaleString *create_OrgSpongycastleI18nLocaleString_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleI18nLocaleString)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleI18nLocaleString")
