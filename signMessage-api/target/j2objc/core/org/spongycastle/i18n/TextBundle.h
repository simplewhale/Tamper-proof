//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/i18n/TextBundle.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleI18nTextBundle")
#ifdef RESTRICT_OrgSpongycastleI18nTextBundle
#define INCLUDE_ALL_OrgSpongycastleI18nTextBundle 0
#else
#define INCLUDE_ALL_OrgSpongycastleI18nTextBundle 1
#endif
#undef RESTRICT_OrgSpongycastleI18nTextBundle

#if !defined (OrgSpongycastleI18nTextBundle_) && (INCLUDE_ALL_OrgSpongycastleI18nTextBundle || defined(INCLUDE_OrgSpongycastleI18nTextBundle))
#define OrgSpongycastleI18nTextBundle_

#define RESTRICT_OrgSpongycastleI18nLocalizedMessage 1
#define INCLUDE_OrgSpongycastleI18nLocalizedMessage 1
#include "org/spongycastle/i18n/LocalizedMessage.h"

@class IOSObjectArray;
@class JavaUtilLocale;
@class JavaUtilTimeZone;

@interface OrgSpongycastleI18nTextBundle : OrgSpongycastleI18nLocalizedMessage

#pragma mark Public

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_;

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
               withNSObjectArray:(IOSObjectArray *)arguments;

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
                    withNSString:(NSString *)encoding;

- (instancetype)initWithNSString:(NSString *)resource
                    withNSString:(NSString *)id_
                    withNSString:(NSString *)encoding
               withNSObjectArray:(IOSObjectArray *)arguments;

- (NSString *)getTextWithJavaUtilLocale:(JavaUtilLocale *)loc;

- (NSString *)getTextWithJavaUtilLocale:(JavaUtilLocale *)loc
                   withJavaUtilTimeZone:(JavaUtilTimeZone *)timezone;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleI18nTextBundle)

inline NSString *OrgSpongycastleI18nTextBundle_get_TEXT_ENTRY(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *OrgSpongycastleI18nTextBundle_TEXT_ENTRY;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleI18nTextBundle, TEXT_ENTRY, NSString *)

FOUNDATION_EXPORT void OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_(OrgSpongycastleI18nTextBundle *self, NSString *resource, NSString *id_);

FOUNDATION_EXPORT OrgSpongycastleI18nTextBundle *new_OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_(NSString *resource, NSString *id_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleI18nTextBundle *create_OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_(NSString *resource, NSString *id_);

FOUNDATION_EXPORT void OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSString_(OrgSpongycastleI18nTextBundle *self, NSString *resource, NSString *id_, NSString *encoding);

FOUNDATION_EXPORT OrgSpongycastleI18nTextBundle *new_OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleI18nTextBundle *create_OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSString_(NSString *resource, NSString *id_, NSString *encoding);

FOUNDATION_EXPORT void OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSObjectArray_(OrgSpongycastleI18nTextBundle *self, NSString *resource, NSString *id_, IOSObjectArray *arguments);

FOUNDATION_EXPORT OrgSpongycastleI18nTextBundle *new_OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, IOSObjectArray *arguments) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleI18nTextBundle *create_OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, IOSObjectArray *arguments);

FOUNDATION_EXPORT void OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(OrgSpongycastleI18nTextBundle *self, NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments);

FOUNDATION_EXPORT OrgSpongycastleI18nTextBundle *new_OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleI18nTextBundle *create_OrgSpongycastleI18nTextBundle_initWithNSString_withNSString_withNSString_withNSObjectArray_(NSString *resource, NSString *id_, NSString *encoding, IOSObjectArray *arguments);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleI18nTextBundle)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleI18nTextBundle")
