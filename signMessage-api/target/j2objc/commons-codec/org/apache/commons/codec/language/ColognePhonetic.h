//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/commons-codec/org/apache/commons/codec/language/ColognePhonetic.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgApacheCommonsCodecLanguageColognePhonetic")
#ifdef RESTRICT_OrgApacheCommonsCodecLanguageColognePhonetic
#define INCLUDE_ALL_OrgApacheCommonsCodecLanguageColognePhonetic 0
#else
#define INCLUDE_ALL_OrgApacheCommonsCodecLanguageColognePhonetic 1
#endif
#undef RESTRICT_OrgApacheCommonsCodecLanguageColognePhonetic

#if !defined (OrgApacheCommonsCodecLanguageColognePhonetic_) && (INCLUDE_ALL_OrgApacheCommonsCodecLanguageColognePhonetic || defined(INCLUDE_OrgApacheCommonsCodecLanguageColognePhonetic))
#define OrgApacheCommonsCodecLanguageColognePhonetic_

#define RESTRICT_OrgApacheCommonsCodecStringEncoder 1
#define INCLUDE_OrgApacheCommonsCodecStringEncoder 1
#include "org/apache/commons/codec/StringEncoder.h"

@interface OrgApacheCommonsCodecLanguageColognePhonetic : NSObject < OrgApacheCommonsCodecStringEncoder >

#pragma mark Public

- (instancetype)init;

- (NSString *)colognePhoneticWithNSString:(NSString *)text;

- (id)encodeWithId:(id)object;

- (NSString *)encodeWithNSString:(NSString *)text;

- (jboolean)isEncodeEqualWithNSString:(NSString *)text1
                         withNSString:(NSString *)text2;

@end

J2OBJC_STATIC_INIT(OrgApacheCommonsCodecLanguageColognePhonetic)

FOUNDATION_EXPORT void OrgApacheCommonsCodecLanguageColognePhonetic_init(OrgApacheCommonsCodecLanguageColognePhonetic *self);

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageColognePhonetic *new_OrgApacheCommonsCodecLanguageColognePhonetic_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageColognePhonetic *create_OrgApacheCommonsCodecLanguageColognePhonetic_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgApacheCommonsCodecLanguageColognePhonetic)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgApacheCommonsCodecLanguageColognePhonetic")
