//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/commons-codec/org/apache/commons/codec/language/RefinedSoundex.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgApacheCommonsCodecLanguageRefinedSoundex")
#ifdef RESTRICT_OrgApacheCommonsCodecLanguageRefinedSoundex
#define INCLUDE_ALL_OrgApacheCommonsCodecLanguageRefinedSoundex 0
#else
#define INCLUDE_ALL_OrgApacheCommonsCodecLanguageRefinedSoundex 1
#endif
#undef RESTRICT_OrgApacheCommonsCodecLanguageRefinedSoundex

#if !defined (OrgApacheCommonsCodecLanguageRefinedSoundex_) && (INCLUDE_ALL_OrgApacheCommonsCodecLanguageRefinedSoundex || defined(INCLUDE_OrgApacheCommonsCodecLanguageRefinedSoundex))
#define OrgApacheCommonsCodecLanguageRefinedSoundex_

#define RESTRICT_OrgApacheCommonsCodecStringEncoder 1
#define INCLUDE_OrgApacheCommonsCodecStringEncoder 1
#include "org/apache/commons/codec/StringEncoder.h"

@class IOSCharArray;

@interface OrgApacheCommonsCodecLanguageRefinedSoundex : NSObject < OrgApacheCommonsCodecStringEncoder >

#pragma mark Public

- (instancetype)init;

- (instancetype)initWithCharArray:(IOSCharArray *)mapping;

- (instancetype)initWithNSString:(NSString *)mapping;

- (jint)differenceWithNSString:(NSString *)s1
                  withNSString:(NSString *)s2;

- (id)encodeWithId:(id)pObject;

- (NSString *)encodeWithNSString:(NSString *)pString;

- (NSString *)soundexWithNSString:(NSString *)str;

#pragma mark Package-Private

- (jchar)getMappingCodeWithChar:(jchar)c;

@end

J2OBJC_STATIC_INIT(OrgApacheCommonsCodecLanguageRefinedSoundex)

inline NSString *OrgApacheCommonsCodecLanguageRefinedSoundex_get_US_ENGLISH_MAPPING_STRING(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *OrgApacheCommonsCodecLanguageRefinedSoundex_US_ENGLISH_MAPPING_STRING;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgApacheCommonsCodecLanguageRefinedSoundex, US_ENGLISH_MAPPING_STRING, NSString *)

inline OrgApacheCommonsCodecLanguageRefinedSoundex *OrgApacheCommonsCodecLanguageRefinedSoundex_get_US_ENGLISH(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageRefinedSoundex *OrgApacheCommonsCodecLanguageRefinedSoundex_US_ENGLISH;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgApacheCommonsCodecLanguageRefinedSoundex, US_ENGLISH, OrgApacheCommonsCodecLanguageRefinedSoundex *)

FOUNDATION_EXPORT void OrgApacheCommonsCodecLanguageRefinedSoundex_init(OrgApacheCommonsCodecLanguageRefinedSoundex *self);

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageRefinedSoundex *new_OrgApacheCommonsCodecLanguageRefinedSoundex_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageRefinedSoundex *create_OrgApacheCommonsCodecLanguageRefinedSoundex_init(void);

FOUNDATION_EXPORT void OrgApacheCommonsCodecLanguageRefinedSoundex_initWithCharArray_(OrgApacheCommonsCodecLanguageRefinedSoundex *self, IOSCharArray *mapping);

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageRefinedSoundex *new_OrgApacheCommonsCodecLanguageRefinedSoundex_initWithCharArray_(IOSCharArray *mapping) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageRefinedSoundex *create_OrgApacheCommonsCodecLanguageRefinedSoundex_initWithCharArray_(IOSCharArray *mapping);

FOUNDATION_EXPORT void OrgApacheCommonsCodecLanguageRefinedSoundex_initWithNSString_(OrgApacheCommonsCodecLanguageRefinedSoundex *self, NSString *mapping);

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageRefinedSoundex *new_OrgApacheCommonsCodecLanguageRefinedSoundex_initWithNSString_(NSString *mapping) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageRefinedSoundex *create_OrgApacheCommonsCodecLanguageRefinedSoundex_initWithNSString_(NSString *mapping);

J2OBJC_TYPE_LITERAL_HEADER(OrgApacheCommonsCodecLanguageRefinedSoundex)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgApacheCommonsCodecLanguageRefinedSoundex")
