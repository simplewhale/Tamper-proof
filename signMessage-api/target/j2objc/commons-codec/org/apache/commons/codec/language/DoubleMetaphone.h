//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/commons-codec/org/apache/commons/codec/language/DoubleMetaphone.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgApacheCommonsCodecLanguageDoubleMetaphone")
#ifdef RESTRICT_OrgApacheCommonsCodecLanguageDoubleMetaphone
#define INCLUDE_ALL_OrgApacheCommonsCodecLanguageDoubleMetaphone 0
#else
#define INCLUDE_ALL_OrgApacheCommonsCodecLanguageDoubleMetaphone 1
#endif
#undef RESTRICT_OrgApacheCommonsCodecLanguageDoubleMetaphone

#if !defined (OrgApacheCommonsCodecLanguageDoubleMetaphone_) && (INCLUDE_ALL_OrgApacheCommonsCodecLanguageDoubleMetaphone || defined(INCLUDE_OrgApacheCommonsCodecLanguageDoubleMetaphone))
#define OrgApacheCommonsCodecLanguageDoubleMetaphone_

#define RESTRICT_OrgApacheCommonsCodecStringEncoder 1
#define INCLUDE_OrgApacheCommonsCodecStringEncoder 1
#include "org/apache/commons/codec/StringEncoder.h"

@class IOSObjectArray;

@interface OrgApacheCommonsCodecLanguageDoubleMetaphone : NSObject < OrgApacheCommonsCodecStringEncoder >

#pragma mark Public

- (instancetype)init;

- (NSString *)doubleMetaphoneWithNSString:(NSString *)value;

- (NSString *)doubleMetaphoneWithNSString:(NSString *)value
                              withBoolean:(jboolean)alternate;

- (id)encodeWithId:(id)obj;

- (NSString *)encodeWithNSString:(NSString *)value;

- (jint)getMaxCodeLen;

- (jboolean)isDoubleMetaphoneEqualWithNSString:(NSString *)value1
                                  withNSString:(NSString *)value2;

- (jboolean)isDoubleMetaphoneEqualWithNSString:(NSString *)value1
                                  withNSString:(NSString *)value2
                                   withBoolean:(jboolean)alternate;

- (void)setMaxCodeLenWithInt:(jint)maxCodeLen;

#pragma mark Protected

- (jchar)charAtWithNSString:(NSString *)value
                    withInt:(jint)index;

+ (jboolean)containsWithNSString:(NSString *)value
                         withInt:(jint)start
                         withInt:(jint)length
               withNSStringArray:(IOSObjectArray *)criteria;

@end

J2OBJC_STATIC_INIT(OrgApacheCommonsCodecLanguageDoubleMetaphone)

FOUNDATION_EXPORT void OrgApacheCommonsCodecLanguageDoubleMetaphone_init(OrgApacheCommonsCodecLanguageDoubleMetaphone *self);

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageDoubleMetaphone *new_OrgApacheCommonsCodecLanguageDoubleMetaphone_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageDoubleMetaphone *create_OrgApacheCommonsCodecLanguageDoubleMetaphone_init(void);

FOUNDATION_EXPORT jboolean OrgApacheCommonsCodecLanguageDoubleMetaphone_containsWithNSString_withInt_withInt_withNSStringArray_(NSString *value, jint start, jint length, IOSObjectArray *criteria);

J2OBJC_TYPE_LITERAL_HEADER(OrgApacheCommonsCodecLanguageDoubleMetaphone)

#endif

#if !defined (OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult_) && (INCLUDE_ALL_OrgApacheCommonsCodecLanguageDoubleMetaphone || defined(INCLUDE_OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult))
#define OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult_

@class OrgApacheCommonsCodecLanguageDoubleMetaphone;

@interface OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult : NSObject

#pragma mark Public

- (instancetype)initWithOrgApacheCommonsCodecLanguageDoubleMetaphone:(OrgApacheCommonsCodecLanguageDoubleMetaphone *)outer$
                                                             withInt:(jint)maxLength;

- (void)appendWithChar:(jchar)value;

- (void)appendWithChar:(jchar)primary
              withChar:(jchar)alternate;

- (void)appendWithNSString:(NSString *)value;

- (void)appendWithNSString:(NSString *)primary
              withNSString:(NSString *)alternate;

- (void)appendAlternateWithChar:(jchar)value;

- (void)appendAlternateWithNSString:(NSString *)value;

- (void)appendPrimaryWithChar:(jchar)value;

- (void)appendPrimaryWithNSString:(NSString *)value;

- (NSString *)getAlternate;

- (NSString *)getPrimary;

- (jboolean)isComplete;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult)

FOUNDATION_EXPORT void OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult_initWithOrgApacheCommonsCodecLanguageDoubleMetaphone_withInt_(OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult *self, OrgApacheCommonsCodecLanguageDoubleMetaphone *outer$, jint maxLength);

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult *new_OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult_initWithOrgApacheCommonsCodecLanguageDoubleMetaphone_withInt_(OrgApacheCommonsCodecLanguageDoubleMetaphone *outer$, jint maxLength) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult *create_OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult_initWithOrgApacheCommonsCodecLanguageDoubleMetaphone_withInt_(OrgApacheCommonsCodecLanguageDoubleMetaphone *outer$, jint maxLength);

J2OBJC_TYPE_LITERAL_HEADER(OrgApacheCommonsCodecLanguageDoubleMetaphone_DoubleMetaphoneResult)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgApacheCommonsCodecLanguageDoubleMetaphone")
