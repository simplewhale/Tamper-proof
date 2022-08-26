//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/test/TestRandomBigInteger.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleUtilTestTestRandomBigInteger")
#ifdef RESTRICT_OrgSpongycastleUtilTestTestRandomBigInteger
#define INCLUDE_ALL_OrgSpongycastleUtilTestTestRandomBigInteger 0
#else
#define INCLUDE_ALL_OrgSpongycastleUtilTestTestRandomBigInteger 1
#endif
#undef RESTRICT_OrgSpongycastleUtilTestTestRandomBigInteger

#if !defined (OrgSpongycastleUtilTestTestRandomBigInteger_) && (INCLUDE_ALL_OrgSpongycastleUtilTestTestRandomBigInteger || defined(INCLUDE_OrgSpongycastleUtilTestTestRandomBigInteger))
#define OrgSpongycastleUtilTestTestRandomBigInteger_

#define RESTRICT_OrgSpongycastleUtilTestFixedSecureRandom 1
#define INCLUDE_OrgSpongycastleUtilTestFixedSecureRandom 1
#include "org/spongycastle/util/test/FixedSecureRandom.h"

@class IOSByteArray;
@class IOSObjectArray;

@interface OrgSpongycastleUtilTestTestRandomBigInteger : OrgSpongycastleUtilTestFixedSecureRandom

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)encoding;

- (instancetype)initWithInt:(jint)bitLength
              withByteArray:(IOSByteArray *)encoding;

- (instancetype)initWithNSString:(NSString *)encoding;

- (instancetype)initWithNSString:(NSString *)encoding
                         withInt:(jint)radix;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithByteArray2:(IOSObjectArray *)arg0 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleUtilTestFixedSecureRandom_SourceArray:(IOSObjectArray *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleUtilTestTestRandomBigInteger)

FOUNDATION_EXPORT void OrgSpongycastleUtilTestTestRandomBigInteger_initWithNSString_(OrgSpongycastleUtilTestTestRandomBigInteger *self, NSString *encoding);

FOUNDATION_EXPORT OrgSpongycastleUtilTestTestRandomBigInteger *new_OrgSpongycastleUtilTestTestRandomBigInteger_initWithNSString_(NSString *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleUtilTestTestRandomBigInteger *create_OrgSpongycastleUtilTestTestRandomBigInteger_initWithNSString_(NSString *encoding);

FOUNDATION_EXPORT void OrgSpongycastleUtilTestTestRandomBigInteger_initWithNSString_withInt_(OrgSpongycastleUtilTestTestRandomBigInteger *self, NSString *encoding, jint radix);

FOUNDATION_EXPORT OrgSpongycastleUtilTestTestRandomBigInteger *new_OrgSpongycastleUtilTestTestRandomBigInteger_initWithNSString_withInt_(NSString *encoding, jint radix) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleUtilTestTestRandomBigInteger *create_OrgSpongycastleUtilTestTestRandomBigInteger_initWithNSString_withInt_(NSString *encoding, jint radix);

FOUNDATION_EXPORT void OrgSpongycastleUtilTestTestRandomBigInteger_initWithByteArray_(OrgSpongycastleUtilTestTestRandomBigInteger *self, IOSByteArray *encoding);

FOUNDATION_EXPORT OrgSpongycastleUtilTestTestRandomBigInteger *new_OrgSpongycastleUtilTestTestRandomBigInteger_initWithByteArray_(IOSByteArray *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleUtilTestTestRandomBigInteger *create_OrgSpongycastleUtilTestTestRandomBigInteger_initWithByteArray_(IOSByteArray *encoding);

FOUNDATION_EXPORT void OrgSpongycastleUtilTestTestRandomBigInteger_initWithInt_withByteArray_(OrgSpongycastleUtilTestTestRandomBigInteger *self, jint bitLength, IOSByteArray *encoding);

FOUNDATION_EXPORT OrgSpongycastleUtilTestTestRandomBigInteger *new_OrgSpongycastleUtilTestTestRandomBigInteger_initWithInt_withByteArray_(jint bitLength, IOSByteArray *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleUtilTestTestRandomBigInteger *create_OrgSpongycastleUtilTestTestRandomBigInteger_initWithInt_withByteArray_(jint bitLength, IOSByteArray *encoding);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleUtilTestTestRandomBigInteger)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleUtilTestTestRandomBigInteger")
