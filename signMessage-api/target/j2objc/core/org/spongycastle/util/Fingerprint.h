//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/Fingerprint.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleUtilFingerprint")
#ifdef RESTRICT_OrgSpongycastleUtilFingerprint
#define INCLUDE_ALL_OrgSpongycastleUtilFingerprint 0
#else
#define INCLUDE_ALL_OrgSpongycastleUtilFingerprint 1
#endif
#undef RESTRICT_OrgSpongycastleUtilFingerprint

#if !defined (OrgSpongycastleUtilFingerprint_) && (INCLUDE_ALL_OrgSpongycastleUtilFingerprint || defined(INCLUDE_OrgSpongycastleUtilFingerprint))
#define OrgSpongycastleUtilFingerprint_

@class IOSByteArray;

@interface OrgSpongycastleUtilFingerprint : NSObject

#pragma mark Public

- (instancetype)initWithByteArray:(IOSByteArray *)source;

+ (IOSByteArray *)calculateFingerprintWithByteArray:(IOSByteArray *)input;

- (jboolean)isEqual:(id)o;

- (IOSByteArray *)getFingerprint;

- (NSUInteger)hash;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleUtilFingerprint)

FOUNDATION_EXPORT void OrgSpongycastleUtilFingerprint_initWithByteArray_(OrgSpongycastleUtilFingerprint *self, IOSByteArray *source);

FOUNDATION_EXPORT OrgSpongycastleUtilFingerprint *new_OrgSpongycastleUtilFingerprint_initWithByteArray_(IOSByteArray *source) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleUtilFingerprint *create_OrgSpongycastleUtilFingerprint_initWithByteArray_(IOSByteArray *source);

FOUNDATION_EXPORT IOSByteArray *OrgSpongycastleUtilFingerprint_calculateFingerprintWithByteArray_(IOSByteArray *input);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleUtilFingerprint)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleUtilFingerprint")
