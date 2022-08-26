//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/GOST28147ParameterSpec.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec

#if !defined (ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec))
#define ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_

#define RESTRICT_JavaSecuritySpecAlgorithmParameterSpec 1
#define INCLUDE_JavaSecuritySpecAlgorithmParameterSpec 1
#include "java/security/spec/AlgorithmParameterSpec.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1ObjectIdentifier;

@interface ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1ASN1ObjectIdentifier:(OrgSpongycastleAsn1ASN1ObjectIdentifier *)sBoxName
                                                  withByteArray:(IOSByteArray *)iv;

- (instancetype)initWithByteArray:(IOSByteArray *)sBox;

- (instancetype)initWithByteArray:(IOSByteArray *)sBox
                    withByteArray:(IOSByteArray *)iv;

- (instancetype)initWithNSString:(NSString *)sBoxName;

- (instancetype)initWithNSString:(NSString *)sBoxName
                   withByteArray:(IOSByteArray *)iv;

- (IOSByteArray *)getIV;

- (IOSByteArray *)getSbox;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, IOSByteArray *sBox);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_(IOSByteArray *sBox) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_(IOSByteArray *sBox);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_withByteArray_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, IOSByteArray *sBox, IOSByteArray *iv);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_withByteArray_(IOSByteArray *sBox, IOSByteArray *iv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithByteArray_withByteArray_(IOSByteArray *sBox, IOSByteArray *iv);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, NSString *sBoxName);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(NSString *sBoxName) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_(NSString *sBoxName);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_withByteArray_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, NSString *sBoxName, IOSByteArray *iv);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_withByteArray_(NSString *sBoxName, IOSByteArray *iv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithNSString_withByteArray_(NSString *sBoxName, IOSByteArray *iv);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *self, OrgSpongycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *new_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec *create_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withByteArray_(OrgSpongycastleAsn1ASN1ObjectIdentifier *sBoxName, IOSByteArray *iv);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsGOST28147ParameterSpec")
