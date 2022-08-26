//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/ECPublicKeySpec.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec

#if !defined (ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec))
#define ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsECKeySpec 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsECKeySpec 1
#include "com/youzh/lingtu/sign/crypto/utils/ECKeySpec.h"

@class ComYouzhLingtuSignCryptoUtilsECParameterSpec;
@class OrgSpongycastleMathEcECPoint;

@interface ComYouzhLingtuSignCryptoUtilsECPublicKeySpec : ComYouzhLingtuSignCryptoUtilsECKeySpec

#pragma mark Public

- (instancetype)initWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)q
    withComYouzhLingtuSignCryptoUtilsECParameterSpec:(ComYouzhLingtuSignCryptoUtilsECParameterSpec *)spec;

- (OrgSpongycastleMathEcECPoint *)getQ;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithComYouzhLingtuSignCryptoUtilsECParameterSpec:(ComYouzhLingtuSignCryptoUtilsECParameterSpec *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsECPublicKeySpec)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_(ComYouzhLingtuSignCryptoUtilsECPublicKeySpec *self, OrgSpongycastleMathEcECPoint *q, ComYouzhLingtuSignCryptoUtilsECParameterSpec *spec);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECPublicKeySpec *new_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_(OrgSpongycastleMathEcECPoint *q, ComYouzhLingtuSignCryptoUtilsECParameterSpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECPublicKeySpec *create_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec_initWithOrgSpongycastleMathEcECPoint_withComYouzhLingtuSignCryptoUtilsECParameterSpec_(OrgSpongycastleMathEcECPoint *q, ComYouzhLingtuSignCryptoUtilsECParameterSpec *spec);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsECPublicKeySpec)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECPublicKeySpec")