//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/ECParameterSpec.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECParameterSpec")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsECParameterSpec
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECParameterSpec 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECParameterSpec 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsECParameterSpec

#if !defined (ComYouzhLingtuSignCryptoUtilsECParameterSpec_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECParameterSpec || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsECParameterSpec))
#define ComYouzhLingtuSignCryptoUtilsECParameterSpec_

#define RESTRICT_JavaSecuritySpecAlgorithmParameterSpec 1
#define INCLUDE_JavaSecuritySpecAlgorithmParameterSpec 1
#include "java/security/spec/AlgorithmParameterSpec.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class OrgSpongycastleMathEcECCurve;
@class OrgSpongycastleMathEcECPoint;

@interface ComYouzhLingtuSignCryptoUtilsECParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
                    withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
                              withJavaMathBigInteger:(JavaMathBigInteger *)n;

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
                    withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
                              withJavaMathBigInteger:(JavaMathBigInteger *)n
                              withJavaMathBigInteger:(JavaMathBigInteger *)h;

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
                    withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
                              withJavaMathBigInteger:(JavaMathBigInteger *)n
                              withJavaMathBigInteger:(JavaMathBigInteger *)h
                                       withByteArray:(IOSByteArray *)seed;

- (jboolean)isEqual:(id)o;

- (OrgSpongycastleMathEcECCurve *)getCurve;

- (OrgSpongycastleMathEcECPoint *)getG;

- (JavaMathBigInteger *)getH;

- (JavaMathBigInteger *)getN;

- (IOSByteArray *)getSeed;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsECParameterSpec)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(ComYouzhLingtuSignCryptoUtilsECParameterSpec *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(ComYouzhLingtuSignCryptoUtilsECParameterSpec *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(ComYouzhLingtuSignCryptoUtilsECParameterSpec *self, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsECParameterSpec)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECParameterSpec")