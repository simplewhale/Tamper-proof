//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/ECNamedCurveParameterSpec.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec

#if !defined (ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec))
#define ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_

#define RESTRICT_ComYouzhLingtuSignCryptoUtilsECParameterSpec 1
#define INCLUDE_ComYouzhLingtuSignCryptoUtilsECParameterSpec 1
#include "com/youzh/lingtu/sign/crypto/utils/ECParameterSpec.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class OrgSpongycastleMathEcECCurve;
@class OrgSpongycastleMathEcECPoint;

@interface ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec : ComYouzhLingtuSignCryptoUtilsECParameterSpec

#pragma mark Public

- (instancetype)initWithNSString:(NSString *)name
withOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
          withJavaMathBigInteger:(JavaMathBigInteger *)n;

- (instancetype)initWithNSString:(NSString *)name
withOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
          withJavaMathBigInteger:(JavaMathBigInteger *)n
          withJavaMathBigInteger:(JavaMathBigInteger *)h;

- (instancetype)initWithNSString:(NSString *)name
withOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
          withJavaMathBigInteger:(JavaMathBigInteger *)n
          withJavaMathBigInteger:(JavaMathBigInteger *)h
                   withByteArray:(IOSByteArray *)seed;

- (NSString *)getName;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)arg0
                    withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)arg1
                              withJavaMathBigInteger:(JavaMathBigInteger *)arg2 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)arg0
                    withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)arg1
                              withJavaMathBigInteger:(JavaMathBigInteger *)arg2
                              withJavaMathBigInteger:(JavaMathBigInteger *)arg3 NS_UNAVAILABLE;

- (instancetype)initWithOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)arg0
                    withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)arg1
                              withJavaMathBigInteger:(JavaMathBigInteger *)arg2
                              withJavaMathBigInteger:(JavaMathBigInteger *)arg3
                                       withByteArray:(IOSByteArray *)arg4 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec)

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *self, NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *self, NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h);

FOUNDATION_EXPORT void ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *self, NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed);

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec")
