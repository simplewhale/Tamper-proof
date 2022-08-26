//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/SRP6GroupParameters.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsSRP6GroupParameters")
#ifdef RESTRICT_OrgSpongycastleCryptoParamsSRP6GroupParameters
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsSRP6GroupParameters 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoParamsSRP6GroupParameters 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoParamsSRP6GroupParameters

#if !defined (OrgSpongycastleCryptoParamsSRP6GroupParameters_) && (INCLUDE_ALL_OrgSpongycastleCryptoParamsSRP6GroupParameters || defined(INCLUDE_OrgSpongycastleCryptoParamsSRP6GroupParameters))
#define OrgSpongycastleCryptoParamsSRP6GroupParameters_

@class JavaMathBigInteger;

@interface OrgSpongycastleCryptoParamsSRP6GroupParameters : NSObject

#pragma mark Public

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)N
                    withJavaMathBigInteger:(JavaMathBigInteger *)g;

- (JavaMathBigInteger *)getG;

- (JavaMathBigInteger *)getN;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoParamsSRP6GroupParameters)

FOUNDATION_EXPORT void OrgSpongycastleCryptoParamsSRP6GroupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleCryptoParamsSRP6GroupParameters *self, JavaMathBigInteger *N, JavaMathBigInteger *g);

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsSRP6GroupParameters *new_OrgSpongycastleCryptoParamsSRP6GroupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *N, JavaMathBigInteger *g) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoParamsSRP6GroupParameters *create_OrgSpongycastleCryptoParamsSRP6GroupParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *N, JavaMathBigInteger *g);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoParamsSRP6GroupParameters)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoParamsSRP6GroupParameters")
