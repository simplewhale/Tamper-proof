//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/Numeric.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsNumeric")
#ifdef RESTRICT_ComYouzhLingtuSignCryptoUtilsNumeric
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsNumeric 0
#else
#define INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsNumeric 1
#endif
#undef RESTRICT_ComYouzhLingtuSignCryptoUtilsNumeric

#if !defined (ComYouzhLingtuSignCryptoUtilsNumeric_) && (INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsNumeric || defined(INCLUDE_ComYouzhLingtuSignCryptoUtilsNumeric))
#define ComYouzhLingtuSignCryptoUtilsNumeric_

@class IOSByteArray;
@class JavaMathBigDecimal;
@class JavaMathBigInteger;

@interface ComYouzhLingtuSignCryptoUtilsNumeric : NSObject

#pragma mark Public

+ (jbyte)asByteWithInt:(jint)m
               withInt:(jint)n;

+ (NSString *)cleanHexPrefixWithNSString:(NSString *)input;

+ (jboolean)containsHexPrefixWithNSString:(NSString *)input;

+ (JavaMathBigInteger *)decodeQuantityWithNSString:(NSString *)value;

+ (NSString *)encodeQuantityWithJavaMathBigInteger:(JavaMathBigInteger *)value;

+ (IOSByteArray *)hexStringToByteArrayWithNSString:(NSString *)input;

+ (jboolean)isIntegerValueWithJavaMathBigDecimal:(JavaMathBigDecimal *)value;

+ (NSString *)prependHexPrefixWithNSString:(NSString *)input;

+ (JavaMathBigInteger *)toBigIntWithByteArray:(IOSByteArray *)value;

+ (JavaMathBigInteger *)toBigIntWithByteArray:(IOSByteArray *)value
                                      withInt:(jint)offset
                                      withInt:(jint)length;

+ (JavaMathBigInteger *)toBigIntWithNSString:(NSString *)hexValue;

+ (JavaMathBigInteger *)toBigIntNoPrefixWithNSString:(NSString *)hexValue;

+ (IOSByteArray *)toBytesPaddedWithJavaMathBigInteger:(JavaMathBigInteger *)value
                                              withInt:(jint)length;

+ (NSString *)toHexStringWithByteArray:(IOSByteArray *)input;

+ (NSString *)toHexStringWithByteArray:(IOSByteArray *)input
                               withInt:(jint)offset
                               withInt:(jint)length
                           withBoolean:(jboolean)withPrefix;

+ (NSString *)toHexStringNoPrefixWithJavaMathBigInteger:(JavaMathBigInteger *)value;

+ (NSString *)toHexStringNoPrefixWithByteArray:(IOSByteArray *)input;

+ (NSString *)toHexStringNoPrefixZeroPaddedWithJavaMathBigInteger:(JavaMathBigInteger *)value
                                                          withInt:(jint)size;

+ (NSString *)toHexStringWithPrefixWithJavaMathBigInteger:(JavaMathBigInteger *)value;

+ (NSString *)toHexStringWithPrefixSafeWithJavaMathBigInteger:(JavaMathBigInteger *)value;

+ (NSString *)toHexStringWithPrefixZeroPaddedWithJavaMathBigInteger:(JavaMathBigInteger *)value
                                                            withInt:(jint)size;

@end

J2OBJC_EMPTY_STATIC_INIT(ComYouzhLingtuSignCryptoUtilsNumeric)

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_encodeQuantityWithJavaMathBigInteger_(JavaMathBigInteger *value);

FOUNDATION_EXPORT JavaMathBigInteger *ComYouzhLingtuSignCryptoUtilsNumeric_decodeQuantityWithNSString_(NSString *value);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_cleanHexPrefixWithNSString_(NSString *input);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_prependHexPrefixWithNSString_(NSString *input);

FOUNDATION_EXPORT jboolean ComYouzhLingtuSignCryptoUtilsNumeric_containsHexPrefixWithNSString_(NSString *input);

FOUNDATION_EXPORT JavaMathBigInteger *ComYouzhLingtuSignCryptoUtilsNumeric_toBigIntWithByteArray_withInt_withInt_(IOSByteArray *value, jint offset, jint length);

FOUNDATION_EXPORT JavaMathBigInteger *ComYouzhLingtuSignCryptoUtilsNumeric_toBigIntWithByteArray_(IOSByteArray *value);

FOUNDATION_EXPORT JavaMathBigInteger *ComYouzhLingtuSignCryptoUtilsNumeric_toBigIntWithNSString_(NSString *hexValue);

FOUNDATION_EXPORT JavaMathBigInteger *ComYouzhLingtuSignCryptoUtilsNumeric_toBigIntNoPrefixWithNSString_(NSString *hexValue);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_toHexStringWithPrefixWithJavaMathBigInteger_(JavaMathBigInteger *value);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_toHexStringNoPrefixWithJavaMathBigInteger_(JavaMathBigInteger *value);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_toHexStringNoPrefixWithByteArray_(IOSByteArray *input);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_toHexStringWithPrefixZeroPaddedWithJavaMathBigInteger_withInt_(JavaMathBigInteger *value, jint size);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_toHexStringWithPrefixSafeWithJavaMathBigInteger_(JavaMathBigInteger *value);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_toHexStringNoPrefixZeroPaddedWithJavaMathBigInteger_withInt_(JavaMathBigInteger *value, jint size);

FOUNDATION_EXPORT IOSByteArray *ComYouzhLingtuSignCryptoUtilsNumeric_toBytesPaddedWithJavaMathBigInteger_withInt_(JavaMathBigInteger *value, jint length);

FOUNDATION_EXPORT IOSByteArray *ComYouzhLingtuSignCryptoUtilsNumeric_hexStringToByteArrayWithNSString_(NSString *input);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_toHexStringWithByteArray_withInt_withInt_withBoolean_(IOSByteArray *input, jint offset, jint length, jboolean withPrefix);

FOUNDATION_EXPORT NSString *ComYouzhLingtuSignCryptoUtilsNumeric_toHexStringWithByteArray_(IOSByteArray *input);

FOUNDATION_EXPORT jbyte ComYouzhLingtuSignCryptoUtilsNumeric_asByteWithInt_withInt_(jint m, jint n);

FOUNDATION_EXPORT jboolean ComYouzhLingtuSignCryptoUtilsNumeric_isIntegerValueWithJavaMathBigDecimal_(JavaMathBigDecimal *value);

J2OBJC_TYPE_LITERAL_HEADER(ComYouzhLingtuSignCryptoUtilsNumeric)

#endif

#pragma pop_macro("INCLUDE_ALL_ComYouzhLingtuSignCryptoUtilsNumeric")
