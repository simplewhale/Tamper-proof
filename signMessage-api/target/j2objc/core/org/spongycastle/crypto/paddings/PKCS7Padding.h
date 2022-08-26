//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/paddings/PKCS7Padding.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoPaddingsPKCS7Padding")
#ifdef RESTRICT_OrgSpongycastleCryptoPaddingsPKCS7Padding
#define INCLUDE_ALL_OrgSpongycastleCryptoPaddingsPKCS7Padding 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoPaddingsPKCS7Padding 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoPaddingsPKCS7Padding

#if !defined (OrgSpongycastleCryptoPaddingsPKCS7Padding_) && (INCLUDE_ALL_OrgSpongycastleCryptoPaddingsPKCS7Padding || defined(INCLUDE_OrgSpongycastleCryptoPaddingsPKCS7Padding))
#define OrgSpongycastleCryptoPaddingsPKCS7Padding_

#define RESTRICT_OrgSpongycastleCryptoPaddingsBlockCipherPadding 1
#define INCLUDE_OrgSpongycastleCryptoPaddingsBlockCipherPadding 1
#include "org/spongycastle/crypto/paddings/BlockCipherPadding.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;

@interface OrgSpongycastleCryptoPaddingsPKCS7Padding : NSObject < OrgSpongycastleCryptoPaddingsBlockCipherPadding >

#pragma mark Public

- (instancetype)init;

- (jint)addPaddingWithByteArray:(IOSByteArray *)inArg
                        withInt:(jint)inOff;

- (NSString *)getPaddingName;

- (void)init__WithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

- (jint)padCountWithByteArray:(IOSByteArray *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPaddingsPKCS7Padding)

FOUNDATION_EXPORT void OrgSpongycastleCryptoPaddingsPKCS7Padding_init(OrgSpongycastleCryptoPaddingsPKCS7Padding *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoPaddingsPKCS7Padding *new_OrgSpongycastleCryptoPaddingsPKCS7Padding_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoPaddingsPKCS7Padding *create_OrgSpongycastleCryptoPaddingsPKCS7Padding_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoPaddingsPKCS7Padding)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoPaddingsPKCS7Padding")
