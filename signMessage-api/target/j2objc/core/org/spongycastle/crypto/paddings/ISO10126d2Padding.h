//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/paddings/ISO10126d2Padding.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoPaddingsISO10126d2Padding")
#ifdef RESTRICT_OrgSpongycastleCryptoPaddingsISO10126d2Padding
#define INCLUDE_ALL_OrgSpongycastleCryptoPaddingsISO10126d2Padding 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoPaddingsISO10126d2Padding 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoPaddingsISO10126d2Padding

#if !defined (OrgSpongycastleCryptoPaddingsISO10126d2Padding_) && (INCLUDE_ALL_OrgSpongycastleCryptoPaddingsISO10126d2Padding || defined(INCLUDE_OrgSpongycastleCryptoPaddingsISO10126d2Padding))
#define OrgSpongycastleCryptoPaddingsISO10126d2Padding_

#define RESTRICT_OrgSpongycastleCryptoPaddingsBlockCipherPadding 1
#define INCLUDE_OrgSpongycastleCryptoPaddingsBlockCipherPadding 1
#include "org/spongycastle/crypto/paddings/BlockCipherPadding.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;

@interface OrgSpongycastleCryptoPaddingsISO10126d2Padding : NSObject < OrgSpongycastleCryptoPaddingsBlockCipherPadding > {
 @public
  JavaSecuritySecureRandom *random_;
}

#pragma mark Public

- (instancetype)init;

- (jint)addPaddingWithByteArray:(IOSByteArray *)inArg
                        withInt:(jint)inOff;

- (NSString *)getPaddingName;

- (void)init__WithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

- (jint)padCountWithByteArray:(IOSByteArray *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoPaddingsISO10126d2Padding)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoPaddingsISO10126d2Padding, random_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoPaddingsISO10126d2Padding_init(OrgSpongycastleCryptoPaddingsISO10126d2Padding *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoPaddingsISO10126d2Padding *new_OrgSpongycastleCryptoPaddingsISO10126d2Padding_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoPaddingsISO10126d2Padding *create_OrgSpongycastleCryptoPaddingsISO10126d2Padding_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoPaddingsISO10126d2Padding)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoPaddingsISO10126d2Padding")
