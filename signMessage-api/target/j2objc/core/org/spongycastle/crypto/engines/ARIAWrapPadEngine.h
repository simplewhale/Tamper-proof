//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/ARIAWrapPadEngine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAWrapPadEngine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesARIAWrapPadEngine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAWrapPadEngine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAWrapPadEngine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesARIAWrapPadEngine

#if !defined (OrgSpongycastleCryptoEnginesARIAWrapPadEngine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAWrapPadEngine || defined(INCLUDE_OrgSpongycastleCryptoEnginesARIAWrapPadEngine))
#define OrgSpongycastleCryptoEnginesARIAWrapPadEngine_

#define RESTRICT_OrgSpongycastleCryptoEnginesRFC5649WrapEngine 1
#define INCLUDE_OrgSpongycastleCryptoEnginesRFC5649WrapEngine 1
#include "org/spongycastle/crypto/engines/RFC5649WrapEngine.h"

@protocol OrgSpongycastleCryptoBlockCipher;

@interface OrgSpongycastleCryptoEnginesARIAWrapPadEngine : OrgSpongycastleCryptoEnginesRFC5649WrapEngine

#pragma mark Public

- (instancetype)init;

// Disallowed inherited constructors, do not use.

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEnginesARIAWrapPadEngine)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesARIAWrapPadEngine_init(OrgSpongycastleCryptoEnginesARIAWrapPadEngine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesARIAWrapPadEngine *new_OrgSpongycastleCryptoEnginesARIAWrapPadEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesARIAWrapPadEngine *create_OrgSpongycastleCryptoEnginesARIAWrapPadEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesARIAWrapPadEngine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesARIAWrapPadEngine")