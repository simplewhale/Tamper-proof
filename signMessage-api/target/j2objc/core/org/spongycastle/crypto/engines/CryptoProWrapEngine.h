//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/CryptoProWrapEngine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesCryptoProWrapEngine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesCryptoProWrapEngine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesCryptoProWrapEngine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesCryptoProWrapEngine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesCryptoProWrapEngine

#if !defined (OrgSpongycastleCryptoEnginesCryptoProWrapEngine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesCryptoProWrapEngine || defined(INCLUDE_OrgSpongycastleCryptoEnginesCryptoProWrapEngine))
#define OrgSpongycastleCryptoEnginesCryptoProWrapEngine_

#define RESTRICT_OrgSpongycastleCryptoEnginesGOST28147WrapEngine 1
#define INCLUDE_OrgSpongycastleCryptoEnginesGOST28147WrapEngine 1
#include "org/spongycastle/crypto/engines/GOST28147WrapEngine.h"

@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoEnginesCryptoProWrapEngine : OrgSpongycastleCryptoEnginesGOST28147WrapEngine

#pragma mark Public

- (instancetype)init;

- (void)init__WithBoolean:(jboolean)forWrapping
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoEnginesCryptoProWrapEngine)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesCryptoProWrapEngine_init(OrgSpongycastleCryptoEnginesCryptoProWrapEngine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesCryptoProWrapEngine *new_OrgSpongycastleCryptoEnginesCryptoProWrapEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesCryptoProWrapEngine *create_OrgSpongycastleCryptoEnginesCryptoProWrapEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesCryptoProWrapEngine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesCryptoProWrapEngine")
