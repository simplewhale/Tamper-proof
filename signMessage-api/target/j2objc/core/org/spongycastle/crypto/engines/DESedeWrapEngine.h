//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/engines/DESedeWrapEngine.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesDESedeWrapEngine")
#ifdef RESTRICT_OrgSpongycastleCryptoEnginesDESedeWrapEngine
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesDESedeWrapEngine 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoEnginesDESedeWrapEngine 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoEnginesDESedeWrapEngine

#if !defined (OrgSpongycastleCryptoEnginesDESedeWrapEngine_) && (INCLUDE_ALL_OrgSpongycastleCryptoEnginesDESedeWrapEngine || defined(INCLUDE_OrgSpongycastleCryptoEnginesDESedeWrapEngine))
#define OrgSpongycastleCryptoEnginesDESedeWrapEngine_

#define RESTRICT_OrgSpongycastleCryptoWrapper 1
#define INCLUDE_OrgSpongycastleCryptoWrapper 1
#include "org/spongycastle/crypto/Wrapper.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;
@protocol OrgSpongycastleCryptoDigest;

@interface OrgSpongycastleCryptoEnginesDESedeWrapEngine : NSObject < OrgSpongycastleCryptoWrapper > {
 @public
  id<OrgSpongycastleCryptoDigest> sha1_;
  IOSByteArray *digest_;
}

#pragma mark Public

- (instancetype)init;

- (NSString *)getAlgorithmName;

- (void)init__WithBoolean:(jboolean)forWrapping
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)inArg
                              withInt:(jint)inOff
                              withInt:(jint)inLen;

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                            withInt:(jint)inLen;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoEnginesDESedeWrapEngine)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeWrapEngine, sha1_, id<OrgSpongycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoEnginesDESedeWrapEngine, digest_, IOSByteArray *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoEnginesDESedeWrapEngine_init(OrgSpongycastleCryptoEnginesDESedeWrapEngine *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesDESedeWrapEngine *new_OrgSpongycastleCryptoEnginesDESedeWrapEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoEnginesDESedeWrapEngine *create_OrgSpongycastleCryptoEnginesDESedeWrapEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoEnginesDESedeWrapEngine)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoEnginesDESedeWrapEngine")