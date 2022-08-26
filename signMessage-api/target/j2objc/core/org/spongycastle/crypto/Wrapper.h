//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/Wrapper.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoWrapper")
#ifdef RESTRICT_OrgSpongycastleCryptoWrapper
#define INCLUDE_ALL_OrgSpongycastleCryptoWrapper 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoWrapper 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoWrapper

#if !defined (OrgSpongycastleCryptoWrapper_) && (INCLUDE_ALL_OrgSpongycastleCryptoWrapper || defined(INCLUDE_OrgSpongycastleCryptoWrapper))
#define OrgSpongycastleCryptoWrapper_

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;

@protocol OrgSpongycastleCryptoWrapper < JavaObject >

- (void)init__WithBoolean:(jboolean)forWrapping
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (NSString *)getAlgorithmName;

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                            withInt:(jint)inLen;

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)inArg
                              withInt:(jint)inOff
                              withInt:(jint)inLen;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoWrapper)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoWrapper)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoWrapper")
