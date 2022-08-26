//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/macs/OldHMac.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoMacsOldHMac")
#ifdef RESTRICT_OrgSpongycastleCryptoMacsOldHMac
#define INCLUDE_ALL_OrgSpongycastleCryptoMacsOldHMac 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoMacsOldHMac 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoMacsOldHMac

#if !defined (OrgSpongycastleCryptoMacsOldHMac_) && (INCLUDE_ALL_OrgSpongycastleCryptoMacsOldHMac || defined(INCLUDE_OrgSpongycastleCryptoMacsOldHMac))
#define OrgSpongycastleCryptoMacsOldHMac_

#define RESTRICT_OrgSpongycastleCryptoMac 1
#define INCLUDE_OrgSpongycastleCryptoMac 1
#include "org/spongycastle/crypto/Mac.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;
@protocol OrgSpongycastleCryptoDigest;

@interface OrgSpongycastleCryptoMacsOldHMac : NSObject < OrgSpongycastleCryptoMac >

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getMacSize;

- (id<OrgSpongycastleCryptoDigest>)getUnderlyingDigest;

- (void)init__WithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoMacsOldHMac)

FOUNDATION_EXPORT void OrgSpongycastleCryptoMacsOldHMac_initWithOrgSpongycastleCryptoDigest_(OrgSpongycastleCryptoMacsOldHMac *self, id<OrgSpongycastleCryptoDigest> digest);

FOUNDATION_EXPORT OrgSpongycastleCryptoMacsOldHMac *new_OrgSpongycastleCryptoMacsOldHMac_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoMacsOldHMac *create_OrgSpongycastleCryptoMacsOldHMac_initWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoMacsOldHMac)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoMacsOldHMac")
