//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/macs/DSTU7564Mac.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoMacsDSTU7564Mac")
#ifdef RESTRICT_OrgSpongycastleCryptoMacsDSTU7564Mac
#define INCLUDE_ALL_OrgSpongycastleCryptoMacsDSTU7564Mac 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoMacsDSTU7564Mac 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoMacsDSTU7564Mac

#if !defined (OrgSpongycastleCryptoMacsDSTU7564Mac_) && (INCLUDE_ALL_OrgSpongycastleCryptoMacsDSTU7564Mac || defined(INCLUDE_OrgSpongycastleCryptoMacsDSTU7564Mac))
#define OrgSpongycastleCryptoMacsDSTU7564Mac_

#define RESTRICT_OrgSpongycastleCryptoMac 1
#define INCLUDE_OrgSpongycastleCryptoMac 1
#include "org/spongycastle/crypto/Mac.h"

@class IOSByteArray;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastleCryptoMacsDSTU7564Mac : NSObject < OrgSpongycastleCryptoMac >

#pragma mark Public

- (instancetype)initWithInt:(jint)macBitSize;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getMacSize;

- (void)init__WithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoMacsDSTU7564Mac)

FOUNDATION_EXPORT void OrgSpongycastleCryptoMacsDSTU7564Mac_initWithInt_(OrgSpongycastleCryptoMacsDSTU7564Mac *self, jint macBitSize);

FOUNDATION_EXPORT OrgSpongycastleCryptoMacsDSTU7564Mac *new_OrgSpongycastleCryptoMacsDSTU7564Mac_initWithInt_(jint macBitSize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoMacsDSTU7564Mac *create_OrgSpongycastleCryptoMacsDSTU7564Mac_initWithInt_(jint macBitSize);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoMacsDSTU7564Mac)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoMacsDSTU7564Mac")
