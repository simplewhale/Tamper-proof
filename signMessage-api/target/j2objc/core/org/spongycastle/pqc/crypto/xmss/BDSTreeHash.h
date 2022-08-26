//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/BDSTreeHash.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssBDSTreeHash")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoXmssBDSTreeHash
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssBDSTreeHash 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssBDSTreeHash 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoXmssBDSTreeHash

#if !defined (OrgSpongycastlePqcCryptoXmssBDSTreeHash_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssBDSTreeHash || defined(INCLUDE_OrgSpongycastlePqcCryptoXmssBDSTreeHash))
#define OrgSpongycastlePqcCryptoXmssBDSTreeHash_

#define RESTRICT_JavaIoSerializable 1
#define INCLUDE_JavaIoSerializable 1
#include "java/io/Serializable.h"

@class IOSByteArray;
@class JavaUtilStack;
@class OrgSpongycastlePqcCryptoXmssOTSHashAddress;
@class OrgSpongycastlePqcCryptoXmssWOTSPlus;
@class OrgSpongycastlePqcCryptoXmssXMSSNode;

@interface OrgSpongycastlePqcCryptoXmssBDSTreeHash : NSObject < JavaIoSerializable >

#pragma mark Public

- (OrgSpongycastlePqcCryptoXmssXMSSNode *)getTailNode;

#pragma mark Package-Private

- (instancetype)initWithInt:(jint)initialHeight;

- (jint)getHeight;

- (jint)getIndexLeaf;

- (void)initialize__WithInt:(jint)nextIndex OBJC_METHOD_FAMILY_NONE;

- (jboolean)isFinished;

- (jboolean)isInitialized;

- (void)setNodeWithOrgSpongycastlePqcCryptoXmssXMSSNode:(OrgSpongycastlePqcCryptoXmssXMSSNode *)node;

- (void)updateWithJavaUtilStack:(JavaUtilStack *)stack
withOrgSpongycastlePqcCryptoXmssWOTSPlus:(OrgSpongycastlePqcCryptoXmssWOTSPlus *)wotsPlus
                  withByteArray:(IOSByteArray *)publicSeed
                  withByteArray:(IOSByteArray *)secretSeed
withOrgSpongycastlePqcCryptoXmssOTSHashAddress:(OrgSpongycastlePqcCryptoXmssOTSHashAddress *)otsHashAddress;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoXmssBDSTreeHash)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoXmssBDSTreeHash_initWithInt_(OrgSpongycastlePqcCryptoXmssBDSTreeHash *self, jint initialHeight);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssBDSTreeHash *new_OrgSpongycastlePqcCryptoXmssBDSTreeHash_initWithInt_(jint initialHeight) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssBDSTreeHash *create_OrgSpongycastlePqcCryptoXmssBDSTreeHash_initWithInt_(jint initialHeight);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoXmssBDSTreeHash)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssBDSTreeHash")