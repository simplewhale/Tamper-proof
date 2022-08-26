//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/mceliece/McElieceFujisakiCipher.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher

#if !defined (OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher || defined(INCLUDE_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher))
#define OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher_

#define RESTRICT_OrgSpongycastlePqcCryptoMessageEncryptor 1
#define INCLUDE_OrgSpongycastlePqcCryptoMessageEncryptor 1
#include "org/spongycastle/pqc/crypto/MessageEncryptor.h"

@class IOSByteArray;
@class OrgSpongycastlePqcCryptoMcelieceMcElieceCCA2KeyParameters;
@protocol OrgSpongycastleCryptoCipherParameters;

@interface OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher : NSObject < OrgSpongycastlePqcCryptoMessageEncryptor > {
 @public
  OrgSpongycastlePqcCryptoMcelieceMcElieceCCA2KeyParameters *key_;
}

#pragma mark Public

- (instancetype)init;

- (jint)getKeySizeWithOrgSpongycastlePqcCryptoMcelieceMcElieceCCA2KeyParameters:(OrgSpongycastlePqcCryptoMcelieceMcElieceCCA2KeyParameters *)key;

- (void)init__WithBoolean:(jboolean)forEncryption
withOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)messageDecryptWithByteArray:(IOSByteArray *)input;

- (IOSByteArray *)messageEncryptWithByteArray:(IOSByteArray *)input;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher)

J2OBJC_FIELD_SETTER(OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher, key_, OrgSpongycastlePqcCryptoMcelieceMcElieceCCA2KeyParameters *)

inline NSString *OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher_get_OID(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher_OID;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher, OID, NSString *)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher_init(OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher *self);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher *new_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher *create_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoMcelieceMcElieceFujisakiCipher")
