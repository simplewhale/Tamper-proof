//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/CharToByteConverter.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoCharToByteConverter")
#ifdef RESTRICT_OrgSpongycastleCryptoCharToByteConverter
#define INCLUDE_ALL_OrgSpongycastleCryptoCharToByteConverter 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoCharToByteConverter 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoCharToByteConverter

#if !defined (OrgSpongycastleCryptoCharToByteConverter_) && (INCLUDE_ALL_OrgSpongycastleCryptoCharToByteConverter || defined(INCLUDE_OrgSpongycastleCryptoCharToByteConverter))
#define OrgSpongycastleCryptoCharToByteConverter_

@class IOSByteArray;
@class IOSCharArray;

@protocol OrgSpongycastleCryptoCharToByteConverter < JavaObject >

- (NSString *)getType;

- (IOSByteArray *)convertWithCharArray:(IOSCharArray *)password;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoCharToByteConverter)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoCharToByteConverter)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoCharToByteConverter")
