//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsCompression.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsCompression")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsTlsCompression
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsCompression 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsCompression 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsTlsCompression

#if !defined (OrgSpongycastleCryptoTlsTlsCompression_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsCompression || defined(INCLUDE_OrgSpongycastleCryptoTlsTlsCompression))
#define OrgSpongycastleCryptoTlsTlsCompression_

@class JavaIoOutputStream;

@protocol OrgSpongycastleCryptoTlsTlsCompression < JavaObject >

- (JavaIoOutputStream *)compressWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (JavaIoOutputStream *)decompressWithJavaIoOutputStream:(JavaIoOutputStream *)output;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsTlsCompression)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsTlsCompression)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsTlsCompression")