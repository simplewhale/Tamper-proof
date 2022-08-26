//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/DTLSProtocol.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/SecureRandom.h"
#include "java/util/Hashtable.h"
#include "java/util/Vector.h"
#include "org/spongycastle/crypto/tls/AlertDescription.h"
#include "org/spongycastle/crypto/tls/Certificate.h"
#include "org/spongycastle/crypto/tls/DTLSProtocol.h"
#include "org/spongycastle/crypto/tls/DTLSRecordLayer.h"
#include "org/spongycastle/crypto/tls/EncryptionAlgorithm.h"
#include "org/spongycastle/crypto/tls/MaxFragmentLength.h"
#include "org/spongycastle/crypto/tls/TlsExtensionsUtils.h"
#include "org/spongycastle/crypto/tls/TlsFatalAlert.h"
#include "org/spongycastle/crypto/tls/TlsProtocol.h"
#include "org/spongycastle/crypto/tls/TlsUtils.h"
#include "org/spongycastle/util/Arrays.h"

@implementation OrgSpongycastleCryptoTlsDTLSProtocol

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom {
  OrgSpongycastleCryptoTlsDTLSProtocol_initWithJavaSecuritySecureRandom_(self, secureRandom);
  return self;
}

- (void)processFinishedWithByteArray:(IOSByteArray *)body
                       withByteArray:(IOSByteArray *)expected_verify_data {
  JavaIoByteArrayInputStream *buf = new_JavaIoByteArrayInputStream_initWithByteArray_(body);
  IOSByteArray *verify_data = OrgSpongycastleCryptoTlsTlsUtils_readFullyWithInt_withJavaIoInputStream_(((IOSByteArray *) nil_chk(expected_verify_data))->size_, buf);
  OrgSpongycastleCryptoTlsTlsProtocol_assertEmptyWithJavaIoByteArrayInputStream_(buf);
  if (!OrgSpongycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(expected_verify_data, verify_data)) {
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_handshake_failure);
  }
}

+ (void)applyMaxFragmentLengthExtensionWithOrgSpongycastleCryptoTlsDTLSRecordLayer:(OrgSpongycastleCryptoTlsDTLSRecordLayer *)recordLayer
                                                                         withShort:(jshort)maxFragmentLength {
  OrgSpongycastleCryptoTlsDTLSProtocol_applyMaxFragmentLengthExtensionWithOrgSpongycastleCryptoTlsDTLSRecordLayer_withShort_(recordLayer, maxFragmentLength);
}

+ (jshort)evaluateMaxFragmentLengthExtensionWithBoolean:(jboolean)resumedSession
                                  withJavaUtilHashtable:(JavaUtilHashtable *)clientExtensions
                                  withJavaUtilHashtable:(JavaUtilHashtable *)serverExtensions
                                              withShort:(jshort)alertDescription {
  return OrgSpongycastleCryptoTlsDTLSProtocol_evaluateMaxFragmentLengthExtensionWithBoolean_withJavaUtilHashtable_withJavaUtilHashtable_withShort_(resumedSession, clientExtensions, serverExtensions, alertDescription);
}

+ (IOSByteArray *)generateCertificateWithOrgSpongycastleCryptoTlsCertificate:(OrgSpongycastleCryptoTlsCertificate *)certificate {
  return OrgSpongycastleCryptoTlsDTLSProtocol_generateCertificateWithOrgSpongycastleCryptoTlsCertificate_(certificate);
}

+ (IOSByteArray *)generateSupplementalDataWithJavaUtilVector:(JavaUtilVector *)supplementalData {
  return OrgSpongycastleCryptoTlsDTLSProtocol_generateSupplementalDataWithJavaUtilVector_(supplementalData);
}

+ (void)validateSelectedCipherSuiteWithInt:(jint)selectedCipherSuite
                                 withShort:(jshort)alertDescription {
  OrgSpongycastleCryptoTlsDTLSProtocol_validateSelectedCipherSuiteWithInt_withShort_(selectedCipherSuite, alertDescription);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0xc, 4, 5, 3, -1, -1, -1 },
    { NULL, "S", 0xc, 6, 7, 3, -1, -1, -1 },
    { NULL, "[B", 0xc, 8, 9, 3, -1, -1, -1 },
    { NULL, "[B", 0xc, 10, 11, 3, -1, -1, -1 },
    { NULL, "V", 0xc, 12, 13, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecuritySecureRandom:);
  methods[1].selector = @selector(processFinishedWithByteArray:withByteArray:);
  methods[2].selector = @selector(applyMaxFragmentLengthExtensionWithOrgSpongycastleCryptoTlsDTLSRecordLayer:withShort:);
  methods[3].selector = @selector(evaluateMaxFragmentLengthExtensionWithBoolean:withJavaUtilHashtable:withJavaUtilHashtable:withShort:);
  methods[4].selector = @selector(generateCertificateWithOrgSpongycastleCryptoTlsCertificate:);
  methods[5].selector = @selector(generateSupplementalDataWithJavaUtilVector:);
  methods[6].selector = @selector(validateSelectedCipherSuiteWithInt:withShort:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "secureRandom_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;", "processFinished", "[B[B", "LJavaIoIOException;", "applyMaxFragmentLengthExtension", "LOrgSpongycastleCryptoTlsDTLSRecordLayer;S", "evaluateMaxFragmentLengthExtension", "ZLJavaUtilHashtable;LJavaUtilHashtable;S", "generateCertificate", "LOrgSpongycastleCryptoTlsCertificate;", "generateSupplementalData", "LJavaUtilVector;", "validateSelectedCipherSuite", "IS" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsDTLSProtocol = { "DTLSProtocol", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x401, 7, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsDTLSProtocol;
}

@end

void OrgSpongycastleCryptoTlsDTLSProtocol_initWithJavaSecuritySecureRandom_(OrgSpongycastleCryptoTlsDTLSProtocol *self, JavaSecuritySecureRandom *secureRandom) {
  NSObject_init(self);
  if (secureRandom == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'secureRandom' cannot be null");
  }
  self->secureRandom_ = secureRandom;
}

void OrgSpongycastleCryptoTlsDTLSProtocol_applyMaxFragmentLengthExtensionWithOrgSpongycastleCryptoTlsDTLSRecordLayer_withShort_(OrgSpongycastleCryptoTlsDTLSRecordLayer *recordLayer, jshort maxFragmentLength) {
  OrgSpongycastleCryptoTlsDTLSProtocol_initialize();
  if (maxFragmentLength >= 0) {
    if (!OrgSpongycastleCryptoTlsMaxFragmentLength_isValidWithShort_(maxFragmentLength)) {
      @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_internal_error);
    }
    jint plainTextLimit = JreLShift32(1, (8 + maxFragmentLength));
    [((OrgSpongycastleCryptoTlsDTLSRecordLayer *) nil_chk(recordLayer)) setPlaintextLimitWithInt:plainTextLimit];
  }
}

jshort OrgSpongycastleCryptoTlsDTLSProtocol_evaluateMaxFragmentLengthExtensionWithBoolean_withJavaUtilHashtable_withJavaUtilHashtable_withShort_(jboolean resumedSession, JavaUtilHashtable *clientExtensions, JavaUtilHashtable *serverExtensions, jshort alertDescription) {
  OrgSpongycastleCryptoTlsDTLSProtocol_initialize();
  jshort maxFragmentLength = OrgSpongycastleCryptoTlsTlsExtensionsUtils_getMaxFragmentLengthExtensionWithJavaUtilHashtable_(serverExtensions);
  if (maxFragmentLength >= 0) {
    if (!OrgSpongycastleCryptoTlsMaxFragmentLength_isValidWithShort_(maxFragmentLength) || (!resumedSession && maxFragmentLength != OrgSpongycastleCryptoTlsTlsExtensionsUtils_getMaxFragmentLengthExtensionWithJavaUtilHashtable_(clientExtensions))) {
      @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(alertDescription);
    }
  }
  return maxFragmentLength;
}

IOSByteArray *OrgSpongycastleCryptoTlsDTLSProtocol_generateCertificateWithOrgSpongycastleCryptoTlsCertificate_(OrgSpongycastleCryptoTlsCertificate *certificate) {
  OrgSpongycastleCryptoTlsDTLSProtocol_initialize();
  JavaIoByteArrayOutputStream *buf = new_JavaIoByteArrayOutputStream_init();
  [((OrgSpongycastleCryptoTlsCertificate *) nil_chk(certificate)) encodeWithJavaIoOutputStream:buf];
  return [buf toByteArray];
}

IOSByteArray *OrgSpongycastleCryptoTlsDTLSProtocol_generateSupplementalDataWithJavaUtilVector_(JavaUtilVector *supplementalData) {
  OrgSpongycastleCryptoTlsDTLSProtocol_initialize();
  JavaIoByteArrayOutputStream *buf = new_JavaIoByteArrayOutputStream_init();
  OrgSpongycastleCryptoTlsTlsProtocol_writeSupplementalDataWithJavaIoOutputStream_withJavaUtilVector_(buf, supplementalData);
  return [buf toByteArray];
}

void OrgSpongycastleCryptoTlsDTLSProtocol_validateSelectedCipherSuiteWithInt_withShort_(jint selectedCipherSuite, jshort alertDescription) {
  OrgSpongycastleCryptoTlsDTLSProtocol_initialize();
  switch (OrgSpongycastleCryptoTlsTlsUtils_getEncryptionAlgorithmWithInt_(selectedCipherSuite)) {
    case OrgSpongycastleCryptoTlsEncryptionAlgorithm_RC4_40:
    case OrgSpongycastleCryptoTlsEncryptionAlgorithm_RC4_128:
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(alertDescription);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsDTLSProtocol)
