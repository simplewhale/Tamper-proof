//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/util/PrivateKeyFactory.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/InputStream.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/asn1/ASN1Encodable.h"
#include "org/spongycastle/asn1/ASN1InputStream.h"
#include "org/spongycastle/asn1/ASN1Integer.h"
#include "org/spongycastle/asn1/ASN1ObjectIdentifier.h"
#include "org/spongycastle/asn1/ASN1Primitive.h"
#include "org/spongycastle/asn1/oiw/ElGamalParameter.h"
#include "org/spongycastle/asn1/oiw/OIWObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/DHParameter.h"
#include "org/spongycastle/asn1/pkcs/PKCSObjectIdentifiers.h"
#include "org/spongycastle/asn1/pkcs/PrivateKeyInfo.h"
#include "org/spongycastle/asn1/pkcs/RSAPrivateKey.h"
#include "org/spongycastle/asn1/sec/ECPrivateKey.h"
#include "org/spongycastle/asn1/x509/AlgorithmIdentifier.h"
#include "org/spongycastle/asn1/x509/DSAParameter.h"
#include "org/spongycastle/asn1/x9/ECNamedCurveTable.h"
#include "org/spongycastle/asn1/x9/X962Parameters.h"
#include "org/spongycastle/asn1/x9/X9ECParameters.h"
#include "org/spongycastle/asn1/x9/X9ObjectIdentifiers.h"
#include "org/spongycastle/crypto/ec/CustomNamedCurves.h"
#include "org/spongycastle/crypto/params/AsymmetricKeyParameter.h"
#include "org/spongycastle/crypto/params/DHParameters.h"
#include "org/spongycastle/crypto/params/DHPrivateKeyParameters.h"
#include "org/spongycastle/crypto/params/DSAParameters.h"
#include "org/spongycastle/crypto/params/DSAPrivateKeyParameters.h"
#include "org/spongycastle/crypto/params/ECDomainParameters.h"
#include "org/spongycastle/crypto/params/ECNamedDomainParameters.h"
#include "org/spongycastle/crypto/params/ECPrivateKeyParameters.h"
#include "org/spongycastle/crypto/params/ElGamalParameters.h"
#include "org/spongycastle/crypto/params/ElGamalPrivateKeyParameters.h"
#include "org/spongycastle/crypto/params/RSAPrivateCrtKeyParameters.h"
#include "org/spongycastle/crypto/util/PrivateKeyFactory.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECPoint.h"

@implementation OrgSpongycastleCryptoUtilPrivateKeyFactory

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoUtilPrivateKeyFactory_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)createKeyWithByteArray:(IOSByteArray *)privateKeyInfoData {
  return OrgSpongycastleCryptoUtilPrivateKeyFactory_createKeyWithByteArray_(privateKeyInfoData);
}

+ (OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)createKeyWithJavaIoInputStream:(JavaIoInputStream *)inStr {
  return OrgSpongycastleCryptoUtilPrivateKeyFactory_createKeyWithJavaIoInputStream_(inStr);
}

+ (OrgSpongycastleCryptoParamsAsymmetricKeyParameter *)createKeyWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:(OrgSpongycastleAsn1PkcsPrivateKeyInfo *)keyInfo {
  return OrgSpongycastleCryptoUtilPrivateKeyFactory_createKeyWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(keyInfo);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 0, 3, 2, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoParamsAsymmetricKeyParameter;", 0x9, 0, 4, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(createKeyWithByteArray:);
  methods[2].selector = @selector(createKeyWithJavaIoInputStream:);
  methods[3].selector = @selector(createKeyWithOrgSpongycastleAsn1PkcsPrivateKeyInfo:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "createKey", "[B", "LJavaIoIOException;", "LJavaIoInputStream;", "LOrgSpongycastleAsn1PkcsPrivateKeyInfo;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoUtilPrivateKeyFactory = { "PrivateKeyFactory", "org.spongycastle.crypto.util", ptrTable, methods, NULL, 7, 0x1, 4, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoUtilPrivateKeyFactory;
}

@end

void OrgSpongycastleCryptoUtilPrivateKeyFactory_init(OrgSpongycastleCryptoUtilPrivateKeyFactory *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoUtilPrivateKeyFactory *new_OrgSpongycastleCryptoUtilPrivateKeyFactory_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoUtilPrivateKeyFactory, init)
}

OrgSpongycastleCryptoUtilPrivateKeyFactory *create_OrgSpongycastleCryptoUtilPrivateKeyFactory_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoUtilPrivateKeyFactory, init)
}

OrgSpongycastleCryptoParamsAsymmetricKeyParameter *OrgSpongycastleCryptoUtilPrivateKeyFactory_createKeyWithByteArray_(IOSByteArray *privateKeyInfoData) {
  OrgSpongycastleCryptoUtilPrivateKeyFactory_initialize();
  return OrgSpongycastleCryptoUtilPrivateKeyFactory_createKeyWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(OrgSpongycastleAsn1PkcsPrivateKeyInfo_getInstanceWithId_(OrgSpongycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(privateKeyInfoData)));
}

OrgSpongycastleCryptoParamsAsymmetricKeyParameter *OrgSpongycastleCryptoUtilPrivateKeyFactory_createKeyWithJavaIoInputStream_(JavaIoInputStream *inStr) {
  OrgSpongycastleCryptoUtilPrivateKeyFactory_initialize();
  return OrgSpongycastleCryptoUtilPrivateKeyFactory_createKeyWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(OrgSpongycastleAsn1PkcsPrivateKeyInfo_getInstanceWithId_([new_OrgSpongycastleAsn1ASN1InputStream_initWithJavaIoInputStream_(inStr) readObject]));
}

OrgSpongycastleCryptoParamsAsymmetricKeyParameter *OrgSpongycastleCryptoUtilPrivateKeyFactory_createKeyWithOrgSpongycastleAsn1PkcsPrivateKeyInfo_(OrgSpongycastleAsn1PkcsPrivateKeyInfo *keyInfo) {
  OrgSpongycastleCryptoUtilPrivateKeyFactory_initialize();
  OrgSpongycastleAsn1X509AlgorithmIdentifier *algId = [((OrgSpongycastleAsn1PkcsPrivateKeyInfo *) nil_chk(keyInfo)) getPrivateKeyAlgorithm];
  if ([((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([((OrgSpongycastleAsn1X509AlgorithmIdentifier *) nil_chk(algId)) getAlgorithm])) isEqual:JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, rsaEncryption)]) {
    OrgSpongycastleAsn1PkcsRSAPrivateKey *keyStructure = OrgSpongycastleAsn1PkcsRSAPrivateKey_getInstanceWithId_([keyInfo parsePrivateKey]);
    return new_OrgSpongycastleCryptoParamsRSAPrivateCrtKeyParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((OrgSpongycastleAsn1PkcsRSAPrivateKey *) nil_chk(keyStructure)) getModulus], [keyStructure getPublicExponent], [keyStructure getPrivateExponent], [keyStructure getPrime1], [keyStructure getPrime2], [keyStructure getExponent1], [keyStructure getExponent2], [keyStructure getCoefficient]);
  }
  else if ([((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([algId getAlgorithm])) isEqual:JreLoadStatic(OrgSpongycastleAsn1PkcsPKCSObjectIdentifiers, dhKeyAgreement)]) {
    OrgSpongycastleAsn1PkcsDHParameter *params = OrgSpongycastleAsn1PkcsDHParameter_getInstanceWithId_([algId getParameters]);
    OrgSpongycastleAsn1ASN1Integer *derX = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([keyInfo parsePrivateKey], [OrgSpongycastleAsn1ASN1Integer class]);
    JavaMathBigInteger *lVal = [((OrgSpongycastleAsn1PkcsDHParameter *) nil_chk(params)) getL];
    jint l = lVal == nil ? 0 : [lVal intValue];
    OrgSpongycastleCryptoParamsDHParameters *dhParams = new_OrgSpongycastleCryptoParamsDHParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_([params getP], [params getG], nil, l);
    return new_OrgSpongycastleCryptoParamsDHPrivateKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDHParameters_([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(derX)) getValue], dhParams);
  }
  else if ([((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([algId getAlgorithm])) isEqual:JreLoadStatic(OrgSpongycastleAsn1OiwOIWObjectIdentifiers, elGamalAlgorithm)]) {
    OrgSpongycastleAsn1OiwElGamalParameter *params = OrgSpongycastleAsn1OiwElGamalParameter_getInstanceWithId_([algId getParameters]);
    OrgSpongycastleAsn1ASN1Integer *derX = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([keyInfo parsePrivateKey], [OrgSpongycastleAsn1ASN1Integer class]);
    return new_OrgSpongycastleCryptoParamsElGamalPrivateKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsElGamalParameters_([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(derX)) getValue], new_OrgSpongycastleCryptoParamsElGamalParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_([((OrgSpongycastleAsn1OiwElGamalParameter *) nil_chk(params)) getP], [params getG]));
  }
  else if ([((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([algId getAlgorithm])) isEqual:JreLoadStatic(OrgSpongycastleAsn1X9X9ObjectIdentifiers, id_dsa)]) {
    OrgSpongycastleAsn1ASN1Integer *derX = (OrgSpongycastleAsn1ASN1Integer *) cast_chk([keyInfo parsePrivateKey], [OrgSpongycastleAsn1ASN1Integer class]);
    id<OrgSpongycastleAsn1ASN1Encodable> de = [algId getParameters];
    OrgSpongycastleCryptoParamsDSAParameters *parameters = nil;
    if (de != nil) {
      OrgSpongycastleAsn1X509DSAParameter *params = OrgSpongycastleAsn1X509DSAParameter_getInstanceWithId_([de toASN1Primitive]);
      parameters = new_OrgSpongycastleCryptoParamsDSAParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((OrgSpongycastleAsn1X509DSAParameter *) nil_chk(params)) getP], [params getQ], [params getG]);
    }
    return new_OrgSpongycastleCryptoParamsDSAPrivateKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsDSAParameters_([((OrgSpongycastleAsn1ASN1Integer *) nil_chk(derX)) getValue], parameters);
  }
  else if ([((OrgSpongycastleAsn1ASN1ObjectIdentifier *) nil_chk([algId getAlgorithm])) isEqual:JreLoadStatic(OrgSpongycastleAsn1X9X9ObjectIdentifiers, id_ecPublicKey)]) {
    OrgSpongycastleAsn1X9X962Parameters *params = new_OrgSpongycastleAsn1X9X962Parameters_initWithOrgSpongycastleAsn1ASN1Primitive_((OrgSpongycastleAsn1ASN1Primitive *) cast_chk([algId getParameters], [OrgSpongycastleAsn1ASN1Primitive class]));
    OrgSpongycastleAsn1X9X9ECParameters *x9;
    OrgSpongycastleCryptoParamsECDomainParameters *dParams;
    if ([params isNamedCurve]) {
      OrgSpongycastleAsn1ASN1ObjectIdentifier *oid = (OrgSpongycastleAsn1ASN1ObjectIdentifier *) cast_chk([params getParameters], [OrgSpongycastleAsn1ASN1ObjectIdentifier class]);
      x9 = OrgSpongycastleCryptoEcCustomNamedCurves_getByOIDWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(oid);
      if (x9 == nil) {
        x9 = OrgSpongycastleAsn1X9ECNamedCurveTable_getByOIDWithOrgSpongycastleAsn1ASN1ObjectIdentifier_(oid);
      }
      dParams = new_OrgSpongycastleCryptoParamsECNamedDomainParameters_initWithOrgSpongycastleAsn1ASN1ObjectIdentifier_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(oid, [((OrgSpongycastleAsn1X9X9ECParameters *) nil_chk(x9)) getCurve], [x9 getG], [x9 getN], [x9 getH], [x9 getSeed]);
    }
    else {
      x9 = OrgSpongycastleAsn1X9X9ECParameters_getInstanceWithId_([params getParameters]);
      dParams = new_OrgSpongycastleCryptoParamsECDomainParameters_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_([((OrgSpongycastleAsn1X9X9ECParameters *) nil_chk(x9)) getCurve], [x9 getG], [x9 getN], [x9 getH], [x9 getSeed]);
    }
    OrgSpongycastleAsn1SecECPrivateKey *ec = OrgSpongycastleAsn1SecECPrivateKey_getInstanceWithId_([keyInfo parsePrivateKey]);
    JavaMathBigInteger *d = [((OrgSpongycastleAsn1SecECPrivateKey *) nil_chk(ec)) getKey];
    return new_OrgSpongycastleCryptoParamsECPrivateKeyParameters_initWithJavaMathBigInteger_withOrgSpongycastleCryptoParamsECDomainParameters_(d, dParams);
  }
  else {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"algorithm identifier in key not recognised");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoUtilPrivateKeyFactory)
