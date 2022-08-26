package com.youzh.lingtu.sign.crypto.utils;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1ObjectIdentifier;

import java.util.Enumeration;

/**
 * allow us to set attributes on objects that can go into a PKCS12 store.
 */
public interface PKCS12BagAttributeCarrier
{
    void setBagAttribute(
            ASN1ObjectIdentifier oid,
            ASN1Encodable attribute);

    ASN1Encodable getBagAttribute(
            ASN1ObjectIdentifier oid);

    Enumeration getBagAttributeKeys();
}
