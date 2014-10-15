//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AddressFamilyTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="AddressFamilyTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="AF_UNSPEC"/>
 *     &lt;enumeration value="AF_INET"/>
 *     &lt;enumeration value="AF_IPX"/>
 *     &lt;enumeration value="AF_APPLETALK"/>
 *     &lt;enumeration value="AF_NETBIOS"/>
 *     &lt;enumeration value="AF_INET6"/>
 *     &lt;enumeration value="AF_IRDA"/>
 *     &lt;enumeration value="AF_BTH"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "AddressFamilyTypeEnum", namespace = "http://cybox.mitre.org/objects#NetworkSocketObject-2")
@XmlEnum
public enum AddressFamilyTypeEnum {


    /**
     * Specifies an unspecified address family.
     * 
     */
    AF_UNSPEC("AF_UNSPEC"),

    /**
     * Specifies sockets using for the Internet when using Berkeley sockets.
     * 
     */
    AF_INET("AF_INET"),

    /**
     * Specifies the IPX (Novell Internet Protocol) address family.
     * 
     */
    AF_IPX("AF_IPX"),

    /**
     * Specifies the APPLETALK DDP address family.
     * 
     */
    AF_APPLETALK("AF_APPLETALK"),

    /**
     * Specifies the NETBIOS address family.
     * 
     */
    AF_NETBIOS("AF_NETBIOS"),

    /**
     * Specifies the IP version 6 address family.
     * 
     */
    @XmlEnumValue("AF_INET6")
    AF_INET_6("AF_INET6"),

    /**
     * Specifies IRDA sockets.
     * 
     */
    AF_IRDA("AF_IRDA"),

    /**
     * Specifies BTH sockets.
     * 
     */
    AF_BTH("AF_BTH");
    private final String value;

    AddressFamilyTypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static AddressFamilyTypeEnum fromValue(String v) {
        for (AddressFamilyTypeEnum c: AddressFamilyTypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
