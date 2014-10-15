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
 * <p>Java class for ProtocolTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ProtocolTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="IPPROTO_ICMP"/>
 *     &lt;enumeration value="IPPROTO_IGMP"/>
 *     &lt;enumeration value="BTHPROTO_RFCOMM"/>
 *     &lt;enumeration value="IPPROTO_TCP"/>
 *     &lt;enumeration value="IPPROTO_UDP"/>
 *     &lt;enumeration value="IPPROTO_ICMPV6"/>
 *     &lt;enumeration value="IPPROTO_RM"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ProtocolTypeEnum", namespace = "http://cybox.mitre.org/objects#NetworkSocketObject-2")
@XmlEnum
public enum ProtocolTypeEnum {


    /**
     * Indicates the ICMP protocol.
     * 
     */
    IPPROTO_ICMP("IPPROTO_ICMP"),

    /**
     * Indicates the IGMP protocol.
     * 
     */
    IPPROTO_IGMP("IPPROTO_IGMP"),

    /**
     * Indicates the Bluetooth protocol.
     * 
     */
    BTHPROTO_RFCOMM("BTHPROTO_RFCOMM"),

    /**
     * Indicates the TCP protocol.
     * 
     */
    IPPROTO_TCP("IPPROTO_TCP"),

    /**
     * Indicates the UDP protocol.
     * 
     */
    IPPROTO_UDP("IPPROTO_UDP"),

    /**
     * Indicates the ICMP v6 protocol.
     * 
     */
    @XmlEnumValue("IPPROTO_ICMPV6")
    IPPROTO_ICMPV_6("IPPROTO_ICMPV6"),

    /**
     * Indicates the Reliable Multicasting protocol.
     * 
     */
    IPPROTO_RM("IPPROTO_RM");
    private final String value;

    ProtocolTypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ProtocolTypeEnum fromValue(String v) {
        for (ProtocolTypeEnum c: ProtocolTypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
