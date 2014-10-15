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
 * <p>Java class for URITypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="URITypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="URL"/>
 *     &lt;enumeration value="General URN"/>
 *     &lt;enumeration value="Domain Name"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "URITypeEnum", namespace = "http://cybox.mitre.org/objects#URIObject-2")
@XmlEnum
public enum URITypeEnum {


    /**
     * Specifies a URL type of URI.
     * 
     */
    URL("URL"),

    /**
     * Specifies a General URN type of URI.
     * 
     */
    @XmlEnumValue("General URN")
    GENERAL_URN("General URN"),

    /**
     * Specifies a Domain Name type of URI.
     * 
     */
    @XmlEnumValue("Domain Name")
    DOMAIN_NAME("Domain Name");
    private final String value;

    URITypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static URITypeEnum fromValue(String v) {
        for (URITypeEnum c: URITypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
