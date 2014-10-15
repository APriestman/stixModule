//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for WhoisContactTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="WhoisContactTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="ADMIN"/>
 *     &lt;enumeration value="BILLING"/>
 *     &lt;enumeration value="TECHNICAL"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "WhoisContactTypeEnum", namespace = "http://cybox.mitre.org/objects#WhoisObject-2")
@XmlEnum
public enum WhoisContactTypeEnum {


    /**
     * The contact is an administrator.
     * 
     */
    ADMIN,

    /**
     * The contact is for billing.
     * 
     */
    BILLING,

    /**
     * The contact is for technical assistance.
     * 
     */
    TECHNICAL;

    public String value() {
        return name();
    }

    public static WhoisContactTypeEnum fromValue(String v) {
        return valueOf(v);
    }

}
