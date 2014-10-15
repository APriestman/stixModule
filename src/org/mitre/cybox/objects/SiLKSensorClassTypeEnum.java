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
 * <p>Java class for SiLKSensorClassTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="SiLKSensorClassTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="all"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SiLKSensorClassTypeEnum", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2")
@XmlEnum
public enum SiLKSensorClassTypeEnum {


    /**
     * Defines sensor class "all".
     * 
     */
    @XmlEnumValue("all")
    ALL("all");
    private final String value;

    SiLKSensorClassTypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static SiLKSensorClassTypeEnum fromValue(String v) {
        for (SiLKSensorClassTypeEnum c: SiLKSensorClassTypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
