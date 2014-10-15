//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.stix.default_vocabularies_1;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SecurityCompromiseEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="SecurityCompromiseEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Yes"/>
 *     &lt;enumeration value="Suspected"/>
 *     &lt;enumeration value="No"/>
 *     &lt;enumeration value="Unknown"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SecurityCompromiseEnum-1.0")
@XmlEnum
public enum SecurityCompromiseEnum10 {


    /**
     * It has been confirmed that this incident resulted in a security compromise.
     * 
     */
    @XmlEnumValue("Yes")
    YES("Yes"),

    /**
     * It is suspected that this incident resulted in a security compromise.
     * 
     */
    @XmlEnumValue("Suspected")
    SUSPECTED("Suspected"),

    /**
     * It has been confirmed that this incident did not result in a security compromise.
     * 
     */
    @XmlEnumValue("No")
    NO("No"),

    /**
     * It is not known whether this incident resulted in a security compromise.
     * 
     */
    @XmlEnumValue("Unknown")
    UNKNOWN("Unknown");
    private final String value;

    SecurityCompromiseEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static SecurityCompromiseEnum10 fromValue(String v) {
        for (SecurityCompromiseEnum10 c: SecurityCompromiseEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
