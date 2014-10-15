//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.cybox_2;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for EffectTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="EffectTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="State_Changed"/>
 *     &lt;enumeration value="Data_Read"/>
 *     &lt;enumeration value="Data_Written"/>
 *     &lt;enumeration value="Data_Sent"/>
 *     &lt;enumeration value="Data_Received"/>
 *     &lt;enumeration value="Properties_Read"/>
 *     &lt;enumeration value="Properties_Enumerated"/>
 *     &lt;enumeration value="Values_Enumerated"/>
 *     &lt;enumeration value="ControlCode_Sent"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "EffectTypeEnum")
@XmlEnum
public enum EffectTypeEnum {


    /**
     * Specifies that the associated Action had an effect on the Object of changing its state.
     * 
     */
    @XmlEnumValue("State_Changed")
    STATE_CHANGED("State_Changed"),

    /**
     * Specifies that the associated Action had an effect on the Object of reading data from it.
     * 
     */
    @XmlEnumValue("Data_Read")
    DATA_READ("Data_Read"),

    /**
     * Specifies that the associated Action had an effect on the Object of writing data to it.
     * 
     */
    @XmlEnumValue("Data_Written")
    DATA_WRITTEN("Data_Written"),

    /**
     * Specifies that the associated Action had an effect on the Object of sending data to it.
     * 
     */
    @XmlEnumValue("Data_Sent")
    DATA_SENT("Data_Sent"),

    /**
     * Specifies that the associated Action had an effect on the Object of receiving data from it.
     * 
     */
    @XmlEnumValue("Data_Received")
    DATA_RECEIVED("Data_Received"),

    /**
     * Specifies that the associated Action had an effect on the Object of reading properties from it.
     * 
     */
    @XmlEnumValue("Properties_Read")
    PROPERTIES_READ("Properties_Read"),

    /**
     * Specifies that the associated Action had an effect on the Object of enumerating properties from it.
     * 
     */
    @XmlEnumValue("Properties_Enumerated")
    PROPERTIES_ENUMERATED("Properties_Enumerated"),

    /**
     * Specifies that the associated Action had an effect on the Object of enumerating values from it.
     * 
     */
    @XmlEnumValue("Values_Enumerated")
    VALUES_ENUMERATED("Values_Enumerated"),

    /**
     * Specifies that the associated Action had an effect on the Object of having a control code sent to it.
     * 
     */
    @XmlEnumValue("ControlCode_Sent")
    CONTROL_CODE_SENT("ControlCode_Sent");
    private final String value;

    EffectTypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static EffectTypeEnum fromValue(String v) {
        for (EffectTypeEnum c: EffectTypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
