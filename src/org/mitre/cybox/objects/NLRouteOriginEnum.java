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
 * <p>Java class for NLRouteOriginEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="NLRouteOriginEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="NlroManual"/>
 *     &lt;enumeration value="NlroWellKnown"/>
 *     &lt;enumeration value="NlroDHCP"/>
 *     &lt;enumeration value="NlroRouterAdvertisement"/>
 *     &lt;enumeration value="Nlro6to4"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "NLRouteOriginEnum", namespace = "http://cybox.mitre.org/objects#WinNetworkRouteEntryObject-2")
@XmlEnum
public enum NLRouteOriginEnum {


    /**
     * Specifies that the origin was determined as a result of manual configuration.
     * 
     */
    @XmlEnumValue("NlroManual")
    NLRO_MANUAL("NlroManual"),

    /**
     * Specifies that the route is well-known.
     * 
     */
    @XmlEnumValue("NlroWellKnown")
    NLRO_WELL_KNOWN("NlroWellKnown"),

    /**
     * Specifies that the origin was determined as a result of DHCP configuration.
     * 
     */
    @XmlEnumValue("NlroDHCP")
    NLRO_DHCP("NlroDHCP"),

    /**
     * Specifies that the origin was determined as a result of router advertisement.
     * 
     */
    @XmlEnumValue("NlroRouterAdvertisement")
    NLRO_ROUTER_ADVERTISEMENT("NlroRouterAdvertisement"),

    /**
     * Specifies that the origin was determined as a result of 6to4 tunneling.
     * 
     */
    @XmlEnumValue("Nlro6to4")
    NLRO_6_TO_4("Nlro6to4");
    private final String value;

    NLRouteOriginEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static NLRouteOriginEnum fromValue(String v) {
        for (NLRouteOriginEnum c: NLRouteOriginEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
