//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.HexBinaryObjectPropertyType;


/**
 * The Delegation field specifies the Kerberos delegation used for the Windows computer account.
 * 
 * <p>Java class for KerberosDelegationType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="KerberosDelegationType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Bitmask" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Service" type="{http://cybox.mitre.org/objects#WinComputerAccountObject-2}KerberosServiceType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KerberosDelegationType", namespace = "http://cybox.mitre.org/objects#WinComputerAccountObject-2", propOrder = {
    "bitmask",
    "service"
})
public class KerberosDelegationType {

    @XmlElement(name = "Bitmask")
    protected HexBinaryObjectPropertyType bitmask;
    @XmlElement(name = "Service")
    protected KerberosServiceType service;

    /**
     * Gets the value of the bitmask property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getBitmask() {
        return bitmask;
    }

    /**
     * Sets the value of the bitmask property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setBitmask(HexBinaryObjectPropertyType value) {
        this.bitmask = value;
    }

    /**
     * Gets the value of the service property.
     * 
     * @return
     *     possible object is
     *     {@link KerberosServiceType }
     *     
     */
    public KerberosServiceType getService() {
        return service;
    }

    /**
     * Sets the value of the service property.
     * 
     * @param value
     *     allowed object is
     *     {@link KerberosServiceType }
     *     
     */
    public void setService(KerberosServiceType value) {
        this.service = value;
    }

}
