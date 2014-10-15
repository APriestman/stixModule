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
import org.mitre.cybox.common_2.IntegerObjectPropertyType;


/**
 * The PadN type specifies how two or more octets of padding are inserted into the Options area of a header.
 * 
 * <p>Java class for PadNType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PadNType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Octet" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Option_Data_Length" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Option_Data" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PadNType", propOrder = {
    "octet",
    "optionDataLength",
    "optionData"
})
public class PadNType {

    @XmlElement(name = "Octet")
    protected HexBinaryObjectPropertyType octet;
    @XmlElement(name = "Option_Data_Length")
    protected IntegerObjectPropertyType optionDataLength;
    @XmlElement(name = "Option_Data")
    protected IntegerObjectPropertyType optionData;

    /**
     * Gets the value of the octet property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getOctet() {
        return octet;
    }

    /**
     * Sets the value of the octet property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setOctet(HexBinaryObjectPropertyType value) {
        this.octet = value;
    }

    /**
     * Gets the value of the optionDataLength property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getOptionDataLength() {
        return optionDataLength;
    }

    /**
     * Sets the value of the optionDataLength property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setOptionDataLength(IntegerObjectPropertyType value) {
        this.optionDataLength = value;
    }

    /**
     * Gets the value of the optionData property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getOptionData() {
        return optionData;
    }

    /**
     * Sets the value of the optionData property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setOptionData(IntegerObjectPropertyType value) {
        this.optionData = value;
    }

}
