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
 * Parameter problem error message; ICMP v6 type=4.
 * 
 * <p>Java class for ICMPv6ParameterProblemType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ICMPv6ParameterProblemType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;choice minOccurs="0">
 *           &lt;element name="Erroneous_Header_Field" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *           &lt;element name="Unrecognized_Next_Header_Type" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *           &lt;element name="Unrecognized_IPv6_Option" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;/choice>
 *         &lt;element name="Pointer" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ICMPv6ParameterProblemType", propOrder = {
    "unrecognizedIPv6Option",
    "unrecognizedNextHeaderType",
    "erroneousHeaderField",
    "pointer"
})
public class ICMPv6ParameterProblemType {

    @XmlElement(name = "Unrecognized_IPv6_Option")
    protected Boolean unrecognizedIPv6Option;
    @XmlElement(name = "Unrecognized_Next_Header_Type")
    protected Boolean unrecognizedNextHeaderType;
    @XmlElement(name = "Erroneous_Header_Field")
    protected Boolean erroneousHeaderField;
    @XmlElement(name = "Pointer")
    protected HexBinaryObjectPropertyType pointer;

    /**
     * Gets the value of the unrecognizedIPv6Option property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isUnrecognizedIPv6Option() {
        return unrecognizedIPv6Option;
    }

    /**
     * Sets the value of the unrecognizedIPv6Option property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setUnrecognizedIPv6Option(Boolean value) {
        this.unrecognizedIPv6Option = value;
    }

    /**
     * Gets the value of the unrecognizedNextHeaderType property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isUnrecognizedNextHeaderType() {
        return unrecognizedNextHeaderType;
    }

    /**
     * Sets the value of the unrecognizedNextHeaderType property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setUnrecognizedNextHeaderType(Boolean value) {
        this.unrecognizedNextHeaderType = value;
    }

    /**
     * Gets the value of the erroneousHeaderField property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isErroneousHeaderField() {
        return erroneousHeaderField;
    }

    /**
     * Sets the value of the erroneousHeaderField property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setErroneousHeaderField(Boolean value) {
        this.erroneousHeaderField = value;
    }

    /**
     * Gets the value of the pointer property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getPointer() {
        return pointer;
    }

    /**
     * Sets the value of the pointer property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setPointer(HexBinaryObjectPropertyType value) {
        this.pointer = value;
    }

}
