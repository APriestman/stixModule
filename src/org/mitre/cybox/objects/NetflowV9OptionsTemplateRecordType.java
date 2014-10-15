//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.objects;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.BaseObjectPropertyType;
import org.mitre.cybox.common_2.HexBinaryObjectPropertyType;
import org.mitre.cybox.common_2.IntegerObjectPropertyType;


/**
 * Specifies the Options Template Record region, which includes the Option Scope Length, Option Length, and fields specifying the Scope field type and Scope field length.
 * 
 * <p>Java class for NetflowV9OptionsTemplateRecordType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="NetflowV9OptionsTemplateRecordType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Template_ID" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Option_Scope_Length" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Option_Length" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;sequence maxOccurs="unbounded" minOccurs="0">
 *           &lt;element name="Scope_Field_Type" type="{http://cybox.mitre.org/objects#NetworkFlowObject-2}NetflowV9ScopeFieldType" minOccurs="0"/>
 *           &lt;element name="Scope_Field_Length" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;/sequence>
 *         &lt;sequence maxOccurs="unbounded" minOccurs="0">
 *           &lt;element name="Option_Field_Type" type="{http://cybox.mitre.org/objects#NetworkFlowObject-2}NetflowV9FieldType" minOccurs="0"/>
 *           &lt;element name="Option_Field_Length" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;/sequence>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "NetflowV9OptionsTemplateRecordType", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2", propOrder = {
    "templateID",
    "optionScopeLength",
    "optionLength",
    "scopeFieldTypesAndScopeFieldLengths",
    "optionFieldTypesAndOptionFieldLengths"
})
public class NetflowV9OptionsTemplateRecordType {

    @XmlElement(name = "Template_ID")
    protected IntegerObjectPropertyType templateID;
    @XmlElement(name = "Option_Scope_Length")
    protected HexBinaryObjectPropertyType optionScopeLength;
    @XmlElement(name = "Option_Length")
    protected HexBinaryObjectPropertyType optionLength;
    @XmlElements({
        @XmlElement(name = "Scope_Field_Type", type = NetflowV9ScopeFieldType.class),
        @XmlElement(name = "Scope_Field_Length", type = HexBinaryObjectPropertyType.class)
    })
    protected List<BaseObjectPropertyType> scopeFieldTypesAndScopeFieldLengths;
    @XmlElements({
        @XmlElement(name = "Option_Field_Type", type = NetflowV9FieldType.class),
        @XmlElement(name = "Option_Field_Length", type = HexBinaryObjectPropertyType.class)
    })
    protected List<BaseObjectPropertyType> optionFieldTypesAndOptionFieldLengths;

    /**
     * Gets the value of the templateID property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getTemplateID() {
        return templateID;
    }

    /**
     * Sets the value of the templateID property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setTemplateID(IntegerObjectPropertyType value) {
        this.templateID = value;
    }

    /**
     * Gets the value of the optionScopeLength property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getOptionScopeLength() {
        return optionScopeLength;
    }

    /**
     * Sets the value of the optionScopeLength property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setOptionScopeLength(HexBinaryObjectPropertyType value) {
        this.optionScopeLength = value;
    }

    /**
     * Gets the value of the optionLength property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getOptionLength() {
        return optionLength;
    }

    /**
     * Sets the value of the optionLength property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setOptionLength(HexBinaryObjectPropertyType value) {
        this.optionLength = value;
    }

    /**
     * Gets the value of the scopeFieldTypesAndScopeFieldLengths property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the scopeFieldTypesAndScopeFieldLengths property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getScopeFieldTypesAndScopeFieldLengths().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link NetflowV9ScopeFieldType }
     * {@link HexBinaryObjectPropertyType }
     * 
     * 
     */
    public List<BaseObjectPropertyType> getScopeFieldTypesAndScopeFieldLengths() {
        if (scopeFieldTypesAndScopeFieldLengths == null) {
            scopeFieldTypesAndScopeFieldLengths = new ArrayList<BaseObjectPropertyType>();
        }
        return this.scopeFieldTypesAndScopeFieldLengths;
    }

    /**
     * Gets the value of the optionFieldTypesAndOptionFieldLengths property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the optionFieldTypesAndOptionFieldLengths property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getOptionFieldTypesAndOptionFieldLengths().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link NetflowV9FieldType }
     * {@link HexBinaryObjectPropertyType }
     * 
     * 
     */
    public List<BaseObjectPropertyType> getOptionFieldTypesAndOptionFieldLengths() {
        if (optionFieldTypesAndOptionFieldLengths == null) {
            optionFieldTypesAndOptionFieldLengths = new ArrayList<BaseObjectPropertyType>();
        }
        return this.optionFieldTypesAndOptionFieldLengths;
    }

}
