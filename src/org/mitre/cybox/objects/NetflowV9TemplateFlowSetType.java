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
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.HexBinaryObjectPropertyType;
import org.mitre.cybox.common_2.IntegerObjectPropertyType;


/**
 * Provides the format of the Template FlowSet.
 * 
 * <p>Java class for NetflowV9TemplateFlowSetType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="NetflowV9TemplateFlowSetType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Flow_Set_ID" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Length" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Template_Record" type="{http://cybox.mitre.org/objects#NetworkFlowObject-2}NetflowV9TemplateRecordType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "NetflowV9TemplateFlowSetType", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2", propOrder = {
    "flowSetID",
    "length",
    "templateRecords"
})
public class NetflowV9TemplateFlowSetType {

    @XmlElement(name = "Flow_Set_ID")
    protected HexBinaryObjectPropertyType flowSetID;
    @XmlElement(name = "Length")
    protected IntegerObjectPropertyType length;
    @XmlElement(name = "Template_Record")
    protected List<NetflowV9TemplateRecordType> templateRecords;

    /**
     * Gets the value of the flowSetID property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getFlowSetID() {
        return flowSetID;
    }

    /**
     * Sets the value of the flowSetID property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setFlowSetID(HexBinaryObjectPropertyType value) {
        this.flowSetID = value;
    }

    /**
     * Gets the value of the length property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getLength() {
        return length;
    }

    /**
     * Sets the value of the length property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setLength(IntegerObjectPropertyType value) {
        this.length = value;
    }

    /**
     * Gets the value of the templateRecords property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the templateRecords property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getTemplateRecords().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link NetflowV9TemplateRecordType }
     * 
     * 
     */
    public List<NetflowV9TemplateRecordType> getTemplateRecords() {
        if (templateRecords == null) {
            templateRecords = new ArrayList<NetflowV9TemplateRecordType>();
        }
        return this.templateRecords;
    }

}
