//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.namespace.QName;
import org.mitre.cybox.common_2.ObjectPropertiesType;


/**
 * The CustomObjectType is intended to characterize objects that are not described by other defined CybOX Object schemas. Objects of this type have no pre-defined properties but instead all properties are provided by the author using the inherited Custom_Properties field.
 * 
 * <p>Java class for CustomObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CustomObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Description" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="custom_name" type="{http://www.w3.org/2001/XMLSchema}QName" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CustomObjectType", namespace = "http://cybox.mitre.org/objects#CustomObject-1", propOrder = {
    "description"
})
@XmlRootElement(name = "Custom", namespace = "http://cybox.mitre.org/objects#CustomObject-1")
public class Custom
    extends ObjectPropertiesType
{

    @XmlElement(name = "Description")
    protected String description;
    @XmlAttribute(name = "custom_name")
    protected QName customName;

    /**
     * Gets the value of the description property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the value of the description property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDescription(String value) {
        this.description = value;
    }

    /**
     * Gets the value of the customName property.
     * 
     * @return
     *     possible object is
     *     {@link QName }
     *     
     */
    public QName getCustomName() {
        return customName;
    }

    /**
     * Sets the value of the customName property.
     * 
     * @param value
     *     allowed object is
     *     {@link QName }
     *     
     */
    public void setCustomName(QName value) {
        this.customName = value;
    }

}
