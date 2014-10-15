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
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The WindowsVolumeObjectType type is intended to characterize Windows disk volumes.
 * 
 * <p>Java class for WindowsVolumeObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WindowsVolumeObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/objects#VolumeObject-2}VolumeObjectType">
 *       &lt;sequence>
 *         &lt;element name="Attributes_List" type="{http://cybox.mitre.org/objects#WinVolumeObject-2}WindowsVolumeAttributesListType" minOccurs="0"/>
 *         &lt;element name="Drive_Letter" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Drive_Type" type="{http://cybox.mitre.org/objects#WinVolumeObject-2}WindowsDriveType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WindowsVolumeObjectType", namespace = "http://cybox.mitre.org/objects#WinVolumeObject-2", propOrder = {
    "attributesList",
    "driveLetter",
    "driveType"
})
@XmlRootElement(name = "Windows_Volume", namespace = "http://cybox.mitre.org/objects#WinVolumeObject-2")
public class WindowsVolume
    extends VolumeObjectType
{

    @XmlElement(name = "Attributes_List")
    protected WindowsVolumeAttributesListType attributesList;
    @XmlElement(name = "Drive_Letter")
    protected StringObjectPropertyType driveLetter;
    @XmlElement(name = "Drive_Type")
    protected WindowsDriveType driveType;

    /**
     * Gets the value of the attributesList property.
     * 
     * @return
     *     possible object is
     *     {@link WindowsVolumeAttributesListType }
     *     
     */
    public WindowsVolumeAttributesListType getAttributesList() {
        return attributesList;
    }

    /**
     * Sets the value of the attributesList property.
     * 
     * @param value
     *     allowed object is
     *     {@link WindowsVolumeAttributesListType }
     *     
     */
    public void setAttributesList(WindowsVolumeAttributesListType value) {
        this.attributesList = value;
    }

    /**
     * Gets the value of the driveLetter property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getDriveLetter() {
        return driveLetter;
    }

    /**
     * Sets the value of the driveLetter property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setDriveLetter(StringObjectPropertyType value) {
        this.driveLetter = value;
    }

    /**
     * Gets the value of the driveType property.
     * 
     * @return
     *     possible object is
     *     {@link WindowsDriveType }
     *     
     */
    public WindowsDriveType getDriveType() {
        return driveType;
    }

    /**
     * Sets the value of the driveType property.
     * 
     * @param value
     *     allowed object is
     *     {@link WindowsDriveType }
     *     
     */
    public void setDriveType(WindowsDriveType value) {
        this.driveType = value;
    }

}
