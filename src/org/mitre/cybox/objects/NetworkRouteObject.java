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
import org.mitre.cybox.common_2.DurationObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.StructuredTextType;


/**
 * The NetRouteObjectType type is intended to characterize a specific network route.
 * 
 * <p>Java class for NetRouteObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="NetRouteObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Description" type="{http://cybox.mitre.org/common-2}StructuredTextType" minOccurs="0"/>
 *         &lt;element name="Network_Route_Entries" type="{http://cybox.mitre.org/objects#NetworkRouteObject-2}NetworkRouteEntriesType" minOccurs="0"/>
 *         &lt;element name="Preferred_Lifetime" type="{http://cybox.mitre.org/common-2}DurationObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Valid_Lifetime" type="{http://cybox.mitre.org/common-2}DurationObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Route_Age" type="{http://cybox.mitre.org/common-2}DurationObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="is_ipv6" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="is_autoconfigure_address" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="is_immortal" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="is_loopback" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *       &lt;attribute name="is_publish" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "NetRouteObjectType", namespace = "http://cybox.mitre.org/objects#NetworkRouteObject-2", propOrder = {
    "description",
    "networkRouteEntries",
    "preferredLifetime",
    "validLifetime",
    "routeAge"
})
@XmlRootElement(name = "Network_Route_Object", namespace = "http://cybox.mitre.org/objects#NetworkRouteObject-2")
public class NetworkRouteObject
    extends ObjectPropertiesType
{

    @XmlElement(name = "Description")
    protected StructuredTextType description;
    @XmlElement(name = "Network_Route_Entries")
    protected NetworkRouteEntriesType networkRouteEntries;
    @XmlElement(name = "Preferred_Lifetime")
    protected DurationObjectPropertyType preferredLifetime;
    @XmlElement(name = "Valid_Lifetime")
    protected DurationObjectPropertyType validLifetime;
    @XmlElement(name = "Route_Age")
    protected DurationObjectPropertyType routeAge;
    @XmlAttribute(name = "is_ipv6")
    protected Boolean isIpv6;
    @XmlAttribute(name = "is_autoconfigure_address")
    protected Boolean isAutoconfigureAddress;
    @XmlAttribute(name = "is_immortal")
    protected Boolean isImmortal;
    @XmlAttribute(name = "is_loopback")
    protected Boolean isLoopback;
    @XmlAttribute(name = "is_publish")
    protected Boolean isPublish;

    /**
     * Gets the value of the description property.
     * 
     * @return
     *     possible object is
     *     {@link StructuredTextType }
     *     
     */
    public StructuredTextType getDescription() {
        return description;
    }

    /**
     * Sets the value of the description property.
     * 
     * @param value
     *     allowed object is
     *     {@link StructuredTextType }
     *     
     */
    public void setDescription(StructuredTextType value) {
        this.description = value;
    }

    /**
     * Gets the value of the networkRouteEntries property.
     * 
     * @return
     *     possible object is
     *     {@link NetworkRouteEntriesType }
     *     
     */
    public NetworkRouteEntriesType getNetworkRouteEntries() {
        return networkRouteEntries;
    }

    /**
     * Sets the value of the networkRouteEntries property.
     * 
     * @param value
     *     allowed object is
     *     {@link NetworkRouteEntriesType }
     *     
     */
    public void setNetworkRouteEntries(NetworkRouteEntriesType value) {
        this.networkRouteEntries = value;
    }

    /**
     * Gets the value of the preferredLifetime property.
     * 
     * @return
     *     possible object is
     *     {@link DurationObjectPropertyType }
     *     
     */
    public DurationObjectPropertyType getPreferredLifetime() {
        return preferredLifetime;
    }

    /**
     * Sets the value of the preferredLifetime property.
     * 
     * @param value
     *     allowed object is
     *     {@link DurationObjectPropertyType }
     *     
     */
    public void setPreferredLifetime(DurationObjectPropertyType value) {
        this.preferredLifetime = value;
    }

    /**
     * Gets the value of the validLifetime property.
     * 
     * @return
     *     possible object is
     *     {@link DurationObjectPropertyType }
     *     
     */
    public DurationObjectPropertyType getValidLifetime() {
        return validLifetime;
    }

    /**
     * Sets the value of the validLifetime property.
     * 
     * @param value
     *     allowed object is
     *     {@link DurationObjectPropertyType }
     *     
     */
    public void setValidLifetime(DurationObjectPropertyType value) {
        this.validLifetime = value;
    }

    /**
     * Gets the value of the routeAge property.
     * 
     * @return
     *     possible object is
     *     {@link DurationObjectPropertyType }
     *     
     */
    public DurationObjectPropertyType getRouteAge() {
        return routeAge;
    }

    /**
     * Sets the value of the routeAge property.
     * 
     * @param value
     *     allowed object is
     *     {@link DurationObjectPropertyType }
     *     
     */
    public void setRouteAge(DurationObjectPropertyType value) {
        this.routeAge = value;
    }

    /**
     * Gets the value of the isIpv6 property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsIpv6() {
        return isIpv6;
    }

    /**
     * Sets the value of the isIpv6 property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsIpv6(Boolean value) {
        this.isIpv6 = value;
    }

    /**
     * Gets the value of the isAutoconfigureAddress property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsAutoconfigureAddress() {
        return isAutoconfigureAddress;
    }

    /**
     * Sets the value of the isAutoconfigureAddress property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsAutoconfigureAddress(Boolean value) {
        this.isAutoconfigureAddress = value;
    }

    /**
     * Gets the value of the isImmortal property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsImmortal() {
        return isImmortal;
    }

    /**
     * Sets the value of the isImmortal property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsImmortal(Boolean value) {
        this.isImmortal = value;
    }

    /**
     * Gets the value of the isLoopback property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsLoopback() {
        return isLoopback;
    }

    /**
     * Sets the value of the isLoopback property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsLoopback(Boolean value) {
        this.isLoopback = value;
    }

    /**
     * Gets the value of the isPublish property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isIsPublish() {
        return isPublish;
    }

    /**
     * Sets the value of the isPublish property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsPublish(Boolean value) {
        this.isPublish = value;
    }

}
