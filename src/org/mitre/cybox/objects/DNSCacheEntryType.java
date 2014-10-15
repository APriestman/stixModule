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
import org.mitre.cybox.common_2.PositiveIntegerObjectPropertyType;


/**
 * The DNSCacheEntryType type is intended to characterize a single entry in a system's DNS cache.
 * 
 * <p>Java class for DNSCacheEntryType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DNSCacheEntryType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="DNS_Entry" type="{http://cybox.mitre.org/objects#DNSRecordObject-2}DNSRecordObjectType" minOccurs="0"/>
 *         &lt;element name="TTL" type="{http://cybox.mitre.org/common-2}PositiveIntegerObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DNSCacheEntryType", namespace = "http://cybox.mitre.org/objects#DNSCacheObject-2", propOrder = {
    "dnsEntry",
    "ttl"
})
public class DNSCacheEntryType {

    @XmlElement(name = "DNS_Entry")
    protected DNSRecord dnsEntry;
    @XmlElement(name = "TTL")
    protected PositiveIntegerObjectPropertyType ttl;

    /**
     * Gets the value of the dnsEntry property.
     * 
     * @return
     *     possible object is
     *     {@link DNSRecord }
     *     
     */
    public DNSRecord getDNSEntry() {
        return dnsEntry;
    }

    /**
     * Sets the value of the dnsEntry property.
     * 
     * @param value
     *     allowed object is
     *     {@link DNSRecord }
     *     
     */
    public void setDNSEntry(DNSRecord value) {
        this.dnsEntry = value;
    }

    /**
     * Gets the value of the ttl property.
     * 
     * @return
     *     possible object is
     *     {@link PositiveIntegerObjectPropertyType }
     *     
     */
    public PositiveIntegerObjectPropertyType getTTL() {
        return ttl;
    }

    /**
     * Sets the value of the ttl property.
     * 
     * @param value
     *     allowed object is
     *     {@link PositiveIntegerObjectPropertyType }
     *     
     */
    public void setTTL(PositiveIntegerObjectPropertyType value) {
        this.ttl = value;
    }

}
