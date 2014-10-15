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


/**
 * only UDP and TCP defined to begin. Other protocols will be defined as necessary.
 * 
 * <p>Java class for TransportLayerType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TransportLayerType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element name="TCP" type="{http://cybox.mitre.org/objects#PacketObject-2}TCPType" minOccurs="0"/>
 *         &lt;element name="UDP" type="{http://cybox.mitre.org/objects#PacketObject-2}UDPType" minOccurs="0"/>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TransportLayerType", propOrder = {
    "udp",
    "tcp"
})
public class TransportLayerType {

    @XmlElement(name = "UDP")
    protected UDPType udp;
    @XmlElement(name = "TCP")
    protected TCPType tcp;

    /**
     * Gets the value of the udp property.
     * 
     * @return
     *     possible object is
     *     {@link UDPType }
     *     
     */
    public UDPType getUDP() {
        return udp;
    }

    /**
     * Sets the value of the udp property.
     * 
     * @param value
     *     allowed object is
     *     {@link UDPType }
     *     
     */
    public void setUDP(UDPType value) {
        this.udp = value;
    }

    /**
     * Gets the value of the tcp property.
     * 
     * @return
     *     possible object is
     *     {@link TCPType }
     *     
     */
    public TCPType getTCP() {
        return tcp;
    }

    /**
     * Sets the value of the tcp property.
     * 
     * @param value
     *     allowed object is
     *     {@link TCPType }
     *     
     */
    public void setTCP(TCPType value) {
        this.tcp = value;
    }

}
