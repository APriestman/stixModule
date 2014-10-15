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
import org.mitre.cybox.common_2.PlatformSpecificationType;


/**
 * These elements of a YAF record correspond to the flow generally or to the forward portion of the flow. Elements common to all network flow objects are defined in the NetworkFlowLabelType (src ip address, ingress/egress interface).
 * 
 * <p>Java class for YAFFlowType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="YAFFlowType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Flow_Start_Milliseconds" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Flow_End_Milliseconds" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Octet_Total_Count" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Packet_Total_Count" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Flow_End_Reason" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="SiLK_App_Label" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Payload_Entropy" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="ML_App_Label" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="TCP_Flow" type="{http://cybox.mitre.org/objects#NetworkFlowObject-2}YAFTCPFlowType" minOccurs="0"/>
 *         &lt;element name="Vlan_ID_MAC_Addr" type="{http://cybox.mitre.org/objects#AddressObject-2}AddressObjectType" minOccurs="0"/>
 *         &lt;element name="Passive_OS_Fingerprinting" type="{http://cybox.mitre.org/common-2}PlatformSpecificationType" minOccurs="0"/>
 *         &lt;element name="First_Packet_Banner" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Second_Packet_Banner" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="N_Bytes_Payload" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "YAFFlowType", namespace = "http://cybox.mitre.org/objects#NetworkFlowObject-2", propOrder = {
    "flowStartMilliseconds",
    "flowEndMilliseconds",
    "octetTotalCount",
    "packetTotalCount",
    "flowEndReason",
    "siLKAppLabel",
    "payloadEntropy",
    "mlAppLabel",
    "tcpFlow",
    "vlanIDMACAddr",
    "passiveOSFingerprinting",
    "firstPacketBanner",
    "secondPacketBanner",
    "nBytesPayload"
})
public class YAFFlowType {

    @XmlElement(name = "Flow_Start_Milliseconds")
    protected IntegerObjectPropertyType flowStartMilliseconds;
    @XmlElement(name = "Flow_End_Milliseconds")
    protected IntegerObjectPropertyType flowEndMilliseconds;
    @XmlElement(name = "Octet_Total_Count")
    protected IntegerObjectPropertyType octetTotalCount;
    @XmlElement(name = "Packet_Total_Count")
    protected IntegerObjectPropertyType packetTotalCount;
    @XmlElement(name = "Flow_End_Reason")
    protected HexBinaryObjectPropertyType flowEndReason;
    @XmlElement(name = "SiLK_App_Label")
    protected IntegerObjectPropertyType siLKAppLabel;
    @XmlElement(name = "Payload_Entropy")
    protected IntegerObjectPropertyType payloadEntropy;
    @XmlElement(name = "ML_App_Label")
    protected HexBinaryObjectPropertyType mlAppLabel;
    @XmlElement(name = "TCP_Flow")
    protected YAFTCPFlowType tcpFlow;
    @XmlElement(name = "Vlan_ID_MAC_Addr")
    protected Address vlanIDMACAddr;
    @XmlElement(name = "Passive_OS_Fingerprinting")
    protected PlatformSpecificationType passiveOSFingerprinting;
    @XmlElement(name = "First_Packet_Banner")
    protected HexBinaryObjectPropertyType firstPacketBanner;
    @XmlElement(name = "Second_Packet_Banner")
    protected HexBinaryObjectPropertyType secondPacketBanner;
    @XmlElement(name = "N_Bytes_Payload")
    protected HexBinaryObjectPropertyType nBytesPayload;

    /**
     * Gets the value of the flowStartMilliseconds property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getFlowStartMilliseconds() {
        return flowStartMilliseconds;
    }

    /**
     * Sets the value of the flowStartMilliseconds property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setFlowStartMilliseconds(IntegerObjectPropertyType value) {
        this.flowStartMilliseconds = value;
    }

    /**
     * Gets the value of the flowEndMilliseconds property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getFlowEndMilliseconds() {
        return flowEndMilliseconds;
    }

    /**
     * Sets the value of the flowEndMilliseconds property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setFlowEndMilliseconds(IntegerObjectPropertyType value) {
        this.flowEndMilliseconds = value;
    }

    /**
     * Gets the value of the octetTotalCount property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getOctetTotalCount() {
        return octetTotalCount;
    }

    /**
     * Sets the value of the octetTotalCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setOctetTotalCount(IntegerObjectPropertyType value) {
        this.octetTotalCount = value;
    }

    /**
     * Gets the value of the packetTotalCount property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getPacketTotalCount() {
        return packetTotalCount;
    }

    /**
     * Sets the value of the packetTotalCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setPacketTotalCount(IntegerObjectPropertyType value) {
        this.packetTotalCount = value;
    }

    /**
     * Gets the value of the flowEndReason property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getFlowEndReason() {
        return flowEndReason;
    }

    /**
     * Sets the value of the flowEndReason property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setFlowEndReason(HexBinaryObjectPropertyType value) {
        this.flowEndReason = value;
    }

    /**
     * Gets the value of the siLKAppLabel property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getSiLKAppLabel() {
        return siLKAppLabel;
    }

    /**
     * Sets the value of the siLKAppLabel property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setSiLKAppLabel(IntegerObjectPropertyType value) {
        this.siLKAppLabel = value;
    }

    /**
     * Gets the value of the payloadEntropy property.
     * 
     * @return
     *     possible object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public IntegerObjectPropertyType getPayloadEntropy() {
        return payloadEntropy;
    }

    /**
     * Sets the value of the payloadEntropy property.
     * 
     * @param value
     *     allowed object is
     *     {@link IntegerObjectPropertyType }
     *     
     */
    public void setPayloadEntropy(IntegerObjectPropertyType value) {
        this.payloadEntropy = value;
    }

    /**
     * Gets the value of the mlAppLabel property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getMLAppLabel() {
        return mlAppLabel;
    }

    /**
     * Sets the value of the mlAppLabel property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setMLAppLabel(HexBinaryObjectPropertyType value) {
        this.mlAppLabel = value;
    }

    /**
     * Gets the value of the tcpFlow property.
     * 
     * @return
     *     possible object is
     *     {@link YAFTCPFlowType }
     *     
     */
    public YAFTCPFlowType getTCPFlow() {
        return tcpFlow;
    }

    /**
     * Sets the value of the tcpFlow property.
     * 
     * @param value
     *     allowed object is
     *     {@link YAFTCPFlowType }
     *     
     */
    public void setTCPFlow(YAFTCPFlowType value) {
        this.tcpFlow = value;
    }

    /**
     * Gets the value of the vlanIDMACAddr property.
     * 
     * @return
     *     possible object is
     *     {@link Address }
     *     
     */
    public Address getVlanIDMACAddr() {
        return vlanIDMACAddr;
    }

    /**
     * Sets the value of the vlanIDMACAddr property.
     * 
     * @param value
     *     allowed object is
     *     {@link Address }
     *     
     */
    public void setVlanIDMACAddr(Address value) {
        this.vlanIDMACAddr = value;
    }

    /**
     * Gets the value of the passiveOSFingerprinting property.
     * 
     * @return
     *     possible object is
     *     {@link PlatformSpecificationType }
     *     
     */
    public PlatformSpecificationType getPassiveOSFingerprinting() {
        return passiveOSFingerprinting;
    }

    /**
     * Sets the value of the passiveOSFingerprinting property.
     * 
     * @param value
     *     allowed object is
     *     {@link PlatformSpecificationType }
     *     
     */
    public void setPassiveOSFingerprinting(PlatformSpecificationType value) {
        this.passiveOSFingerprinting = value;
    }

    /**
     * Gets the value of the firstPacketBanner property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getFirstPacketBanner() {
        return firstPacketBanner;
    }

    /**
     * Sets the value of the firstPacketBanner property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setFirstPacketBanner(HexBinaryObjectPropertyType value) {
        this.firstPacketBanner = value;
    }

    /**
     * Gets the value of the secondPacketBanner property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getSecondPacketBanner() {
        return secondPacketBanner;
    }

    /**
     * Sets the value of the secondPacketBanner property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setSecondPacketBanner(HexBinaryObjectPropertyType value) {
        this.secondPacketBanner = value;
    }

    /**
     * Gets the value of the nBytesPayload property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getNBytesPayload() {
        return nBytesPayload;
    }

    /**
     * Sets the value of the nBytesPayload property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setNBytesPayload(HexBinaryObjectPropertyType value) {
        this.nBytesPayload = value;
    }

}
