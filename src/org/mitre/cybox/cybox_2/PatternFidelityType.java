//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.cybox_2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for PatternFidelityType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PatternFidelityType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Noisiness" type="{http://cybox.mitre.org/cybox-2}NoisinessEnum" minOccurs="0"/>
 *         &lt;element name="Ease_of_Evasion" type="{http://cybox.mitre.org/cybox-2}EaseOfObfuscationEnum" minOccurs="0"/>
 *         &lt;element name="Evasion_Techniques" type="{http://cybox.mitre.org/cybox-2}ObfuscationTechniquesType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PatternFidelityType", propOrder = {
    "noisiness",
    "easeOfEvasion",
    "evasionTechniques"
})
public class PatternFidelityType {

    @XmlElement(name = "Noisiness")
    protected NoisinessEnum noisiness;
    @XmlElement(name = "Ease_of_Evasion")
    protected EaseOfObfuscationEnum easeOfEvasion;
    @XmlElement(name = "Evasion_Techniques")
    protected ObfuscationTechniquesType evasionTechniques;

    /**
     * Gets the value of the noisiness property.
     * 
     * @return
     *     possible object is
     *     {@link NoisinessEnum }
     *     
     */
    public NoisinessEnum getNoisiness() {
        return noisiness;
    }

    /**
     * Sets the value of the noisiness property.
     * 
     * @param value
     *     allowed object is
     *     {@link NoisinessEnum }
     *     
     */
    public void setNoisiness(NoisinessEnum value) {
        this.noisiness = value;
    }

    /**
     * Gets the value of the easeOfEvasion property.
     * 
     * @return
     *     possible object is
     *     {@link EaseOfObfuscationEnum }
     *     
     */
    public EaseOfObfuscationEnum getEaseOfEvasion() {
        return easeOfEvasion;
    }

    /**
     * Sets the value of the easeOfEvasion property.
     * 
     * @param value
     *     allowed object is
     *     {@link EaseOfObfuscationEnum }
     *     
     */
    public void setEaseOfEvasion(EaseOfObfuscationEnum value) {
        this.easeOfEvasion = value;
    }

    /**
     * Gets the value of the evasionTechniques property.
     * 
     * @return
     *     possible object is
     *     {@link ObfuscationTechniquesType }
     *     
     */
    public ObfuscationTechniquesType getEvasionTechniques() {
        return evasionTechniques;
    }

    /**
     * Sets the value of the evasionTechniques property.
     * 
     * @param value
     *     allowed object is
     *     {@link ObfuscationTechniquesType }
     *     
     */
    public void setEvasionTechniques(ObfuscationTechniquesType value) {
        this.evasionTechniques = value;
    }

}
