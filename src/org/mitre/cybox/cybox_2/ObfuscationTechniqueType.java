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
import org.mitre.cybox.common_2.StructuredTextType;


/**
 * The ObfuscationTechniqueType enables the description of a single potential technique an attacker could leverage to obfuscate the observability of this Observable.
 * 
 * <p>Java class for ObfuscationTechniqueType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ObfuscationTechniqueType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Description" type="{http://cybox.mitre.org/common-2}StructuredTextType"/>
 *         &lt;element name="Observables" type="{http://cybox.mitre.org/cybox-2}ObservablesType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ObfuscationTechniqueType", propOrder = {
    "description",
    "observables"
})
public class ObfuscationTechniqueType {

    @XmlElement(name = "Description", required = true)
    protected StructuredTextType description;
    @XmlElement(name = "Observables")
    protected Observables observables;

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
     * Gets the value of the observables property.
     * 
     * @return
     *     possible object is
     *     {@link Observables }
     *     
     */
    public Observables getObservables() {
        return observables;
    }

    /**
     * Sets the value of the observables property.
     * 
     * @param value
     *     allowed object is
     *     {@link Observables }
     *     
     */
    public void setObservables(Observables value) {
        this.observables = value;
    }

}
