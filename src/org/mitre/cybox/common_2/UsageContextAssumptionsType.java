//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.common_2;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The UsageContextAssumptionsType contains descriptions of the various relevant usage context assumptions for this tool.
 * 
 * <p>Java class for UsageContextAssumptionsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="UsageContextAssumptionsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Usage_Context_Assumption" type="{http://cybox.mitre.org/common-2}StructuredTextType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "UsageContextAssumptionsType", propOrder = {
    "usageContextAssumptions"
})
public class UsageContextAssumptionsType {

    @XmlElement(name = "Usage_Context_Assumption", required = true)
    protected List<StructuredTextType> usageContextAssumptions;

    /**
     * Gets the value of the usageContextAssumptions property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the usageContextAssumptions property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getUsageContextAssumptions().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link StructuredTextType }
     * 
     * 
     */
    public List<StructuredTextType> getUsageContextAssumptions() {
        if (usageContextAssumptions == null) {
            usageContextAssumptions = new ArrayList<StructuredTextType>();
        }
        return this.usageContextAssumptions;
    }

}
