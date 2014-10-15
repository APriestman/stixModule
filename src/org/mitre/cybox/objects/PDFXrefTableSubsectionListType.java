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


/**
 * The PDFXrefTableSubsectionListType captures a list of cross-reference table subsections.
 * 
 * <p>Java class for PDFXrefTableSubsectionListType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PDFXrefTableSubsectionListType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Subsection" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFXrefTableSubsectionType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PDFXrefTableSubsectionListType", namespace = "http://cybox.mitre.org/objects#PDFFileObject-1", propOrder = {
    "subsections"
})
public class PDFXrefTableSubsectionListType {

    @XmlElement(name = "Subsection", required = true)
    protected List<PDFXrefTableSubsectionType> subsections;

    /**
     * Gets the value of the subsections property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the subsections property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSubsections().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link PDFXrefTableSubsectionType }
     * 
     * 
     */
    public List<PDFXrefTableSubsectionType> getSubsections() {
        if (subsections == null) {
            subsections = new ArrayList<PDFXrefTableSubsectionType>();
        }
        return this.subsections;
    }

}
