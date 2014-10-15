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
 * The IDTEntryListType type specifies a listing of the entries in the Interrupt Descriptor Table (IDT). The IDT is specific to the I386 architecture, indicating where the Protected mode Interrupt Service Routines (ISR) are located. See http://wiki.osdev.org/Interrupt_Descriptor_Table.
 * 
 * <p>Java class for IDTEntryListType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IDTEntryListType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="IDT_Entry" type="{http://cybox.mitre.org/objects#WinKernelObject-2}IDTEntryType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IDTEntryListType", namespace = "http://cybox.mitre.org/objects#WinKernelObject-2", propOrder = {
    "idtEntries"
})
public class IDTEntryListType {

    @XmlElement(name = "IDT_Entry", required = true)
    protected List<IDTEntryType> idtEntries;

    /**
     * Gets the value of the idtEntries property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the idtEntries property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getIDTEntries().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link IDTEntryType }
     * 
     * 
     */
    public List<IDTEntryType> getIDTEntries() {
        if (idtEntries == null) {
            idtEntries = new ArrayList<IDTEntryType>();
        }
        return this.idtEntries;
    }

}
