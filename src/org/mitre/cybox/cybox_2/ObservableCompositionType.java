//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.cybox_2;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The ObservablesCompositionType enables the specification of higher-order composite observables composed of logical combinations of other observables.
 * 
 * <p>Java class for ObservableCompositionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ObservableCompositionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence minOccurs="0">
 *         &lt;element name="Observable" type="{http://cybox.mitre.org/cybox-2}ObservableType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="operator" use="required" type="{http://cybox.mitre.org/cybox-2}OperatorTypeEnum" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ObservableCompositionType", propOrder = {
    "observables"
})
public class ObservableCompositionType {

    @XmlElement(name = "Observable")
    protected List<Observable> observables;
    @XmlAttribute(name = "operator", required = true)
    protected OperatorTypeEnum operator;

    /**
     * Gets the value of the observables property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the observables property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getObservables().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Observable }
     * 
     * 
     */
    public List<Observable> getObservables() {
        if (observables == null) {
            observables = new ArrayList<Observable>();
        }
        return this.observables;
    }

    /**
     * Gets the value of the operator property.
     * 
     * @return
     *     possible object is
     *     {@link OperatorTypeEnum }
     *     
     */
    public OperatorTypeEnum getOperator() {
        return operator;
    }

    /**
     * Sets the value of the operator property.
     * 
     * @param value
     *     allowed object is
     *     {@link OperatorTypeEnum }
     *     
     */
    public void setOperator(OperatorTypeEnum value) {
        this.operator = value;
    }

}
