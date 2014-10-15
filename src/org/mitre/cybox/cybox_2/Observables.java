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
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.MeasureSourceType;


/**
 * The ObservablesType is a type representing a collection of cyber observables.
 * 
 * <p>Java class for ObservablesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ObservablesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Observable_Package_Source" type="{http://cybox.mitre.org/common-2}MeasureSourceType" minOccurs="0"/>
 *         &lt;element ref="{http://cybox.mitre.org/cybox-2}Observable" maxOccurs="unbounded"/>
 *         &lt;element name="Pools" type="{http://cybox.mitre.org/cybox-2}PoolsType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="cybox_major_version" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="cybox_minor_version" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="cybox_update_version" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ObservablesType", propOrder = {
    "observablePackageSource",
    "observables",
    "pools"
})
@XmlRootElement(name = "Observables")
public class Observables {

    @XmlElement(name = "Observable_Package_Source")
    protected MeasureSourceType observablePackageSource;
    @XmlElement(name = "Observable", required = true)
    protected List<Observable> observables;
    @XmlElement(name = "Pools")
    protected PoolsType pools;
    @XmlAttribute(name = "cybox_major_version", required = true)
    protected String cyboxMajorVersion;
    @XmlAttribute(name = "cybox_minor_version", required = true)
    protected String cyboxMinorVersion;
    @XmlAttribute(name = "cybox_update_version")
    protected String cyboxUpdateVersion;

    /**
     * Gets the value of the observablePackageSource property.
     * 
     * @return
     *     possible object is
     *     {@link MeasureSourceType }
     *     
     */
    public MeasureSourceType getObservablePackageSource() {
        return observablePackageSource;
    }

    /**
     * Sets the value of the observablePackageSource property.
     * 
     * @param value
     *     allowed object is
     *     {@link MeasureSourceType }
     *     
     */
    public void setObservablePackageSource(MeasureSourceType value) {
        this.observablePackageSource = value;
    }

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
     * Gets the value of the pools property.
     * 
     * @return
     *     possible object is
     *     {@link PoolsType }
     *     
     */
    public PoolsType getPools() {
        return pools;
    }

    /**
     * Sets the value of the pools property.
     * 
     * @param value
     *     allowed object is
     *     {@link PoolsType }
     *     
     */
    public void setPools(PoolsType value) {
        this.pools = value;
    }

    /**
     * Gets the value of the cyboxMajorVersion property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCyboxMajorVersion() {
        return cyboxMajorVersion;
    }

    /**
     * Sets the value of the cyboxMajorVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCyboxMajorVersion(String value) {
        this.cyboxMajorVersion = value;
    }

    /**
     * Gets the value of the cyboxMinorVersion property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCyboxMinorVersion() {
        return cyboxMinorVersion;
    }

    /**
     * Sets the value of the cyboxMinorVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCyboxMinorVersion(String value) {
        this.cyboxMinorVersion = value;
    }

    /**
     * Gets the value of the cyboxUpdateVersion property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCyboxUpdateVersion() {
        return cyboxUpdateVersion;
    }

    /**
     * Sets the value of the cyboxUpdateVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCyboxUpdateVersion(String value) {
        this.cyboxUpdateVersion = value;
    }

}
