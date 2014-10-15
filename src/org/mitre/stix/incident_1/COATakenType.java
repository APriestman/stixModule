//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.stix.incident_1;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import org.mitre.stix.common_1.CourseOfActionBaseType;


/**
 * <p>Java class for COATakenType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="COATakenType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Time" type="{http://stix.mitre.org/Incident-1}COATimeType" minOccurs="0"/>
 *         &lt;element name="Contributors" type="{http://stix.mitre.org/Incident-1}ContributorsType" minOccurs="0"/>
 *         &lt;element name="Course_Of_Action" type="{http://stix.mitre.org/common-1}CourseOfActionBaseType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "COATakenType", propOrder = {
    "time",
    "contributors",
    "courseOfAction"
})
@XmlSeeAlso({
    COARequestedType.class
})
public class COATakenType {

    @XmlElement(name = "Time")
    protected COATimeType time;
    @XmlElement(name = "Contributors")
    protected ContributorsType contributors;
    @XmlElement(name = "Course_Of_Action")
    protected CourseOfActionBaseType courseOfAction;

    /**
     * Gets the value of the time property.
     * 
     * @return
     *     possible object is
     *     {@link COATimeType }
     *     
     */
    public COATimeType getTime() {
        return time;
    }

    /**
     * Sets the value of the time property.
     * 
     * @param value
     *     allowed object is
     *     {@link COATimeType }
     *     
     */
    public void setTime(COATimeType value) {
        this.time = value;
    }

    /**
     * Gets the value of the contributors property.
     * 
     * @return
     *     possible object is
     *     {@link ContributorsType }
     *     
     */
    public ContributorsType getContributors() {
        return contributors;
    }

    /**
     * Sets the value of the contributors property.
     * 
     * @param value
     *     allowed object is
     *     {@link ContributorsType }
     *     
     */
    public void setContributors(ContributorsType value) {
        this.contributors = value;
    }

    /**
     * Gets the value of the courseOfAction property.
     * 
     * @return
     *     possible object is
     *     {@link CourseOfActionBaseType }
     *     
     */
    public CourseOfActionBaseType getCourseOfAction() {
        return courseOfAction;
    }

    /**
     * Sets the value of the courseOfAction property.
     * 
     * @param value
     *     allowed object is
     *     {@link CourseOfActionBaseType }
     *     
     */
    public void setCourseOfAction(CourseOfActionBaseType value) {
        this.courseOfAction = value;
    }

}
