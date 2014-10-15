//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.cybox_2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import javax.xml.namespace.QName;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;
import org.mitre.cybox.common_2.LocationType;
import org.mitre.cybox.common_2.MeasureSourceType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.StructuredTextType;


/**
 * The ObjectType is a complex type representing the characteristics of a specific cyber-relevant object (e.g. a file, a registry key or a process).
 * 
 * <p>Java class for ObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ObjectType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="State" type="{http://cybox.mitre.org/common-2}ControlledVocabularyStringType" minOccurs="0"/>
 *         &lt;element name="Description" type="{http://cybox.mitre.org/common-2}StructuredTextType" minOccurs="0"/>
 *         &lt;element name="Properties" type="{http://cybox.mitre.org/common-2}ObjectPropertiesType" minOccurs="0"/>
 *         &lt;element name="Domain_Specific_Object_Properties" type="{http://cybox.mitre.org/cybox-2}DomainSpecificObjectPropertiesType" minOccurs="0"/>
 *         &lt;element name="Location" type="{http://cybox.mitre.org/common-2}LocationType" minOccurs="0"/>
 *         &lt;element name="Related_Objects" type="{http://cybox.mitre.org/cybox-2}RelatedObjectsType" minOccurs="0"/>
 *         &lt;element name="Defined_Effect" type="{http://cybox.mitre.org/cybox-2}DefinedEffectType" minOccurs="0"/>
 *         &lt;element name="Discovery_Method" type="{http://cybox.mitre.org/common-2}MeasureSourceType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="id" type="{http://www.w3.org/2001/XMLSchema}QName" />
 *       &lt;attribute name="idref" type="{http://www.w3.org/2001/XMLSchema}QName" />
 *       &lt;attribute name="has_changed" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ObjectType", propOrder = {
    "state",
    "description",
    "properties",
    "domainSpecificObjectProperties",
    "location",
    "relatedObjects",
    "definedEffect",
    "discoveryMethod"
})
@XmlSeeAlso({
    RelatedObjectType.class,
    AssociatedObjectType.class
})
public class ObjectType {

    @XmlElement(name = "State")
    protected ControlledVocabularyStringType state;
    @XmlElement(name = "Description")
    protected StructuredTextType description;
    @XmlElement(name = "Properties")
    protected ObjectPropertiesType properties;
    @XmlElement(name = "Domain_Specific_Object_Properties")
    protected DomainSpecificObjectPropertiesType domainSpecificObjectProperties;
    @XmlElement(name = "Location")
    protected LocationType location;
    @XmlElement(name = "Related_Objects")
    protected RelatedObjectsType relatedObjects;
    @XmlElement(name = "Defined_Effect")
    protected DefinedEffectType definedEffect;
    @XmlElement(name = "Discovery_Method")
    protected MeasureSourceType discoveryMethod;
    @XmlAttribute(name = "id")
    protected QName id;
    @XmlAttribute(name = "idref")
    protected QName idref;
    @XmlAttribute(name = "has_changed")
    protected Boolean hasChanged;

    /**
     * Gets the value of the state property.
     * 
     * @return
     *     possible object is
     *     {@link ControlledVocabularyStringType }
     *     
     */
    public ControlledVocabularyStringType getState() {
        return state;
    }

    /**
     * Sets the value of the state property.
     * 
     * @param value
     *     allowed object is
     *     {@link ControlledVocabularyStringType }
     *     
     */
    public void setState(ControlledVocabularyStringType value) {
        this.state = value;
    }

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
     * Gets the value of the properties property.
     * 
     * @return
     *     possible object is
     *     {@link ObjectPropertiesType }
     *     
     */
    public ObjectPropertiesType getProperties() {
        return properties;
    }

    /**
     * Sets the value of the properties property.
     * 
     * @param value
     *     allowed object is
     *     {@link ObjectPropertiesType }
     *     
     */
    public void setProperties(ObjectPropertiesType value) {
        this.properties = value;
    }

    /**
     * Gets the value of the domainSpecificObjectProperties property.
     * 
     * @return
     *     possible object is
     *     {@link DomainSpecificObjectPropertiesType }
     *     
     */
    public DomainSpecificObjectPropertiesType getDomainSpecificObjectProperties() {
        return domainSpecificObjectProperties;
    }

    /**
     * Sets the value of the domainSpecificObjectProperties property.
     * 
     * @param value
     *     allowed object is
     *     {@link DomainSpecificObjectPropertiesType }
     *     
     */
    public void setDomainSpecificObjectProperties(DomainSpecificObjectPropertiesType value) {
        this.domainSpecificObjectProperties = value;
    }

    /**
     * Gets the value of the location property.
     * 
     * @return
     *     possible object is
     *     {@link LocationType }
     *     
     */
    public LocationType getLocation() {
        return location;
    }

    /**
     * Sets the value of the location property.
     * 
     * @param value
     *     allowed object is
     *     {@link LocationType }
     *     
     */
    public void setLocation(LocationType value) {
        this.location = value;
    }

    /**
     * Gets the value of the relatedObjects property.
     * 
     * @return
     *     possible object is
     *     {@link RelatedObjectsType }
     *     
     */
    public RelatedObjectsType getRelatedObjects() {
        return relatedObjects;
    }

    /**
     * Sets the value of the relatedObjects property.
     * 
     * @param value
     *     allowed object is
     *     {@link RelatedObjectsType }
     *     
     */
    public void setRelatedObjects(RelatedObjectsType value) {
        this.relatedObjects = value;
    }

    /**
     * Gets the value of the definedEffect property.
     * 
     * @return
     *     possible object is
     *     {@link DefinedEffectType }
     *     
     */
    public DefinedEffectType getDefinedEffect() {
        return definedEffect;
    }

    /**
     * Sets the value of the definedEffect property.
     * 
     * @param value
     *     allowed object is
     *     {@link DefinedEffectType }
     *     
     */
    public void setDefinedEffect(DefinedEffectType value) {
        this.definedEffect = value;
    }

    /**
     * Gets the value of the discoveryMethod property.
     * 
     * @return
     *     possible object is
     *     {@link MeasureSourceType }
     *     
     */
    public MeasureSourceType getDiscoveryMethod() {
        return discoveryMethod;
    }

    /**
     * Sets the value of the discoveryMethod property.
     * 
     * @param value
     *     allowed object is
     *     {@link MeasureSourceType }
     *     
     */
    public void setDiscoveryMethod(MeasureSourceType value) {
        this.discoveryMethod = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link QName }
     *     
     */
    public QName getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link QName }
     *     
     */
    public void setId(QName value) {
        this.id = value;
    }

    /**
     * Gets the value of the idref property.
     * 
     * @return
     *     possible object is
     *     {@link QName }
     *     
     */
    public QName getIdref() {
        return idref;
    }

    /**
     * Sets the value of the idref property.
     * 
     * @param value
     *     allowed object is
     *     {@link QName }
     *     
     */
    public void setIdref(QName value) {
        this.idref = value;
    }

    /**
     * Gets the value of the hasChanged property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isHasChanged() {
        return hasChanged;
    }

    /**
     * Sets the value of the hasChanged property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setHasChanged(Boolean value) {
        this.hasChanged = value;
    }

}
