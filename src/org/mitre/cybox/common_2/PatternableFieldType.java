//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.common_2;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * The PatternableFieldType is a grouping of attributes applicable to defining patterns on a specific field.
 * 
 * <p>Java class for PatternableFieldType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PatternableFieldType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>anySimpleType">
 *       &lt;attGroup ref="{http://cybox.mitre.org/common-2}PatternFieldGroup"/>
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PatternableFieldType", propOrder = {
    "value"
})
@XmlSeeAlso({
    ControlledVocabularyStringType.class
})
public class PatternableFieldType {

    @XmlValue
    @XmlSchemaType(name = "anySimpleType")
    protected Object value;
    @XmlAttribute(name = "condition")
    protected ConditionTypeEnum condition;
    @XmlAttribute(name = "is_case_sensitive")
    protected Boolean isCaseSensitive;
    @XmlAttribute(name = "apply_condition")
    protected ConditionApplicationEnum applyCondition;
    @XmlAttribute(name = "delimiter")
    protected String delimiter;
    @XmlAttribute(name = "bit_mask")
    @XmlJavaTypeAdapter(HexBinaryAdapter.class)
    @XmlSchemaType(name = "hexBinary")
    protected byte[] bitMask;
    @XmlAttribute(name = "pattern_type")
    protected PatternTypeEnum patternType;
    @XmlAttribute(name = "regex_syntax")
    protected String regexSyntax;
    @XmlAttribute(name = "has_changed")
    protected Boolean hasChanged;
    @XmlAttribute(name = "trend")
    protected Boolean trend;

    /**
     * Gets the value of the value property.
     * 
     * @return
     *     possible object is
     *     {@link Object }
     *     
     */
    public Object getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     * 
     * @param value
     *     allowed object is
     *     {@link Object }
     *     
     */
    public void setValue(Object value) {
        this.value = value;
    }

    /**
     * Gets the value of the condition property.
     * 
     * @return
     *     possible object is
     *     {@link ConditionTypeEnum }
     *     
     */
    public ConditionTypeEnum getCondition() {
        return condition;
    }

    /**
     * Sets the value of the condition property.
     * 
     * @param value
     *     allowed object is
     *     {@link ConditionTypeEnum }
     *     
     */
    public void setCondition(ConditionTypeEnum value) {
        this.condition = value;
    }

    /**
     * Gets the value of the isCaseSensitive property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public boolean isIsCaseSensitive() {
        if (isCaseSensitive == null) {
            return true;
        } else {
            return isCaseSensitive;
        }
    }

    /**
     * Sets the value of the isCaseSensitive property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setIsCaseSensitive(Boolean value) {
        this.isCaseSensitive = value;
    }

    /**
     * Gets the value of the applyCondition property.
     * 
     * @return
     *     possible object is
     *     {@link ConditionApplicationEnum }
     *     
     */
    public ConditionApplicationEnum getApplyCondition() {
        if (applyCondition == null) {
            return ConditionApplicationEnum.ANY;
        } else {
            return applyCondition;
        }
    }

    /**
     * Sets the value of the applyCondition property.
     * 
     * @param value
     *     allowed object is
     *     {@link ConditionApplicationEnum }
     *     
     */
    public void setApplyCondition(ConditionApplicationEnum value) {
        this.applyCondition = value;
    }

    /**
     * Gets the value of the delimiter property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDelimiter() {
        if (delimiter == null) {
            return "##comma##";
        } else {
            return delimiter;
        }
    }

    /**
     * Sets the value of the delimiter property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDelimiter(String value) {
        this.delimiter = value;
    }

    /**
     * Gets the value of the bitMask property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public byte[] getBitMask() {
        return bitMask;
    }

    /**
     * Sets the value of the bitMask property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setBitMask(byte[] value) {
        this.bitMask = value;
    }

    /**
     * Gets the value of the patternType property.
     * 
     * @return
     *     possible object is
     *     {@link PatternTypeEnum }
     *     
     */
    public PatternTypeEnum getPatternType() {
        return patternType;
    }

    /**
     * Sets the value of the patternType property.
     * 
     * @param value
     *     allowed object is
     *     {@link PatternTypeEnum }
     *     
     */
    public void setPatternType(PatternTypeEnum value) {
        this.patternType = value;
    }

    /**
     * Gets the value of the regexSyntax property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRegexSyntax() {
        return regexSyntax;
    }

    /**
     * Sets the value of the regexSyntax property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRegexSyntax(String value) {
        this.regexSyntax = value;
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

    /**
     * Gets the value of the trend property.
     * 
     * @return
     *     possible object is
     *     {@link Boolean }
     *     
     */
    public Boolean isTrend() {
        return trend;
    }

    /**
     * Sets the value of the trend property.
     * 
     * @param value
     *     allowed object is
     *     {@link Boolean }
     *     
     */
    public void setTrend(Boolean value) {
        this.trend = value;
    }

}
