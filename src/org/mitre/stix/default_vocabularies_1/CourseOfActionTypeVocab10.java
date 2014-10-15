//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.stix.default_vocabularies_1;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;
import org.mitre.stix.common_1.ControlledVocabularyStringType;


/**
 * The CourseOfActionTypeVocab is the default STIX vocabulary for expressing types of courses of action.
 * 
 * <p>Java class for CourseOfActionTypeVocab-1.0 complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CourseOfActionTypeVocab-1.0">
 *   &lt;simpleContent>
 *     &lt;restriction base="&lt;http://stix.mitre.org/common-1>ControlledVocabularyStringType">
 *       &lt;attribute name="vocab_name" type="{http://www.w3.org/2001/XMLSchema}string" fixed="STIX Default Course Of Action Type Vocabulary" />
 *       &lt;attribute name="vocab_reference" type="{http://www.w3.org/2001/XMLSchema}anyURI" fixed="http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.0/stix_default_vocabularies.xsd#CourseOfActionTypeVocab-1.0" />
 *     &lt;/restriction>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CourseOfActionTypeVocab-1.0")
public class CourseOfActionTypeVocab10
    extends ControlledVocabularyStringType
{


}
