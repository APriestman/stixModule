//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.stix.default_vocabularies_1;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for PlanningAndOperationalSupportEnum-1.0.1.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="PlanningAndOperationalSupportEnum-1.0.1">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Data Exploitation"/>
 *     &lt;enumeration value="Data Exploitation - Analytic Support"/>
 *     &lt;enumeration value="Data Exploitation - Translation Support"/>
 *     &lt;enumeration value="Financial Resources"/>
 *     &lt;enumeration value="Financial Resources - Academic"/>
 *     &lt;enumeration value="Financial Resources - Commercial"/>
 *     &lt;enumeration value="Financial Resources - Government"/>
 *     &lt;enumeration value="Financial Resources - Hacktivist or Grassroot"/>
 *     &lt;enumeration value="Financial Resources - Non-Attributable Finance"/>
 *     &lt;enumeration value="Skill Development / Recruitment"/>
 *     &lt;enumeration value="Skill Development / Recruitment - Contracting and Hiring"/>
 *     &lt;enumeration value="Skill Development / Recruitment - Document Exploitation (DOCEX) Training"/>
 *     &lt;enumeration value="Skill Development / Recruitment - Internal Training"/>
 *     &lt;enumeration value="Skill Development / Recruitment - Military Programs"/>
 *     &lt;enumeration value="Skill Development / Recruitment - Security / Hacker Conferences"/>
 *     &lt;enumeration value="Skill Development / Recruitment - Underground Forums"/>
 *     &lt;enumeration value="Skill Development / Recruitment - University Programs"/>
 *     &lt;enumeration value="Planning"/>
 *     &lt;enumeration value="Planning - Operational Cover Plan"/>
 *     &lt;enumeration value="Planning - Open-Source Intelligence (OSINT) Gathering"/>
 *     &lt;enumeration value="Planning - Pre-Operational Surveillance and Reconnaissance"/>
 *     &lt;enumeration value="Planning - Target Selection"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "PlanningAndOperationalSupportEnum-1.0.1")
@XmlEnum
public enum PlanningAndOperationalSupportEnum101 {

    @XmlEnumValue("Data Exploitation")
    DATA_EXPLOITATION("Data Exploitation"),
    @XmlEnumValue("Data Exploitation - Analytic Support")
    DATA_EXPLOITATION_ANALYTIC_SUPPORT("Data Exploitation - Analytic Support"),
    @XmlEnumValue("Data Exploitation - Translation Support")
    DATA_EXPLOITATION_TRANSLATION_SUPPORT("Data Exploitation - Translation Support"),
    @XmlEnumValue("Financial Resources")
    FINANCIAL_RESOURCES("Financial Resources"),
    @XmlEnumValue("Financial Resources - Academic")
    FINANCIAL_RESOURCES_ACADEMIC("Financial Resources - Academic"),
    @XmlEnumValue("Financial Resources - Commercial")
    FINANCIAL_RESOURCES_COMMERCIAL("Financial Resources - Commercial"),
    @XmlEnumValue("Financial Resources - Government")
    FINANCIAL_RESOURCES_GOVERNMENT("Financial Resources - Government"),
    @XmlEnumValue("Financial Resources - Hacktivist or Grassroot")
    FINANCIAL_RESOURCES_HACKTIVIST_OR_GRASSROOT("Financial Resources - Hacktivist or Grassroot"),
    @XmlEnumValue("Financial Resources - Non-Attributable Finance")
    FINANCIAL_RESOURCES_NON_ATTRIBUTABLE_FINANCE("Financial Resources - Non-Attributable Finance"),
    @XmlEnumValue("Skill Development / Recruitment")
    SKILL_DEVELOPMENT_RECRUITMENT("Skill Development / Recruitment"),
    @XmlEnumValue("Skill Development / Recruitment - Contracting and Hiring")
    SKILL_DEVELOPMENT_RECRUITMENT_CONTRACTING_AND_HIRING("Skill Development / Recruitment - Contracting and Hiring"),
    @XmlEnumValue("Skill Development / Recruitment - Document Exploitation (DOCEX) Training")
    SKILL_DEVELOPMENT_RECRUITMENT_DOCUMENT_EXPLOITATION_DOCEX_TRAINING("Skill Development / Recruitment - Document Exploitation (DOCEX) Training"),
    @XmlEnumValue("Skill Development / Recruitment - Internal Training")
    SKILL_DEVELOPMENT_RECRUITMENT_INTERNAL_TRAINING("Skill Development / Recruitment - Internal Training"),
    @XmlEnumValue("Skill Development / Recruitment - Military Programs")
    SKILL_DEVELOPMENT_RECRUITMENT_MILITARY_PROGRAMS("Skill Development / Recruitment - Military Programs"),
    @XmlEnumValue("Skill Development / Recruitment - Security / Hacker Conferences")
    SKILL_DEVELOPMENT_RECRUITMENT_SECURITY_HACKER_CONFERENCES("Skill Development / Recruitment - Security / Hacker Conferences"),
    @XmlEnumValue("Skill Development / Recruitment - Underground Forums")
    SKILL_DEVELOPMENT_RECRUITMENT_UNDERGROUND_FORUMS("Skill Development / Recruitment - Underground Forums"),
    @XmlEnumValue("Skill Development / Recruitment - University Programs")
    SKILL_DEVELOPMENT_RECRUITMENT_UNIVERSITY_PROGRAMS("Skill Development / Recruitment - University Programs"),
    @XmlEnumValue("Planning")
    PLANNING("Planning"),
    @XmlEnumValue("Planning - Operational Cover Plan")
    PLANNING_OPERATIONAL_COVER_PLAN("Planning - Operational Cover Plan"),
    @XmlEnumValue("Planning - Open-Source Intelligence (OSINT) Gathering")
    PLANNING_OPEN_SOURCE_INTELLIGENCE_OSINT_GATHERING("Planning - Open-Source Intelligence (OSINT) Gathering"),
    @XmlEnumValue("Planning - Pre-Operational Surveillance and Reconnaissance")
    PLANNING_PRE_OPERATIONAL_SURVEILLANCE_AND_RECONNAISSANCE("Planning - Pre-Operational Surveillance and Reconnaissance"),
    @XmlEnumValue("Planning - Target Selection")
    PLANNING_TARGET_SELECTION("Planning - Target Selection");
    private final String value;

    PlanningAndOperationalSupportEnum101(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static PlanningAndOperationalSupportEnum101 fromValue(String v) {
        for (PlanningAndOperationalSupportEnum101 c: PlanningAndOperationalSupportEnum101 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
