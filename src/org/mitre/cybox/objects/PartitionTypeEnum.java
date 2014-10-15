//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for PartitionTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="PartitionTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="PARTITION_ENTRY_UNUSED"/>
 *     &lt;enumeration value="PARTITION_FAT_12"/>
 *     &lt;enumeration value="PARTITION_XENIX_1"/>
 *     &lt;enumeration value="PARTITION_XENIX_2"/>
 *     &lt;enumeration value="PARTITION_FAT_16"/>
 *     &lt;enumeration value="PARTITION_EXTENDED"/>
 *     &lt;enumeration value="PARTITION_HUGE"/>
 *     &lt;enumeration value="PARTITION_IFS"/>
 *     &lt;enumeration value="PARTITION_OS2BOOTMGR"/>
 *     &lt;enumeration value="PARTITION_FAT32"/>
 *     &lt;enumeration value="PARTITION_FAT32_XINT13"/>
 *     &lt;enumeration value="PARTITION_XINT13"/>
 *     &lt;enumeration value="PARTITION_XINT13_EXTENDED"/>
 *     &lt;enumeration value="PARTITION_PREP"/>
 *     &lt;enumeration value="PARTITION_LDM"/>
 *     &lt;enumeration value="PARTITION_UNIX"/>
 *     &lt;enumeration value="VALID_NTFT"/>
 *     &lt;enumeration value="PARTITION_NTFT"/>
 *     &lt;enumeration value="UNKNOWN"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "PartitionTypeEnum", namespace = "http://cybox.mitre.org/objects#DiskPartitionObject-2")
@XmlEnum
public enum PartitionTypeEnum {


    /**
     * Indicates an unused partition entry.
     * 
     */
    PARTITION_ENTRY_UNUSED("PARTITION_ENTRY_UNUSED"),

    /**
     * Indicates a FAT 12 partition.
     * 
     */
    PARTITION_FAT_12("PARTITION_FAT_12"),

    /**
     * Indicates a XENIX type 1 partition.
     * 
     */
    PARTITION_XENIX_1("PARTITION_XENIX_1"),

    /**
     * Indicates a XENIX type 2 partition.
     * 
     */
    PARTITION_XENIX_2("PARTITION_XENIX_2"),

    /**
     * Indicates a XENIX FAT 16 partition.
     * 
     */
    PARTITION_FAT_16("PARTITION_FAT_16"),

    /**
     * Indicates a XENIX extended partition.
     * 
     */
    PARTITION_EXTENDED("PARTITION_EXTENDED"),

    /**
     * Specifies an MS-DOS V4 huge partition. This value indicates that there is no Microsoft file system on the partition. Use this value when creating a logical volume.
     * 
     */
    PARTITION_HUGE("PARTITION_HUGE"),

    /**
     * Indicates an IFS partition.
     * 
     */
    PARTITION_IFS("PARTITION_IFS"),

    /**
     * Indicates an OS/2 boot manager partition.
     * 
     */
    @XmlEnumValue("PARTITION_OS2BOOTMGR")
    PARTITION_OS_2_BOOTMGR("PARTITION_OS2BOOTMGR"),

    /**
     * Indicates a FAT32 partition.
     * 
     */
    @XmlEnumValue("PARTITION_FAT32")
    PARTITION_FAT_32("PARTITION_FAT32"),

    /**
     * Indicates a FAT32 Extended-INT13 equivalent partition to the FAT32 partition.
     * 
     */
    @XmlEnumValue("PARTITION_FAT32_XINT13")
    PARTITION_FAT_32_XINT_13("PARTITION_FAT32_XINT13"),

    /**
     * Indicates an XINT13 partition.
     * 
     */
    @XmlEnumValue("PARTITION_XINT13")
    PARTITION_XINT_13("PARTITION_XINT13"),

    /**
     * Indicates an extended XINT13 partition.
     * 
     */
    @XmlEnumValue("PARTITION_XINT13_EXTENDED")
    PARTITION_XINT_13_EXTENDED("PARTITION_XINT13_EXTENDED"),

    /**
     * Indicates a PReP (Power PC Reference Platform) partition.
     * 
     */
    PARTITION_PREP("PARTITION_PREP"),

    /**
     * Indicates an LDM partition.
     * 
     */
    PARTITION_LDM("PARTITION_LDM"),

    /**
     * Indicates a UNIX partition.
     * 
     */
    PARTITION_UNIX("PARTITION_UNIX"),

    /**
     * Specifies a valid NTFT partition. The high bit of a partition type code indicates that a partition is part of an NTFT mirror or striped array.
     * 
     */
    VALID_NTFT("VALID_NTFT"),

    /**
     * Specifies an NTFT partition.
     * 
     */
    PARTITION_NTFT("PARTITION_NTFT"),

    /**
     * Refers to an unknown partition or a partition other than those listed.
     * 
     */
    UNKNOWN("UNKNOWN");
    private final String value;

    PartitionTypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static PartitionTypeEnum fromValue(String v) {
        for (PartitionTypeEnum c: PartitionTypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
