//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for WindowsDriveTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="WindowsDriveTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="DRIVE_UNKNOWN"/>
 *     &lt;enumeration value="DRIVE_NO_ROOT_DIR"/>
 *     &lt;enumeration value="DRIVE_REMOVABLE"/>
 *     &lt;enumeration value="DRIVE_FIXED"/>
 *     &lt;enumeration value="DRIVE_REMOTE"/>
 *     &lt;enumeration value="DRIVE_CDROM"/>
 *     &lt;enumeration value="DRIVE_RAMDISK"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "WindowsDriveTypeEnum", namespace = "http://cybox.mitre.org/objects#WinVolumeObject-2")
@XmlEnum
public enum WindowsDriveTypeEnum {


    /**
     * The drive type cannot be determined.
     * 
     */
    DRIVE_UNKNOWN,

    /**
     * The root path is invalid; for example, there is no volume mounted at the specified path.
     * 
     */
    DRIVE_NO_ROOT_DIR,

    /**
     * The drive has removable media; for example, a floppy drive, thumb drive, or flash card reader.
     * 
     */
    DRIVE_REMOVABLE,

    /**
     * The drive has fixed media; for example, a hard disk drive or flash drive.
     * 
     */
    DRIVE_FIXED,

    /**
     * The drive is a remote (network) drive.
     * 
     */
    DRIVE_REMOTE,

    /**
     * The drive is a CD-ROM drive.
     * 
     */
    DRIVE_CDROM,

    /**
     * The drive is a RAM disk.
     * 
     */
    DRIVE_RAMDISK;

    public String value() {
        return name();
    }

    public static WindowsDriveTypeEnum fromValue(String v) {
        return valueOf(v);
    }

}
