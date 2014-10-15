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
 * <p>Java class for SharedResourceTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="SharedResourceTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="STYPE_DISKTREE"/>
 *     &lt;enumeration value="STYPE_DISKTREE_SPECIAL"/>
 *     &lt;enumeration value="STYPE_DISKTREE_TEMPORARY"/>
 *     &lt;enumeration value="STYPE_DISKTREE_SPECIAL_TEMPORARY"/>
 *     &lt;enumeration value="STYPE_PRINTQ"/>
 *     &lt;enumeration value="STYPE_PRINTQ_SPECIAL"/>
 *     &lt;enumeration value="STYPE_PRINTQ_TEMPORARY"/>
 *     &lt;enumeration value="STYPE_PRINTQ_SPECIAL_TEMPORARY"/>
 *     &lt;enumeration value="STYPE_DEVICE"/>
 *     &lt;enumeration value="STYPE_DEVICE_SPECIAL"/>
 *     &lt;enumeration value="STYPE_DEVICE_TEMPORARY"/>
 *     &lt;enumeration value="STYPE_DEVICE_SPECIAL_TEMPORARY"/>
 *     &lt;enumeration value="STYPE_IPC"/>
 *     &lt;enumeration value="STYPE_IPC_SPECIAL"/>
 *     &lt;enumeration value="STYPE_IPC_TEMPORARY"/>
 *     &lt;enumeration value="STYPE_IPC_SPECIAL_TEMPORARY"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SharedResourceTypeEnum", namespace = "http://cybox.mitre.org/objects#WinNetworkShareObject-2")
@XmlEnum
public enum SharedResourceTypeEnum {


    /**
     * Specifies that the shared device is a disk drive.
     * 
     */
    STYPE_DISKTREE,

    /**
     * Specifies that the shared device is a disk drive with special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see http://msdn.microsoft.com/en-us/library/windows/desktop/bb525391(v=vs.85).aspx.
     * 
     */
    STYPE_DISKTREE_SPECIAL,

    /**
     * Specifies that the shared device is a disk drive and serves as a temporary share.
     * 
     */
    STYPE_DISKTREE_TEMPORARY,

    /**
     * Specifies that the shared device is a disk drive with special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$) and serves a temporary share. Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see http://msdn.microsoft.com/en-us/library/windows/desktop/bb525391(v=vs.85).aspx.
     * 
     */
    STYPE_DISKTREE_SPECIAL_TEMPORARY,

    /**
     * Specifies that the shared device is a print queue.
     * 
     */
    STYPE_PRINTQ,

    /**
     * Specifies that the shared device is a disk drive with special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see http://msdn.microsoft.com/en-us/library/windows/desktop/bb525391(v=vs.85).aspx.
     * 
     */
    STYPE_PRINTQ_SPECIAL,

    /**
     * Specifies that the shared device is a print queue and serves as a temporary share.
     * 
     */
    STYPE_PRINTQ_TEMPORARY,

    /**
     * Specifies that the shared device is a print queue with special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$) and serves a temporary share. Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see http://msdn.microsoft.com/en-us/library/windows/desktop/bb525391(v=vs.85).aspx.
     * 
     */
    STYPE_PRINTQ_SPECIAL_TEMPORARY,

    /**
     * Specifies that the shared device is a communications device.
     * 
     */
    STYPE_DEVICE,

    /**
     * Specifies that the shared device is a communications device with special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see http://msdn.microsoft.com/en-us/library/windows/desktop/bb525391(v=vs.85).aspx.
     * 
     */
    STYPE_DEVICE_SPECIAL,

    /**
     * Specifies that the shared device is a communications device and serves as a temporary share.
     * 
     */
    STYPE_DEVICE_TEMPORARY,

    /**
     * Specifies that the shared device is a communications device with special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$) and serves a temporary share. Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see http://msdn.microsoft.com/en-us/library/windows/desktop/bb525391(v=vs.85).aspx.
     * 
     */
    STYPE_DEVICE_SPECIAL_TEMPORARY,

    /**
     * Specifies that the shared device is an Interprocess Communication (IPC) device.
     * 
     */
    STYPE_IPC,

    /**
     * Specifies that the shared device is an Interprocess Communication (IPC) device with special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see http://msdn.microsoft.com/en-us/library/windows/desktop/bb525391(v=vs.85).aspx.
     * 
     */
    STYPE_IPC_SPECIAL,

    /**
     * Specifies that the shared device is an Interprocess Communication (IPC) device and serves as a temporary share.
     * 
     */
    STYPE_IPC_TEMPORARY,

    /**
     * Specifies that the shared device is an Interprocess Communication (IPC) device with special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$) and serves a temporary share. Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see http://msdn.microsoft.com/en-us/library/windows/desktop/bb525391(v=vs.85).aspx.
     * 
     */
    STYPE_IPC_SPECIAL_TEMPORARY;

    public String value() {
        return name();
    }

    public static SharedResourceTypeEnum fromValue(String v) {
        return valueOf(v);
    }

}
