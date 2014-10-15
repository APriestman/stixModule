//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.09.25 at 01:41:27 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.HexBinaryObjectPropertyType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.UnsignedLongObjectPropertyType;


/**
 * The WindowsDriverObject type is intended to characterize Windows device drivers.
 * 
 * <p>Java class for WindowsDriverObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WindowsDriverObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/objects#WinExecutableFileObject-2}WindowsExecutableFileObjectType">
 *       &lt;sequence>
 *         &lt;element name="Device_Object_List" type="{http://cybox.mitre.org/objects#WinDriverObject-3}DeviceObjectListType" minOccurs="0"/>
 *         &lt;element name="Driver_Init" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Driver_Name" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Driver_Object_Address" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Driver_Start_IO" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Driver_Unload" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Image_Base" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Image_Size" type="{http://cybox.mitre.org/common-2}HexBinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_CLEANUP" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_CLOSE" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_CREATE" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_CREATE_MAILSLOT" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_CREATE_NAMED_PIPE" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_DEVICE_CHANGE" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_DEVICE_CONTROL" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_DIRECTORY_CONTROL" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_FILE_SYSTEM_CONTROL" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_FLUSH_BUFFERS" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_INTERNAL_DEVICE_CONTROL" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_LOCK_CONTROL" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_PNP" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_POWER" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_READ" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_QUERY_EA" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_QUERY_INFORMATION" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_QUERY_SECURITY" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_QUERY_QUOTA" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_QUERY_VOLUME_INFORMATION" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_SET_EA" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_SET_INFORMATION" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_SET_SECURITY" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_SET_QUOTA" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_SET_VOLUME_INFORMATION" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_SHUTDOWN" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_SYSTEM_CONTROL" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="IRP_MJ_WRITE" type="{http://cybox.mitre.org/common-2}UnsignedLongObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WindowsDriverObjectType", namespace = "http://cybox.mitre.org/objects#WinDriverObject-3", propOrder = {
    "deviceObjectList",
    "driverInit",
    "driverName",
    "driverObjectAddress",
    "driverStartIO",
    "driverUnload",
    "imageBase",
    "imageSize",
    "irpmjcleanup",
    "irpmjclose",
    "irpmjcreate",
    "irpmjcreatemailslot",
    "irpmjcreatenamedpipe",
    "irpmjdevicechange",
    "irpmjdevicecontrol",
    "irpmjdirectorycontrol",
    "irpmjfilesystemcontrol",
    "irpmjflushbuffers",
    "irpmjinternaldevicecontrol",
    "irpmjlockcontrol",
    "irpmjpnp",
    "irpmjpower",
    "irpmjread",
    "irpmjqueryea",
    "irpmjqueryinformation",
    "irpmjquerysecurity",
    "irpmjqueryquota",
    "irpmjqueryvolumeinformation",
    "irpmjsetea",
    "irpmjsetinformation",
    "irpmjsetsecurity",
    "irpmjsetquota",
    "irpmjsetvolumeinformation",
    "irpmjshutdown",
    "irpmjsystemcontrol",
    "irpmjwrite"
})
@XmlRootElement(name = "Windows_Driver", namespace = "http://cybox.mitre.org/objects#WinDriverObject-3")
public class WindowsDriver
    extends WindowsExecutableFileObjectType
{

    @XmlElement(name = "Device_Object_List")
    protected DeviceObjectListType deviceObjectList;
    @XmlElement(name = "Driver_Init")
    protected UnsignedLongObjectPropertyType driverInit;
    @XmlElement(name = "Driver_Name")
    protected StringObjectPropertyType driverName;
    @XmlElement(name = "Driver_Object_Address")
    protected HexBinaryObjectPropertyType driverObjectAddress;
    @XmlElement(name = "Driver_Start_IO")
    protected HexBinaryObjectPropertyType driverStartIO;
    @XmlElement(name = "Driver_Unload")
    protected HexBinaryObjectPropertyType driverUnload;
    @XmlElement(name = "Image_Base")
    protected HexBinaryObjectPropertyType imageBase;
    @XmlElement(name = "Image_Size")
    protected HexBinaryObjectPropertyType imageSize;
    @XmlElement(name = "IRP_MJ_CLEANUP")
    protected UnsignedLongObjectPropertyType irpmjcleanup;
    @XmlElement(name = "IRP_MJ_CLOSE")
    protected UnsignedLongObjectPropertyType irpmjclose;
    @XmlElement(name = "IRP_MJ_CREATE")
    protected UnsignedLongObjectPropertyType irpmjcreate;
    @XmlElement(name = "IRP_MJ_CREATE_MAILSLOT")
    protected UnsignedLongObjectPropertyType irpmjcreatemailslot;
    @XmlElement(name = "IRP_MJ_CREATE_NAMED_PIPE")
    protected UnsignedLongObjectPropertyType irpmjcreatenamedpipe;
    @XmlElement(name = "IRP_MJ_DEVICE_CHANGE")
    protected UnsignedLongObjectPropertyType irpmjdevicechange;
    @XmlElement(name = "IRP_MJ_DEVICE_CONTROL")
    protected UnsignedLongObjectPropertyType irpmjdevicecontrol;
    @XmlElement(name = "IRP_MJ_DIRECTORY_CONTROL")
    protected UnsignedLongObjectPropertyType irpmjdirectorycontrol;
    @XmlElement(name = "IRP_MJ_FILE_SYSTEM_CONTROL")
    protected UnsignedLongObjectPropertyType irpmjfilesystemcontrol;
    @XmlElement(name = "IRP_MJ_FLUSH_BUFFERS")
    protected UnsignedLongObjectPropertyType irpmjflushbuffers;
    @XmlElement(name = "IRP_MJ_INTERNAL_DEVICE_CONTROL")
    protected UnsignedLongObjectPropertyType irpmjinternaldevicecontrol;
    @XmlElement(name = "IRP_MJ_LOCK_CONTROL")
    protected UnsignedLongObjectPropertyType irpmjlockcontrol;
    @XmlElement(name = "IRP_MJ_PNP")
    protected UnsignedLongObjectPropertyType irpmjpnp;
    @XmlElement(name = "IRP_MJ_POWER")
    protected UnsignedLongObjectPropertyType irpmjpower;
    @XmlElement(name = "IRP_MJ_READ")
    protected UnsignedLongObjectPropertyType irpmjread;
    @XmlElement(name = "IRP_MJ_QUERY_EA")
    protected UnsignedLongObjectPropertyType irpmjqueryea;
    @XmlElement(name = "IRP_MJ_QUERY_INFORMATION")
    protected UnsignedLongObjectPropertyType irpmjqueryinformation;
    @XmlElement(name = "IRP_MJ_QUERY_SECURITY")
    protected UnsignedLongObjectPropertyType irpmjquerysecurity;
    @XmlElement(name = "IRP_MJ_QUERY_QUOTA")
    protected UnsignedLongObjectPropertyType irpmjqueryquota;
    @XmlElement(name = "IRP_MJ_QUERY_VOLUME_INFORMATION")
    protected UnsignedLongObjectPropertyType irpmjqueryvolumeinformation;
    @XmlElement(name = "IRP_MJ_SET_EA")
    protected UnsignedLongObjectPropertyType irpmjsetea;
    @XmlElement(name = "IRP_MJ_SET_INFORMATION")
    protected UnsignedLongObjectPropertyType irpmjsetinformation;
    @XmlElement(name = "IRP_MJ_SET_SECURITY")
    protected UnsignedLongObjectPropertyType irpmjsetsecurity;
    @XmlElement(name = "IRP_MJ_SET_QUOTA")
    protected UnsignedLongObjectPropertyType irpmjsetquota;
    @XmlElement(name = "IRP_MJ_SET_VOLUME_INFORMATION")
    protected UnsignedLongObjectPropertyType irpmjsetvolumeinformation;
    @XmlElement(name = "IRP_MJ_SHUTDOWN")
    protected UnsignedLongObjectPropertyType irpmjshutdown;
    @XmlElement(name = "IRP_MJ_SYSTEM_CONTROL")
    protected UnsignedLongObjectPropertyType irpmjsystemcontrol;
    @XmlElement(name = "IRP_MJ_WRITE")
    protected UnsignedLongObjectPropertyType irpmjwrite;

    /**
     * Gets the value of the deviceObjectList property.
     * 
     * @return
     *     possible object is
     *     {@link DeviceObjectListType }
     *     
     */
    public DeviceObjectListType getDeviceObjectList() {
        return deviceObjectList;
    }

    /**
     * Sets the value of the deviceObjectList property.
     * 
     * @param value
     *     allowed object is
     *     {@link DeviceObjectListType }
     *     
     */
    public void setDeviceObjectList(DeviceObjectListType value) {
        this.deviceObjectList = value;
    }

    /**
     * Gets the value of the driverInit property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getDriverInit() {
        return driverInit;
    }

    /**
     * Sets the value of the driverInit property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setDriverInit(UnsignedLongObjectPropertyType value) {
        this.driverInit = value;
    }

    /**
     * Gets the value of the driverName property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getDriverName() {
        return driverName;
    }

    /**
     * Sets the value of the driverName property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setDriverName(StringObjectPropertyType value) {
        this.driverName = value;
    }

    /**
     * Gets the value of the driverObjectAddress property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getDriverObjectAddress() {
        return driverObjectAddress;
    }

    /**
     * Sets the value of the driverObjectAddress property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setDriverObjectAddress(HexBinaryObjectPropertyType value) {
        this.driverObjectAddress = value;
    }

    /**
     * Gets the value of the driverStartIO property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getDriverStartIO() {
        return driverStartIO;
    }

    /**
     * Sets the value of the driverStartIO property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setDriverStartIO(HexBinaryObjectPropertyType value) {
        this.driverStartIO = value;
    }

    /**
     * Gets the value of the driverUnload property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getDriverUnload() {
        return driverUnload;
    }

    /**
     * Sets the value of the driverUnload property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setDriverUnload(HexBinaryObjectPropertyType value) {
        this.driverUnload = value;
    }

    /**
     * Gets the value of the imageBase property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getImageBase() {
        return imageBase;
    }

    /**
     * Sets the value of the imageBase property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setImageBase(HexBinaryObjectPropertyType value) {
        this.imageBase = value;
    }

    /**
     * Gets the value of the imageSize property.
     * 
     * @return
     *     possible object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public HexBinaryObjectPropertyType getImageSize() {
        return imageSize;
    }

    /**
     * Sets the value of the imageSize property.
     * 
     * @param value
     *     allowed object is
     *     {@link HexBinaryObjectPropertyType }
     *     
     */
    public void setImageSize(HexBinaryObjectPropertyType value) {
        this.imageSize = value;
    }

    /**
     * Gets the value of the irpmjcleanup property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJCLEANUP() {
        return irpmjcleanup;
    }

    /**
     * Sets the value of the irpmjcleanup property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJCLEANUP(UnsignedLongObjectPropertyType value) {
        this.irpmjcleanup = value;
    }

    /**
     * Gets the value of the irpmjclose property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJCLOSE() {
        return irpmjclose;
    }

    /**
     * Sets the value of the irpmjclose property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJCLOSE(UnsignedLongObjectPropertyType value) {
        this.irpmjclose = value;
    }

    /**
     * Gets the value of the irpmjcreate property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJCREATE() {
        return irpmjcreate;
    }

    /**
     * Sets the value of the irpmjcreate property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJCREATE(UnsignedLongObjectPropertyType value) {
        this.irpmjcreate = value;
    }

    /**
     * Gets the value of the irpmjcreatemailslot property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJCREATEMAILSLOT() {
        return irpmjcreatemailslot;
    }

    /**
     * Sets the value of the irpmjcreatemailslot property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJCREATEMAILSLOT(UnsignedLongObjectPropertyType value) {
        this.irpmjcreatemailslot = value;
    }

    /**
     * Gets the value of the irpmjcreatenamedpipe property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJCREATENAMEDPIPE() {
        return irpmjcreatenamedpipe;
    }

    /**
     * Sets the value of the irpmjcreatenamedpipe property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJCREATENAMEDPIPE(UnsignedLongObjectPropertyType value) {
        this.irpmjcreatenamedpipe = value;
    }

    /**
     * Gets the value of the irpmjdevicechange property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJDEVICECHANGE() {
        return irpmjdevicechange;
    }

    /**
     * Sets the value of the irpmjdevicechange property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJDEVICECHANGE(UnsignedLongObjectPropertyType value) {
        this.irpmjdevicechange = value;
    }

    /**
     * Gets the value of the irpmjdevicecontrol property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJDEVICECONTROL() {
        return irpmjdevicecontrol;
    }

    /**
     * Sets the value of the irpmjdevicecontrol property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJDEVICECONTROL(UnsignedLongObjectPropertyType value) {
        this.irpmjdevicecontrol = value;
    }

    /**
     * Gets the value of the irpmjdirectorycontrol property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJDIRECTORYCONTROL() {
        return irpmjdirectorycontrol;
    }

    /**
     * Sets the value of the irpmjdirectorycontrol property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJDIRECTORYCONTROL(UnsignedLongObjectPropertyType value) {
        this.irpmjdirectorycontrol = value;
    }

    /**
     * Gets the value of the irpmjfilesystemcontrol property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJFILESYSTEMCONTROL() {
        return irpmjfilesystemcontrol;
    }

    /**
     * Sets the value of the irpmjfilesystemcontrol property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJFILESYSTEMCONTROL(UnsignedLongObjectPropertyType value) {
        this.irpmjfilesystemcontrol = value;
    }

    /**
     * Gets the value of the irpmjflushbuffers property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJFLUSHBUFFERS() {
        return irpmjflushbuffers;
    }

    /**
     * Sets the value of the irpmjflushbuffers property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJFLUSHBUFFERS(UnsignedLongObjectPropertyType value) {
        this.irpmjflushbuffers = value;
    }

    /**
     * Gets the value of the irpmjinternaldevicecontrol property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJINTERNALDEVICECONTROL() {
        return irpmjinternaldevicecontrol;
    }

    /**
     * Sets the value of the irpmjinternaldevicecontrol property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJINTERNALDEVICECONTROL(UnsignedLongObjectPropertyType value) {
        this.irpmjinternaldevicecontrol = value;
    }

    /**
     * Gets the value of the irpmjlockcontrol property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJLOCKCONTROL() {
        return irpmjlockcontrol;
    }

    /**
     * Sets the value of the irpmjlockcontrol property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJLOCKCONTROL(UnsignedLongObjectPropertyType value) {
        this.irpmjlockcontrol = value;
    }

    /**
     * Gets the value of the irpmjpnp property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJPNP() {
        return irpmjpnp;
    }

    /**
     * Sets the value of the irpmjpnp property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJPNP(UnsignedLongObjectPropertyType value) {
        this.irpmjpnp = value;
    }

    /**
     * Gets the value of the irpmjpower property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJPOWER() {
        return irpmjpower;
    }

    /**
     * Sets the value of the irpmjpower property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJPOWER(UnsignedLongObjectPropertyType value) {
        this.irpmjpower = value;
    }

    /**
     * Gets the value of the irpmjread property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJREAD() {
        return irpmjread;
    }

    /**
     * Sets the value of the irpmjread property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJREAD(UnsignedLongObjectPropertyType value) {
        this.irpmjread = value;
    }

    /**
     * Gets the value of the irpmjqueryea property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJQUERYEA() {
        return irpmjqueryea;
    }

    /**
     * Sets the value of the irpmjqueryea property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJQUERYEA(UnsignedLongObjectPropertyType value) {
        this.irpmjqueryea = value;
    }

    /**
     * Gets the value of the irpmjqueryinformation property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJQUERYINFORMATION() {
        return irpmjqueryinformation;
    }

    /**
     * Sets the value of the irpmjqueryinformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJQUERYINFORMATION(UnsignedLongObjectPropertyType value) {
        this.irpmjqueryinformation = value;
    }

    /**
     * Gets the value of the irpmjquerysecurity property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJQUERYSECURITY() {
        return irpmjquerysecurity;
    }

    /**
     * Sets the value of the irpmjquerysecurity property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJQUERYSECURITY(UnsignedLongObjectPropertyType value) {
        this.irpmjquerysecurity = value;
    }

    /**
     * Gets the value of the irpmjqueryquota property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJQUERYQUOTA() {
        return irpmjqueryquota;
    }

    /**
     * Sets the value of the irpmjqueryquota property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJQUERYQUOTA(UnsignedLongObjectPropertyType value) {
        this.irpmjqueryquota = value;
    }

    /**
     * Gets the value of the irpmjqueryvolumeinformation property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJQUERYVOLUMEINFORMATION() {
        return irpmjqueryvolumeinformation;
    }

    /**
     * Sets the value of the irpmjqueryvolumeinformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJQUERYVOLUMEINFORMATION(UnsignedLongObjectPropertyType value) {
        this.irpmjqueryvolumeinformation = value;
    }

    /**
     * Gets the value of the irpmjsetea property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJSETEA() {
        return irpmjsetea;
    }

    /**
     * Sets the value of the irpmjsetea property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJSETEA(UnsignedLongObjectPropertyType value) {
        this.irpmjsetea = value;
    }

    /**
     * Gets the value of the irpmjsetinformation property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJSETINFORMATION() {
        return irpmjsetinformation;
    }

    /**
     * Sets the value of the irpmjsetinformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJSETINFORMATION(UnsignedLongObjectPropertyType value) {
        this.irpmjsetinformation = value;
    }

    /**
     * Gets the value of the irpmjsetsecurity property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJSETSECURITY() {
        return irpmjsetsecurity;
    }

    /**
     * Sets the value of the irpmjsetsecurity property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJSETSECURITY(UnsignedLongObjectPropertyType value) {
        this.irpmjsetsecurity = value;
    }

    /**
     * Gets the value of the irpmjsetquota property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJSETQUOTA() {
        return irpmjsetquota;
    }

    /**
     * Sets the value of the irpmjsetquota property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJSETQUOTA(UnsignedLongObjectPropertyType value) {
        this.irpmjsetquota = value;
    }

    /**
     * Gets the value of the irpmjsetvolumeinformation property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJSETVOLUMEINFORMATION() {
        return irpmjsetvolumeinformation;
    }

    /**
     * Sets the value of the irpmjsetvolumeinformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJSETVOLUMEINFORMATION(UnsignedLongObjectPropertyType value) {
        this.irpmjsetvolumeinformation = value;
    }

    /**
     * Gets the value of the irpmjshutdown property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJSHUTDOWN() {
        return irpmjshutdown;
    }

    /**
     * Sets the value of the irpmjshutdown property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJSHUTDOWN(UnsignedLongObjectPropertyType value) {
        this.irpmjshutdown = value;
    }

    /**
     * Gets the value of the irpmjsystemcontrol property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJSYSTEMCONTROL() {
        return irpmjsystemcontrol;
    }

    /**
     * Sets the value of the irpmjsystemcontrol property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJSYSTEMCONTROL(UnsignedLongObjectPropertyType value) {
        this.irpmjsystemcontrol = value;
    }

    /**
     * Gets the value of the irpmjwrite property.
     * 
     * @return
     *     possible object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public UnsignedLongObjectPropertyType getIRPMJWRITE() {
        return irpmjwrite;
    }

    /**
     * Sets the value of the irpmjwrite property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnsignedLongObjectPropertyType }
     *     
     */
    public void setIRPMJWRITE(UnsignedLongObjectPropertyType value) {
        this.irpmjwrite = value;
    }

}
