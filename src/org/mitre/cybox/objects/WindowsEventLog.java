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
import org.mitre.cybox.common_2.Base64BinaryObjectPropertyType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.LongObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The WindowsEventLogObjectType type is intended to characterize entries in the Windows event log.
 * 
 * <p>Java class for WindowsEventLogObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WindowsEventLogObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="EID" type="{http://cybox.mitre.org/common-2}LongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Type" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Log" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Message" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Category_Num" type="{http://cybox.mitre.org/common-2}LongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Category" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Generation_Time" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Source" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Machine" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="User" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Blob" type="{http://cybox.mitre.org/common-2}Base64BinaryObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Correlation_Activity_ID" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Correlation_Related_Activity_ID" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Execution_Process_ID" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Execution_Thread_ID" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Index" type="{http://cybox.mitre.org/common-2}LongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Reserved" type="{http://cybox.mitre.org/common-2}LongObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Unformatted_Message_List" type="{http://cybox.mitre.org/objects#WinEventLogObject-2}UnformattedMessageListType" minOccurs="0"/>
 *         &lt;element name="Write_Time" type="{http://cybox.mitre.org/common-2}DateTimeObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WindowsEventLogObjectType", namespace = "http://cybox.mitre.org/objects#WinEventLogObject-2", propOrder = {
    "eid",
    "type",
    "log",
    "message",
    "categoryNum",
    "category",
    "generationTime",
    "source",
    "machine",
    "user",
    "blob",
    "correlationActivityID",
    "correlationRelatedActivityID",
    "executionProcessID",
    "executionThreadID",
    "index",
    "reserved",
    "unformattedMessageList",
    "writeTime"
})
@XmlRootElement(name = "Windows_Event_Log", namespace = "http://cybox.mitre.org/objects#WinEventLogObject-2")
public class WindowsEventLog
    extends ObjectPropertiesType
{

    @XmlElement(name = "EID")
    protected LongObjectPropertyType eid;
    @XmlElement(name = "Type")
    protected StringObjectPropertyType type;
    @XmlElement(name = "Log")
    protected StringObjectPropertyType log;
    @XmlElement(name = "Message")
    protected StringObjectPropertyType message;
    @XmlElement(name = "Category_Num")
    protected LongObjectPropertyType categoryNum;
    @XmlElement(name = "Category")
    protected StringObjectPropertyType category;
    @XmlElement(name = "Generation_Time")
    protected DateTimeObjectPropertyType generationTime;
    @XmlElement(name = "Source")
    protected StringObjectPropertyType source;
    @XmlElement(name = "Machine")
    protected StringObjectPropertyType machine;
    @XmlElement(name = "User")
    protected StringObjectPropertyType user;
    @XmlElement(name = "Blob")
    protected Base64BinaryObjectPropertyType blob;
    @XmlElement(name = "Correlation_Activity_ID")
    protected StringObjectPropertyType correlationActivityID;
    @XmlElement(name = "Correlation_Related_Activity_ID")
    protected StringObjectPropertyType correlationRelatedActivityID;
    @XmlElement(name = "Execution_Process_ID")
    protected StringObjectPropertyType executionProcessID;
    @XmlElement(name = "Execution_Thread_ID")
    protected StringObjectPropertyType executionThreadID;
    @XmlElement(name = "Index")
    protected LongObjectPropertyType index;
    @XmlElement(name = "Reserved")
    protected LongObjectPropertyType reserved;
    @XmlElement(name = "Unformatted_Message_List")
    protected UnformattedMessageListType unformattedMessageList;
    @XmlElement(name = "Write_Time")
    protected DateTimeObjectPropertyType writeTime;

    /**
     * Gets the value of the eid property.
     * 
     * @return
     *     possible object is
     *     {@link LongObjectPropertyType }
     *     
     */
    public LongObjectPropertyType getEID() {
        return eid;
    }

    /**
     * Sets the value of the eid property.
     * 
     * @param value
     *     allowed object is
     *     {@link LongObjectPropertyType }
     *     
     */
    public void setEID(LongObjectPropertyType value) {
        this.eid = value;
    }

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setType(StringObjectPropertyType value) {
        this.type = value;
    }

    /**
     * Gets the value of the log property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getLog() {
        return log;
    }

    /**
     * Sets the value of the log property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setLog(StringObjectPropertyType value) {
        this.log = value;
    }

    /**
     * Gets the value of the message property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getMessage() {
        return message;
    }

    /**
     * Sets the value of the message property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setMessage(StringObjectPropertyType value) {
        this.message = value;
    }

    /**
     * Gets the value of the categoryNum property.
     * 
     * @return
     *     possible object is
     *     {@link LongObjectPropertyType }
     *     
     */
    public LongObjectPropertyType getCategoryNum() {
        return categoryNum;
    }

    /**
     * Sets the value of the categoryNum property.
     * 
     * @param value
     *     allowed object is
     *     {@link LongObjectPropertyType }
     *     
     */
    public void setCategoryNum(LongObjectPropertyType value) {
        this.categoryNum = value;
    }

    /**
     * Gets the value of the category property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getCategory() {
        return category;
    }

    /**
     * Sets the value of the category property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setCategory(StringObjectPropertyType value) {
        this.category = value;
    }

    /**
     * Gets the value of the generationTime property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getGenerationTime() {
        return generationTime;
    }

    /**
     * Sets the value of the generationTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setGenerationTime(DateTimeObjectPropertyType value) {
        this.generationTime = value;
    }

    /**
     * Gets the value of the source property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getSource() {
        return source;
    }

    /**
     * Sets the value of the source property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setSource(StringObjectPropertyType value) {
        this.source = value;
    }

    /**
     * Gets the value of the machine property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getMachine() {
        return machine;
    }

    /**
     * Sets the value of the machine property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setMachine(StringObjectPropertyType value) {
        this.machine = value;
    }

    /**
     * Gets the value of the user property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getUser() {
        return user;
    }

    /**
     * Sets the value of the user property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setUser(StringObjectPropertyType value) {
        this.user = value;
    }

    /**
     * Gets the value of the blob property.
     * 
     * @return
     *     possible object is
     *     {@link Base64BinaryObjectPropertyType }
     *     
     */
    public Base64BinaryObjectPropertyType getBlob() {
        return blob;
    }

    /**
     * Sets the value of the blob property.
     * 
     * @param value
     *     allowed object is
     *     {@link Base64BinaryObjectPropertyType }
     *     
     */
    public void setBlob(Base64BinaryObjectPropertyType value) {
        this.blob = value;
    }

    /**
     * Gets the value of the correlationActivityID property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getCorrelationActivityID() {
        return correlationActivityID;
    }

    /**
     * Sets the value of the correlationActivityID property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setCorrelationActivityID(StringObjectPropertyType value) {
        this.correlationActivityID = value;
    }

    /**
     * Gets the value of the correlationRelatedActivityID property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getCorrelationRelatedActivityID() {
        return correlationRelatedActivityID;
    }

    /**
     * Sets the value of the correlationRelatedActivityID property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setCorrelationRelatedActivityID(StringObjectPropertyType value) {
        this.correlationRelatedActivityID = value;
    }

    /**
     * Gets the value of the executionProcessID property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getExecutionProcessID() {
        return executionProcessID;
    }

    /**
     * Sets the value of the executionProcessID property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setExecutionProcessID(StringObjectPropertyType value) {
        this.executionProcessID = value;
    }

    /**
     * Gets the value of the executionThreadID property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getExecutionThreadID() {
        return executionThreadID;
    }

    /**
     * Sets the value of the executionThreadID property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setExecutionThreadID(StringObjectPropertyType value) {
        this.executionThreadID = value;
    }

    /**
     * Gets the value of the index property.
     * 
     * @return
     *     possible object is
     *     {@link LongObjectPropertyType }
     *     
     */
    public LongObjectPropertyType getIndex() {
        return index;
    }

    /**
     * Sets the value of the index property.
     * 
     * @param value
     *     allowed object is
     *     {@link LongObjectPropertyType }
     *     
     */
    public void setIndex(LongObjectPropertyType value) {
        this.index = value;
    }

    /**
     * Gets the value of the reserved property.
     * 
     * @return
     *     possible object is
     *     {@link LongObjectPropertyType }
     *     
     */
    public LongObjectPropertyType getReserved() {
        return reserved;
    }

    /**
     * Sets the value of the reserved property.
     * 
     * @param value
     *     allowed object is
     *     {@link LongObjectPropertyType }
     *     
     */
    public void setReserved(LongObjectPropertyType value) {
        this.reserved = value;
    }

    /**
     * Gets the value of the unformattedMessageList property.
     * 
     * @return
     *     possible object is
     *     {@link UnformattedMessageListType }
     *     
     */
    public UnformattedMessageListType getUnformattedMessageList() {
        return unformattedMessageList;
    }

    /**
     * Sets the value of the unformattedMessageList property.
     * 
     * @param value
     *     allowed object is
     *     {@link UnformattedMessageListType }
     *     
     */
    public void setUnformattedMessageList(UnformattedMessageListType value) {
        this.unformattedMessageList = value;
    }

    /**
     * Gets the value of the writeTime property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public DateTimeObjectPropertyType getWriteTime() {
        return writeTime;
    }

    /**
     * Sets the value of the writeTime property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimeObjectPropertyType }
     *     
     */
    public void setWriteTime(DateTimeObjectPropertyType value) {
        this.writeTime = value;
    }

}
