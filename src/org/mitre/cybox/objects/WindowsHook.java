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
import org.mitre.cybox.common_2.NonNegativeIntegerObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * For more information please see http://msdn.microsoft.com/en-us/library/windows/desktop/ms644990(v=vs.85).aspx.
 * 
 * <p>Java class for WindowsHookObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WindowsHookObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/common-2}ObjectPropertiesType">
 *       &lt;sequence>
 *         &lt;element name="Type" type="{http://cybox.mitre.org/objects#WinHookObject-1}WinHookType" minOccurs="0"/>
 *         &lt;element name="Handle" type="{http://cybox.mitre.org/objects#WinHandleObject-2}WindowsHandleObjectType" minOccurs="0"/>
 *         &lt;element name="Hooking_Function_Name" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Hooking_Module" type="{http://cybox.mitre.org/objects#LibraryObject-2}LibraryObjectType" minOccurs="0"/>
 *         &lt;element name="Thread_ID" type="{http://cybox.mitre.org/common-2}NonNegativeIntegerObjectPropertyType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "WindowsHookObjectType", namespace = "http://cybox.mitre.org/objects#WinHookObject-1", propOrder = {
    "type",
    "handle",
    "hookingFunctionName",
    "hookingModule",
    "threadID"
})
@XmlRootElement(name = "Windows_Hook", namespace = "http://cybox.mitre.org/objects#WinHookObject-1")
public class WindowsHook
    extends ObjectPropertiesType
{

    @XmlElement(name = "Type")
    protected WinHookType type;
    @XmlElement(name = "Handle")
    protected WindowsHandle handle;
    @XmlElement(name = "Hooking_Function_Name")
    protected StringObjectPropertyType hookingFunctionName;
    @XmlElement(name = "Hooking_Module")
    protected Library hookingModule;
    @XmlElement(name = "Thread_ID")
    protected NonNegativeIntegerObjectPropertyType threadID;

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link WinHookType }
     *     
     */
    public WinHookType getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link WinHookType }
     *     
     */
    public void setType(WinHookType value) {
        this.type = value;
    }

    /**
     * Gets the value of the handle property.
     * 
     * @return
     *     possible object is
     *     {@link WindowsHandle }
     *     
     */
    public WindowsHandle getHandle() {
        return handle;
    }

    /**
     * Sets the value of the handle property.
     * 
     * @param value
     *     allowed object is
     *     {@link WindowsHandle }
     *     
     */
    public void setHandle(WindowsHandle value) {
        this.handle = value;
    }

    /**
     * Gets the value of the hookingFunctionName property.
     * 
     * @return
     *     possible object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public StringObjectPropertyType getHookingFunctionName() {
        return hookingFunctionName;
    }

    /**
     * Sets the value of the hookingFunctionName property.
     * 
     * @param value
     *     allowed object is
     *     {@link StringObjectPropertyType }
     *     
     */
    public void setHookingFunctionName(StringObjectPropertyType value) {
        this.hookingFunctionName = value;
    }

    /**
     * Gets the value of the hookingModule property.
     * 
     * @return
     *     possible object is
     *     {@link Library }
     *     
     */
    public Library getHookingModule() {
        return hookingModule;
    }

    /**
     * Sets the value of the hookingModule property.
     * 
     * @param value
     *     allowed object is
     *     {@link Library }
     *     
     */
    public void setHookingModule(Library value) {
        this.hookingModule = value;
    }

    /**
     * Gets the value of the threadID property.
     * 
     * @return
     *     possible object is
     *     {@link NonNegativeIntegerObjectPropertyType }
     *     
     */
    public NonNegativeIntegerObjectPropertyType getThreadID() {
        return threadID;
    }

    /**
     * Sets the value of the threadID property.
     * 
     * @param value
     *     allowed object is
     *     {@link NonNegativeIntegerObjectPropertyType }
     *     
     */
    public void setThreadID(NonNegativeIntegerObjectPropertyType value) {
        this.threadID = value;
    }

}
