/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy;

import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.OSInfo;
import org.sleuthkit.datamodel.OSUtility;

import java.util.List;
import java.util.ArrayList;

import org.mitre.cybox.objects.SystemObjectType;
import org.mitre.cybox.objects.WindowsSystem;

/**
 *
 */
public class EvalSystemObj extends EvaluatableObject {

    private SystemObjectType obj;

    public EvalSystemObj(SystemObjectType a_obj, String a_id, String a_spacing) {
        obj = a_obj;
        id = a_id;
        spacing = a_spacing;
    }

    @Override
    public synchronized ObservableResult evaluate() {

        setWarnings("");

        // For displaying what we were looking for in the results
        String searchString = "";

        // Check which fields are present and record them 
        boolean haveHostname = false;
       // boolean haveDomain = false; 
        // boolean haveProcArch = false;
        boolean haveProcName = false;
        boolean haveTempDir = false;
        boolean haveProductName = false;
        boolean haveSystemRoot = false;
        boolean haveProductID = false;
        boolean haveOwner = false;
        boolean haveOrganization = false;

        if (obj.getHostname() != null) {
            haveHostname = true;
            searchString = "Hostname \"" + obj.getHostname().getValue().toString() + "\"";
        }
        if (obj.getProcessor() != null) {
            haveProcName = true;
            if (!searchString.isEmpty()) {
                searchString += " and ";
            }
            searchString += "Processor \"" + obj.getHostname().getValue().toString() + "\"";
        }
        //if(obj.getProcessorArchitecture() != null){
        //    haveProcArch = true;
        //    if(! searchString.isEmpty()){
        //        searchString += " and ";
        //    }
        //    searchString += "Processor architecture \"" + obj.getProcessorArchitecture().getValue().toString() + "\"";
        //}

        WindowsSystem winSysObj = null;
        if (obj instanceof WindowsSystem) {
            winSysObj = (WindowsSystem) obj;

            if (winSysObj.getProductID() != null) {
                haveProductID = true;
                if (!searchString.isEmpty()) {
                    searchString += " and ";
                }
                searchString += "Product ID \"" + winSysObj.getProductID().getValue().toString() + "\"";
            }
            if (winSysObj.getProductName() != null) {
                haveProductName = true;
                if (!searchString.isEmpty()) {
                    searchString += " and ";
                }
                searchString += "Product Name \"" + winSysObj.getProductName().getValue().toString() + "\"";
            }
            if (winSysObj.getRegisteredOrganization() != null) {
                haveOrganization = true;
                if (!searchString.isEmpty()) {
                    searchString += " and ";
                }
                searchString += "Registered Org \"" + winSysObj.getRegisteredOrganization().getValue().toString() + "\"";
            }
            if (winSysObj.getRegisteredOwner() != null) {
                haveOwner = true;
                if (!searchString.isEmpty()) {
                    searchString += " and ";
                }
                searchString += "Registered Owner \"" + winSysObj.getRegisteredOwner().getValue().toString() + "\"";
            }
            if (winSysObj.getWindowsSystemDirectory() != null) {
                haveSystemRoot = true;
                if (!searchString.isEmpty()) {
                    searchString += " and ";
                }
                searchString += "System root \"" + winSysObj.getWindowsSystemDirectory().getValue().toString() + "\"";
            }
            if (winSysObj.getWindowsTempDirectory() != null) {
                haveTempDir = true;
                if (!searchString.isEmpty()) {
                    searchString += " and ";
                }
                searchString += "Temp dir \"" + winSysObj.getWindowsTempDirectory().getValue().toString() + "\"";
            }
            //if(winSysObj.getDomains()) //??
        }

        // Return if we have nothing to search for
        if (!(haveHostname || haveProcName
                || haveTempDir || haveProductName || haveSystemRoot || haveProductID
                || haveOwner || haveOrganization)) {
            return new ObservableResult(id, "SystemObject: No evaluatable fields found",
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

        try {
            Case case1 = Case.getCurrentCase();
            SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();
            List<OSInfo> osInfoList = OSUtility.getOSInfo(sleuthkitCase);

            List<BlackboardArtifact> finalHits = new ArrayList<BlackboardArtifact>();

            if (!osInfoList.isEmpty()) {
                for (OSInfo info : osInfoList) {

                    boolean foundHostnameMatch = false;
                    //boolean foundDomainMatch = false;
                    //boolean foundProcArchMatch = false;
                    boolean foundProcNameMatch = false;
                    boolean foundTempDirMatch = false;
                    boolean foundProductNameMatch = false;
                    boolean foundSystemRootMatch = false;
                    boolean foundProductIDMatch = false;
                    boolean foundOwnerMatch = false;
                    boolean foundOrganizationMatch = false;

                    if (haveHostname) {
                        foundHostnameMatch = compareStringObject(obj.getHostname(), info.getCompName());
                    }
                    //if(haveProcArch){
                    //    System.out.println("Found proc arch");
                    //}
                    if (haveProcName) {
                        foundProcNameMatch = compareStringObject(obj.getProcessor(),
                                info.getAttributeValue(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROCESSOR_NAME));
                    }
                    if (haveTempDir) {
                        foundTempDirMatch = compareStringObject(winSysObj.getWindowsTempDirectory(),
                                info.getAttributeValue(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEMP_DIR));
                    }
                    if (haveProductName) {
                        foundProductNameMatch = compareStringObject(winSysObj.getProductName(),
                                info.getAttributeValue(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME));
                    }
                    if (haveSystemRoot) {
                        foundSystemRootMatch = compareStringObject(winSysObj.getWindowsSystemDirectory(),
                                info.getAttributeValue(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH));
                    }
                    if (haveProductID) {
                        foundProductIDMatch = compareStringObject(winSysObj.getProductID(),
                                info.getAttributeValue(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PRODUCT_ID));
                    }
                    if (haveOwner) {
                        foundOwnerMatch = compareStringObject(winSysObj.getRegisteredOwner(),
                                info.getAttributeValue(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_OWNER));
                    }
                    if (haveOrganization) {
                        foundOrganizationMatch = compareStringObject(winSysObj.getRegisteredOrganization(),
                                info.getAttributeValue(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ORGANIZATION));
                    }

                    if (((!haveHostname) || foundHostnameMatch)
                            && ((!haveProcName) || foundProcNameMatch)
                            && ((!haveTempDir) || foundTempDirMatch)
                            && ((!haveProductName) || foundProductNameMatch)
                            && ((!haveSystemRoot) || foundSystemRootMatch)
                            && ((!haveProductID) || foundProductIDMatch)
                            && ((!haveOwner) || foundOwnerMatch)
                            && ((!haveOrganization) || foundOrganizationMatch)) {

                        finalHits.addAll(info.getArtifacts());
                    }
                }

                if (!finalHits.isEmpty()) {
                    List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                    for (BlackboardArtifact a : finalHits) {
                        artData.add(new StixArtifactData(a.getObjectID(), id, "System"));
                    }
                    return new ObservableResult(id, "SystemObject: Found a match for " + searchString,
                            spacing, ObservableResult.ObservableState.TRUE, artData);
                }

                // Didn't find any matches
                return new ObservableResult(id, "SystemObject: No matches found for " + searchString,
                        spacing, ObservableResult.ObservableState.FALSE, null);
            } else {
                return new ObservableResult(id, "SystemObject: No OS artifacts found",
                        spacing, ObservableResult.ObservableState.INDETERMINATE, null);
            }
        } catch (TskCoreException ex) {
            return new ObservableResult(id, "SystemObject: Exception during evaluation: " + ex.getLocalizedMessage(),
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }
    }
}
