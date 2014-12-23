/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy;

import java.util.ArrayList;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;

import java.util.List;

import org.mitre.cybox.objects.WindowsNetworkShare;

/**
 *
 */
public class EvalNetworkShareObj extends EvaluatableObject {

    private final WindowsNetworkShare obj;

    public EvalNetworkShareObj(WindowsNetworkShare a_obj, String a_id, String a_spacing) {
        obj = a_obj;
        id = a_id;
        spacing = a_spacing;
    }

    @Override
    public synchronized ObservableResult evaluate() {

        setWarnings("");

        if ((obj.getNetname() == null) && (obj.getLocalPath() == null)) {
            return new ObservableResult(id, "NetworkShareObjet: No remote name or local path found",
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

        // For displaying what we were looking for in the results
        String searchString = "";
        if (obj.getNetname() != null) {
            searchString += "Netname \"" + obj.getNetname().getValue() + "\"";
        }
        if (obj.getLocalPath() != null) {
            if (!searchString.isEmpty()) {
                searchString += " and ";
            }
            searchString += "LocalPath \"" + obj.getLocalPath().getValue() + "\"";
        }

        // The assumption here is that there aren't going to be too many network shares, so we
        // can cycle through all of them.
        try {
            List<BlackboardArtifact> finalHits = new ArrayList<BlackboardArtifact>();

            Case case1 = Case.getCurrentCase();
            SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();
            List<BlackboardArtifact> artList
                    = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_REMOTE_DRIVE);

            for (BlackboardArtifact art : artList) {
                boolean foundRemotePathMatch = false;
                boolean foundLocalPathMatch = false;

                for (BlackboardAttribute attr : art.getAttributes()) {
                    if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_REMOTE_PATH.getTypeID())
                            && (obj.getNetname() != null)) {
                        foundRemotePathMatch = compareStringObject(obj.getNetname(), attr.getValueString());
                    }
                    if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCAL_PATH.getTypeID())
                            && (obj.getLocalPath() != null)) {
                        foundLocalPathMatch = compareStringObject(obj.getLocalPath(), attr.getValueString());
                    }
                }

                // Check whether we found everything we were looking for
                if (((foundRemotePathMatch) || (obj.getNetname() == null))
                        && ((foundLocalPathMatch) || (obj.getLocalPath() == null))) {
                    finalHits.add(art);
                }
            }

            // Check if we found any matches
            if (!finalHits.isEmpty()) {
                List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                for (BlackboardArtifact a : finalHits) {
                    artData.add(new StixArtifactData(a.getObjectID(), id, "NetworkShare"));
                }
                return new ObservableResult(id, "NetworkShareObject: Found a match for " + searchString,
                        spacing, ObservableResult.ObservableState.TRUE, artData);
            }

            // Didn't find any matches
            return new ObservableResult(id, "NetworkObject: No matches found for " + searchString,
                    spacing, ObservableResult.ObservableState.FALSE, null);
        } catch (TskCoreException ex) {
            return new ObservableResult(id, "NetworkObject: Exception during evaluation: " + ex.getLocalizedMessage(),
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }
    }

}
