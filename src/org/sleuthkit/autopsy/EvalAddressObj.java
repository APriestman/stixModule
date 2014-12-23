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

import java.util.List;
import java.util.ArrayList;
import org.mitre.cybox.common_2.ConditionApplicationEnum;
import org.mitre.cybox.common_2.ConditionTypeEnum;

import org.mitre.cybox.objects.Address;

/**
 *
 */
public class EvalAddressObj extends EvaluatableObject {

    private final Address obj;

    public EvalAddressObj(Address a_obj, String a_id, String a_spacing) {
        obj = a_obj;
        id = a_id;
        spacing = a_spacing;
    }

    @Override
    public synchronized ObservableResult evaluate() {

        setWarnings("");

        if (obj.getAddressValue() == null) {
            return new ObservableResult(id, "AddressObject: No address value field found",
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

        String addressStr = obj.getAddressValue().getValue().toString();

        //if(! ((obj.getAddressValue().getCondition() == null) ||
        //            (obj.getAddressValue().getCondition() == ConditionTypeEnum.EQUALS))){
        //    return new ObservableResult(id, "Can not process condition " + obj.getAddressValue().getCondition().toString() +
        //            " on Address object", spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        //} 
        if (!((obj.getAddressValue().getApplyCondition() == null)
                || (obj.getAddressValue().getApplyCondition() == ConditionApplicationEnum.ANY))) {
            return new ObservableResult(id, "AddressObject: Can not process apply condition " + obj.getAddressValue().getApplyCondition().toString()
                    + " on Address object", spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

        Case case1 = Case.getCurrentCase();
        SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();

        try {
            if ((obj.getAddressValue().getCondition() == null)
                    || (obj.getAddressValue().getCondition() == ConditionTypeEnum.EQUALS)) {
                List<BlackboardArtifact> arts = sleuthkitCase.getBlackboardArtifacts(
                        BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT,
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD,
                        addressStr);

                if (!arts.isEmpty()) {

                    List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                    for (BlackboardArtifact a : arts) {
                        artData.add(new StixArtifactData(a.getObjectID(), id, "AddressObject"));
                    }

                    return new ObservableResult(id, "AddressObject: Found " + arts.size() + " matches for address = \"" + addressStr + "\"",
                            spacing, ObservableResult.ObservableState.TRUE, artData);

                } else {
                    return new ObservableResult(id, "AddressObject: Found no matches for address = \"" + addressStr + "\"",
                            spacing, ObservableResult.ObservableState.FALSE, null);
                }

            } else {
                // This is inefficient, but the easiest way to do it.

                List<BlackboardArtifact> finalHits = new ArrayList<BlackboardArtifact>();

                // Get all the URL artifacts
                List<BlackboardArtifact> artList
                        = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT);

                for (BlackboardArtifact art : artList) {

                    for (BlackboardAttribute attr : art.getAttributes()) {
                        if (attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD.getTypeID()) {
                            if (compareStringObject(addressStr, obj.getAddressValue().getCondition(),
                                    obj.getAddressValue().getApplyCondition(), attr.getValueString())) {
                                finalHits.add(art);
                            }
                        }
                    }
                }

                if (!finalHits.isEmpty()) {
                    List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                    for (BlackboardArtifact a : finalHits) {
                        artData.add(new StixArtifactData(a.getObjectID(), id, "AddressObject"));
                    }
                    return new ObservableResult(id, "AddressObject: Found a match for " + addressStr,
                            spacing, ObservableResult.ObservableState.TRUE, artData);
                }

                return new ObservableResult(id, "AddressObject: Found no matches for " + addressStr,
                        spacing, ObservableResult.ObservableState.FALSE, null);
            }
        } catch (TskCoreException ex) {
            return new ObservableResult(id, "AddressObject: Exception during evaluation: " + ex.getLocalizedMessage(),
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }
    }

}
