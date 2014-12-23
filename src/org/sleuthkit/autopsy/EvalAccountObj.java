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

import org.mitre.cybox.objects.AccountObjectType;
import org.mitre.cybox.objects.UserAccountObjectType;
import org.mitre.cybox.objects.WindowsUserAccount;

/**
 *
 */
public class EvalAccountObj extends EvaluatableObject {

    private AccountObjectType obj;

    public EvalAccountObj(AccountObjectType a_obj, String a_id, String a_spacing) {
        obj = a_obj;
        id = a_id;
        spacing = a_spacing;
    }

    @Override
    public synchronized ObservableResult evaluate() {

        setWarnings("");

        // Fields we can search for:
        //   UserAccount: Home_Directory, Username
        //   WinUserAccount: SID
        if (!(obj instanceof UserAccountObjectType)) {
            return new ObservableResult(id, "AccountObject: Can not process \"Account\" - need a User_Account or Windows_User_Account",
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

        // For displaying what we were looking for in the results
        String searchString = "";

        // Check which fields are present and record them    
        boolean haveHomeDir = false;
        boolean haveUsername = false;
        boolean haveSID = false;

        UserAccountObjectType userAccountObj = (UserAccountObjectType) obj;
        if (userAccountObj.getHomeDirectory() != null) {
            haveHomeDir = true;
            searchString = "HomeDir \"" + userAccountObj.getHomeDirectory().getValue().toString() + "\"";
        }
        if (userAccountObj.getUsername() != null) {
            haveUsername = true;
            if (!searchString.isEmpty()) {
                searchString += " and ";
            }
            searchString += "Username \"" + userAccountObj.getUsername().getValue().toString() + "\"";
        }

        WindowsUserAccount winUserObj = null;
        if (obj instanceof WindowsUserAccount) {
            winUserObj = (WindowsUserAccount) obj;

            if (winUserObj.getSecurityID() != null) {
                haveSID = true;
                if (!searchString.isEmpty()) {
                    searchString += " and ";
                }
                searchString += "SID \"" + winUserObj.getSecurityID().getValue().toString() + "\"";
            }
        }

        if (!(haveHomeDir || haveUsername || haveSID)) {
            return new ObservableResult(id, "AccountObject: No evaluatable fields found",
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

        // The assumption here is that there aren't going to be too many network shares, so we
        // can cycle through all of them.
        try {
            List<BlackboardArtifact> finalHits = new ArrayList<BlackboardArtifact>();

            Case case1 = Case.getCurrentCase();
            SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();
            List<BlackboardArtifact> artList
                    = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_OS_ACCOUNT);

            for (BlackboardArtifact art : artList) {
                boolean foundHomeDirMatch = false;
                boolean foundUsernameMatch = false;
                boolean foundSIDMatch = false;

                for (BlackboardAttribute attr : art.getAttributes()) {
                    if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID())
                            && (haveHomeDir)) {
                        foundHomeDirMatch = compareStringObject(userAccountObj.getHomeDirectory(), attr.getValueString());
                    }
                    if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID())
                            && (haveUsername)) {
                        foundUsernameMatch = compareStringObject(userAccountObj.getUsername(), attr.getValueString());
                    }
                    if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID())
                            && (haveSID)) {
                        foundSIDMatch = compareStringObject(winUserObj.getSecurityID(), attr.getValueString());
                    }
                }

                if (((!haveHomeDir) || foundHomeDirMatch)
                        && ((!haveUsername) || foundUsernameMatch)
                        && ((!haveSID) || foundSIDMatch)) {
                    finalHits.add(art);
                }

            }

            // Check if we found any matches
            if (!finalHits.isEmpty()) {
                List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                for (BlackboardArtifact a : finalHits) {
                    artData.add(new StixArtifactData(a.getObjectID(), id, "Account"));
                }
                return new ObservableResult(id, "AccountObject: Found a match for " + searchString,
                        spacing, ObservableResult.ObservableState.TRUE, artData);
            }

            // Didn't find any matches
            return new ObservableResult(id, "AccountObject: No matches found for " + searchString,
                    spacing, ObservableResult.ObservableState.FALSE, null);
        } catch (TskCoreException ex) {
            return new ObservableResult(id, "AccountObject: Exception during evaluation: " + ex.getLocalizedMessage(),
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

    }

}
