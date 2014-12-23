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

import org.mitre.cybox.common_2.AnyURIObjectPropertyType;
import org.mitre.cybox.objects.URLHistory;
import org.mitre.cybox.objects.URLHistoryEntryType;

/**
 *
 */
public class EvalURLHistoryObj extends EvaluatableObject {

    private final URLHistory obj;

    public EvalURLHistoryObj(URLHistory a_obj, String a_id, String a_spacing) {
        obj = a_obj;
        id = a_id;
        spacing = a_spacing;
    }

    @Override
    public synchronized ObservableResult evaluate() {

        setWarnings("");

        if ((obj.getBrowserInformation() == null) && (obj.getURLHistoryEntries() == null)) {
            return new ObservableResult(id, "URLHistoryObject: No browser info or history entries found",
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

        // For displaying what we were looking for in the results
        String baseSearchString = "";

        // The browser info is the same for each entry
        boolean haveBrowserName = false;
        if (obj.getBrowserInformation() != null) {
            if (obj.getBrowserInformation().getName() != null) {
                haveBrowserName = true;
            }
            baseSearchString = "Browser \"" + obj.getBrowserInformation().getName() + "\"";
        }

        // Matching artifacts
        List<BlackboardArtifact> finalHits = new ArrayList<BlackboardArtifact>();

        if (obj.getURLHistoryEntries() != null) {

            for (URLHistoryEntryType entry : obj.getURLHistoryEntries()) {

                boolean haveURL = false;
                boolean haveHostname = false;
                boolean haveReferrer = false;
                boolean havePageTitle = false;
                boolean haveUserProfile = false;

                // At present, the search string doesn't get reported (because there could be different ones
                // for multiple URL History Entries) but it's good for debugging.
                String searchString = baseSearchString;

                if ((entry.getURL() != null) && (entry.getURL().getValue() != null)) {
                    haveURL = true;
                    if (!searchString.isEmpty()) {
                        searchString += " and ";
                    }
                    searchString += "URL \"" + entry.getURL().getValue().getValue() + "\"";
                }

                if ((entry.getReferrerURL() != null) && (entry.getReferrerURL().getValue() != null)) {
                    haveReferrer = true;
                    if (!searchString.isEmpty()) {
                        searchString += " and ";
                    }
                    searchString += "Referrer \"" + entry.getReferrerURL().getValue().getValue() + "\"";
                }

                if (entry.getUserProfileName() != null) {
                    haveUserProfile = true;
                    if (!searchString.isEmpty()) {
                        searchString += " and ";
                    }
                    searchString += "UserProfile \"" + entry.getUserProfileName().getValue() + "\"";
                }

                if (entry.getPageTitle() != null) {
                    havePageTitle = true;
                    if (!searchString.isEmpty()) {
                        searchString += " and ";
                    }
                    searchString += "Page title \"" + entry.getPageTitle().getValue() + "\"";
                }

                if ((entry.getHostname() != null) && (entry.getHostname().getHostnameValue() != null)) {
                    haveHostname = true;
                    if (!searchString.isEmpty()) {
                        searchString += " and ";
                    }
                    searchString += "Hostname \"" + entry.getHostname().getHostnameValue().getValue() + "\"";
                }

                if (!(haveURL || haveHostname || haveReferrer
                        || havePageTitle || haveUserProfile || haveBrowserName)) {
                    return new ObservableResult(id, "URLHistoryObject: No evaluatable fields found",
                            spacing, ObservableResult.ObservableState.INDETERMINATE, null);
                }

                try {
                    Case case1 = Case.getCurrentCase();
                    SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();
                    List<BlackboardArtifact> artList
                            = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY);

                    for (BlackboardArtifact art : artList) {
                        boolean foundURLMatch = false;
                        boolean foundHostnameMatch = false;
                        boolean foundReferrerMatch = false;
                        boolean foundPageTitleMatch = false;
                        boolean foundUserProfileMatch = false;
                        boolean foundBrowserNameMatch = false;

                        for (BlackboardAttribute attr : art.getAttributes()) {
                            if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID())
                                    && (haveURL)) {
                                if (entry.getURL().getValue() instanceof AnyURIObjectPropertyType) {
                                    foundURLMatch = compareStringObject(entry.getURL().getValue().getValue().toString(),
                                            entry.getURL().getValue().getCondition(),
                                            entry.getURL().getValue().getApplyCondition(),
                                            attr.getValueString());
                                } else {
                                    addWarning("Non-AnyURIObjectPropertyType found in URL value field");
                                }
                            }
                            if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID())
                                    && (haveHostname)) {
                                foundHostnameMatch = compareStringObject(entry.getHostname().getHostnameValue(),
                                        attr.getValueString());
                            }
                            if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_REFERRER.getTypeID())
                                    && (haveReferrer)) {
                                if (entry.getReferrerURL().getValue() instanceof AnyURIObjectPropertyType) {
                                    foundReferrerMatch = compareStringObject(entry.getReferrerURL().getValue().getValue().toString(),
                                            entry.getURL().getValue().getCondition(),
                                            entry.getURL().getValue().getApplyCondition(),
                                            attr.getValueString());
                                } else {
                                    addWarning("Non-AnyURIObjectPropertyType found in URL value field");
                                }
                            }
                            if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID())
                                    && (havePageTitle)) {
                                //System.out.println("Page title: " + attr.getValueString() + " " + entry.getPageTitle());
                                foundPageTitleMatch = compareStringObject(entry.getPageTitle(),
                                        attr.getValueString());
                            }
                            if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID())
                                    && (haveUserProfile)) {
                                foundUserProfileMatch = compareStringObject(entry.getUserProfileName(),
                                        attr.getValueString());
                            }
                            if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID())
                                    && (haveBrowserName)) {
                                foundBrowserNameMatch = compareStringObject(obj.getBrowserInformation().getName(),
                                        null, null, attr.getValueString());
                            }
                        }

                        if (((!haveURL) || foundURLMatch)
                                && ((!haveHostname) || foundHostnameMatch)
                                && ((!haveReferrer) || foundReferrerMatch)
                                && ((!havePageTitle) || foundPageTitleMatch)
                                && ((!haveUserProfile) || foundUserProfileMatch)
                                && ((!haveBrowserName) || foundBrowserNameMatch)) {
                            finalHits.add(art);
                        }
                    }

                } catch (TskCoreException ex) {
                    return new ObservableResult(id, "URLHistoryObject: Exception during evaluation: " + ex.getLocalizedMessage(),
                            spacing, ObservableResult.ObservableState.INDETERMINATE, null);
                }

            }

            if (!finalHits.isEmpty()) {
                List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                for (BlackboardArtifact a : finalHits) {
                    artData.add(new StixArtifactData(a.getObjectID(), id, "URLHistory"));
                }
                return new ObservableResult(id, "URLHistoryObject: Found at least one match",
                        spacing, ObservableResult.ObservableState.TRUE, artData);
            }

            // Didn't find any matches
            return new ObservableResult(id, "URLHistoryObject: No matches found",
                    spacing, ObservableResult.ObservableState.FALSE, null);

        } else if (haveBrowserName) {
            // It doesn't seem too useful, but we can just search for the browser name
            // if there aren't any URL entries

            try {
                Case case1 = Case.getCurrentCase();
                SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();
                List<BlackboardArtifact> artList
                        = sleuthkitCase.getBlackboardArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY);

                for (BlackboardArtifact art : artList) {
                    boolean foundBrowserNameMatch = false;

                    for (BlackboardAttribute attr : art.getAttributes()) {
                        if ((attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID())
                                && (haveBrowserName)) {
                            foundBrowserNameMatch = compareStringObject(obj.getBrowserInformation().getName(),
                                    null, null, attr.getValueString());
                        }
                    }

                    if (foundBrowserNameMatch) {
                        finalHits.add(art);
                    }
                }

                if (!finalHits.isEmpty()) {
                    List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                    for (BlackboardArtifact a : finalHits) {
                        artData.add(new StixArtifactData(a.getObjectID(), id, "URLHistory"));
                    }
                    return new ObservableResult(id, "URLHistoryObject: Found at least one match",
                            spacing, ObservableResult.ObservableState.TRUE, artData);
                }

                // Didn't find any matches
                return new ObservableResult(id, "URLHistoryObject: No matches found",
                        spacing, ObservableResult.ObservableState.FALSE, null);
            } catch (TskCoreException ex) {
                return new ObservableResult(id, "URLHistoryObject: Exception during evaluation: " + ex.getLocalizedMessage(),
                        spacing, ObservableResult.ObservableState.INDETERMINATE, null);
            }

        } else {
            // Nothing to search for
            return new ObservableResult(id, "URLHistoryObject: No evaluatable fields found",
                    spacing, ObservableResult.ObservableState.INDETERMINATE, null);
        }

    }
}
