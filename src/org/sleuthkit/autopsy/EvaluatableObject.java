/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy;

import java.util.ArrayList;
import java.util.List;
import org.mitre.cybox.common_2.ConditionApplicationEnum;
import org.mitre.cybox.common_2.ConditionTypeEnum;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

/**
 *
 */
public abstract class EvaluatableObject {

    private String warnings;
    protected String id;
    protected String spacing;

    abstract public ObservableResult evaluate();

    public void setWarnings(String a_warnings) {
        warnings = a_warnings;
    }

    public String getWarnings() {
        return warnings;
    }

    public void addWarning(String a_newWarning) {
        if ((warnings == null) || warnings.isEmpty()) {
            warnings = a_newWarning;
        }
        warnings = warnings + ", " + a_newWarning;
    }

    public List<BlackboardArtifact> findArtifactsBySubstring(StringObjectPropertyType item,
            BlackboardAttribute.ATTRIBUTE_TYPE attrType) throws TskCoreException {

        if (item.getValue() == null) {
            throw new TskCoreException("Error: Value field is null");
        }

        if (item.getCondition() == null) {
            addWarning("Warning: No condition given for " + attrType.getDisplayName() + " field, using substring comparison");
        } else if (item.getCondition() != ConditionTypeEnum.CONTAINS) {
            addWarning("Warning: Ignoring condition " + item.getCondition() + " for "
                    + attrType.getDisplayName() + " field and doing substring comparison");
        }

        List<BlackboardArtifact> hits = null;
        try {
            Case case1 = Case.getCurrentCase();
            SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();

            String[] parts = item.getValue().toString().split("##comma##");

            if ((item.getApplyCondition() == null)
                    || (item.getApplyCondition() == ConditionApplicationEnum.ANY)) {

                for (String part : parts) {
                    if (hits == null) {
                        hits = sleuthkitCase.getBlackboardArtifacts(
                                attrType,
                                part, false);
                    } else {
                        hits.addAll(sleuthkitCase.getBlackboardArtifacts(
                                attrType,
                                part, false));
                    }
                }
            } else if ((item.getApplyCondition() != null)
                    || (item.getApplyCondition() == ConditionApplicationEnum.ALL)) {

                boolean firstRound = true;
                for (String part : parts) {
                    if (firstRound) {
                        hits = sleuthkitCase.getBlackboardArtifacts(
                                attrType,
                                part, false);
                        firstRound = false;
                    } else if (hits != null) {
                        hits.retainAll(sleuthkitCase.getBlackboardArtifacts(
                                attrType,
                                part, false));
                    } else {
                        // After first round; hits is still null
                        // I don't think this should happen but if it does we're done
                        return new ArrayList<BlackboardArtifact>();
                    }
                }
            } else {
                throw new TskCoreException("Error: Can not apply NONE condition in search");
            }
        } catch (TskCoreException ex) {
            addWarning(ex.getLocalizedMessage());
        }

        return hits;
    }

    public static boolean compareStringObject(StringObjectPropertyType stringObj, String strField)
            throws TskCoreException {
        if (stringObj.getValue() == null) {
            throw new TskCoreException("Error: Value field is null");
        }

        String valueStr = stringObj.getValue().toString();
        ConditionTypeEnum condition = stringObj.getCondition();
        ConditionApplicationEnum applyCondition = stringObj.getApplyCondition();

        return compareStringObject(valueStr, condition, applyCondition, strField);
    }

    public static boolean compareStringObject(String valueStr, ConditionTypeEnum condition,
            ConditionApplicationEnum applyCondition, String strField)
            throws TskCoreException {

        if (valueStr == null) {
            throw new TskCoreException("Error: Value field is null");
        }

        String[] parts = valueStr.split("##comma##");
        String lowerFieldName = strField.toLowerCase();
        boolean result = false;

        for (String value : parts) {
            boolean partialResult;
            if ((condition == null)
                    || (condition == ConditionTypeEnum.EQUALS)) {
                partialResult = value.equalsIgnoreCase(strField);
            } else if (condition == ConditionTypeEnum.DOES_NOT_EQUAL) {
                partialResult = !value.equalsIgnoreCase(strField);
            } else if (condition == ConditionTypeEnum.CONTAINS) {
                partialResult = lowerFieldName.contains(value.toLowerCase());
            } else if (condition == ConditionTypeEnum.DOES_NOT_CONTAIN) {
                partialResult = !lowerFieldName.contains(value.toLowerCase());
            } else if (condition == ConditionTypeEnum.STARTS_WITH) {
                partialResult = !lowerFieldName.contains(value.toLowerCase());
            } else if (condition == ConditionTypeEnum.ENDS_WITH) {
                partialResult = !lowerFieldName.contains(value.toLowerCase());
            } else {
                throw new TskCoreException("Could not process condition " + condition.value() + " on " + value);
            }

            // Do all the short-circuiting
            if (applyCondition == ConditionApplicationEnum.NONE) {
                if (partialResult == true) {
                    // Failed
                    return false;
                }
            } else if (applyCondition == ConditionApplicationEnum.ALL) {
                if (partialResult == false) {
                    // Failed
                    return false;
                }
            } else {
                // Default is "any"
                if (partialResult == true) {
                    return true;
                }
            }
        }

        // At this point we're done and didn't short-circuit, so ALL or NONE conditions were true,
        // and ANY was false
        if ((applyCondition == ConditionApplicationEnum.NONE)
                || (applyCondition == ConditionApplicationEnum.ALL)) {
            return true;
        }
        return false;
    }

    public String getPrintableWarnings() {
        String warningsToPrint = "";
        if ((getWarnings() != null)
                && (!getWarnings().isEmpty())) {
            warningsToPrint = " (" + getWarnings() + ")";
        }
        return warningsToPrint;
    }
}
