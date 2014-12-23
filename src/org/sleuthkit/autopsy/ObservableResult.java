/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy;

import java.util.List;
import java.util.ArrayList;

import org.mitre.cybox.cybox_2.OperatorTypeEnum;

/**
 *
 */
public class ObservableResult {

    public enum ObservableState {

        TRUE("true         "),
        FALSE("false        "),
        INDETERMINATE("indeterminate");

        private final String label;

        private ObservableState(String s) {
            label = s;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private ObservableState state = null;
    private String description = "";
    private List<StixArtifactData> artifacts;

    /*
     public ObservableResult(String a_description, ObservableState a_state){
     state = a_state;
     description = a_description;
     }*/
    public ObservableResult(String a_id, String a_desc, String a_spacing,
            ObservableState a_state, List<StixArtifactData> a_artifacts) {
        state = a_state;
        description = a_spacing + a_id + "\t" + a_state + "\t" + a_desc + "\r\n";
        artifacts = a_artifacts;
    }

    public ObservableResult(OperatorTypeEnum a_operator, String a_spacing) {
        state = ObservableState.INDETERMINATE;
        description = a_spacing + a_operator + "\r\n";
        artifacts = new ArrayList<StixArtifactData>();
    }

    public ObservableState getState() {
        return state;
    }

    public boolean isTrue() {
        return (state == ObservableState.TRUE);
    }

    public boolean isFalse() {
        return (state == ObservableState.FALSE);
    }

    public String getDescription() {
        return description;
    }

    public List<StixArtifactData> getArtifacts() {
        return artifacts;
    }

    public void addResult(ObservableResult a_result, OperatorTypeEnum a_operator) {
        addResult(a_result.getDescription(), a_result.getState(),
                a_result.getArtifacts(), a_operator);
    }

    /**
     * Add a new result to the current state.
     *
     * @param a_description
     * @param a_state
     * @param a_operator
     */
    private void addResult(String a_description, ObservableState a_state,
            List<StixArtifactData> a_artifacts, OperatorTypeEnum a_operator) {

        addToDesc(a_description);

        if (a_operator == OperatorTypeEnum.AND) {

            if (a_state == ObservableState.FALSE) {
                // If we now have a false, the whole thing is false regardless of previous state.
                // Clear out any existing artifacts.
                state = ObservableState.FALSE;
                artifacts.clear();
            } else if (a_state == ObservableState.INDETERMINATE) {
                // Don't change the current state, and don't save the new artifacts
                // (though there probably wouldn't be any)
            } else {
                if (state == ObservableState.FALSE) {
                    // Previous state false + new state true => stay false
                } else if (state == ObservableState.TRUE) {
                    // Previous state true + new state true => stay true and add artifacts
                    if (a_artifacts != null) {
                        artifacts.addAll(a_artifacts);
                    }
                } else {
                    // If the previous state was indeterminate, change it to true and add artifacts
                    state = ObservableState.TRUE;
                    if (a_artifacts != null) {
                        artifacts.addAll(a_artifacts);
                    }
                }
            }
        } else {
            if (a_state == ObservableState.TRUE) {
                // If we now have a true, the whole thing is true regardless of previous state.
                // Add the new artifacts.
                state = ObservableState.TRUE;
                if (a_artifacts != null) {
                    artifacts.addAll(a_artifacts);
                }
            } else if (a_state == ObservableState.INDETERMINATE) {
                // Don't change the current state and don't record it to the
                // description string (later we should save these in some way)
            } else {
                if (state == ObservableState.FALSE) {
                    // Previous state false + new state false => stay false
                } else if (state == ObservableState.TRUE) {
                    // Previous state true + new state false => stay true
                } else {
                    // Previous state indeterminate + new state false => change to false
                    state = ObservableState.FALSE;
                }
            }
        }

    }

    private void addToDesc(String a_desc) {
        if (description == null) {
            description = a_desc;
        } else {
            description += a_desc;
        }
    }
}
