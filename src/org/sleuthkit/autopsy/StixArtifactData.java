/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.sleuthkit.autopsy;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
/**
 *
 */
public class StixArtifactData {
    private AbstractFile file;
    private String observableId;
    private String objType;
    
    public StixArtifactData(AbstractFile a_file, String a_observableId, String a_objType){
        file = a_file;
        observableId = a_observableId;
        objType = a_objType;
    }
    
    public StixArtifactData(long a_objId, String a_observableId, String a_objType){
        Case case1 = Case.getCurrentCase();
        SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();
        try{
            file = sleuthkitCase.getAbstractFileById(a_objId);
        }
        catch(TskCoreException ex){
            file = null;
        }
        observableId = a_observableId;
        objType = a_objType;
    }
    
    public void createArtifact(String a_title) throws TskCoreException{
        Collection<BlackboardAttribute> attrs = new ArrayList<BlackboardAttribute>();
                            
        String setName;
        if(a_title != null){
            setName = "STIX Indicator - " + a_title;
        }
        else{
            setName = "STIX Indicator - (no title)";
        }
        
        BlackboardArtifact bba = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT);
        bba.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), "Stix", setName));
        bba.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), "Stix", observableId));
        bba.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_CATEGORY.getTypeID(), "Stix", objType));
    }
    
    public void print(){
        System.out.println("  " + observableId + " " + file.getName());
    }
}
