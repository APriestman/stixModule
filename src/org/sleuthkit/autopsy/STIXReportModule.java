/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.sleuthkit.autopsy;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.logging.Level;
import java.io.BufferedWriter;
import java.io.FileWriter;
import javax.swing.JPanel;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObservableCompositionType;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.stix_1.STIXPackage;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.report.GeneralReportModule;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.openide.util.NbBundle;
import org.openide.filesystems.FileUtil;
import org.sleuthkit.autopsy.report.ReportProgressPanel;
import org.sleuthkit.datamodel.TskCoreException;

import java.util.Random;
import org.mitre.cybox.cybox_2.OperatorTypeEnum;
import org.mitre.cybox.objects.FileObjectType;
import static org.sleuthkit.autopsy.StixPrinter.printFile;

/**
 *
 */
public class STIXReportModule implements GeneralReportModule{
   
    private static final Logger logger = Logger.getLogger(STIXReportModule.class.getName());
    private static STIXReportModule instance = null;
    private Case currentCase;
    private SleuthkitCase skCase;
    private String reportPath;
    private String reportDir;
    
    private final Map<String, ObjectType> idToObjectMap = new HashMap<String, ObjectType>();
    private final Map<String, ObservableResult> idToResult = new HashMap<String, ObservableResult>();
    
    //private static final String stixFile = "C:/stix/STIX_phishing.xml";
    private static final String stixFile = "C:/stix/Appendix_G_IOCs_No_OpenIOC.xml";
    private final Random random = new Random();
    
    private final boolean debugPrint = false;
    private final boolean skipShortCircuit = true;
    
    private BufferedWriter output = null;
    
    // Hidden constructor for the report
    private STIXReportModule() {
    }

    // Get the default implementation of this report
    public static synchronized STIXReportModule getDefault() {
        if (instance == null) {
            instance = new STIXReportModule();
        }
        return instance;
    }
    
    /**
     * Generates a body file format report for use with the MAC time tool.
     *
     * @param path path to save the report
     * @param progressPanel panel to update the report's progress
     */
    @Override
    public void generateReport(String path, ReportProgressPanel progressPanel) {
        // Start the progress bar and setup the report
        progressPanel.setIndeterminate(false);
        progressPanel.start();
        progressPanel.updateStatusLabel(NbBundle.getMessage(this.getClass(), "STIXReportModule.progress.readSTIX"));
        reportPath = path + getFilePath();
        currentCase = Case.getCurrentCase();
        skCase = currentCase.getSleuthkitCase();
    
        random.setSeed(590);
        
        // Set up the output file
        try{
            File file = new File(reportPath);
            output = new BufferedWriter(new FileWriter(file));
        }
        catch(IOException ex){
            logger.log(Level.SEVERE, "Unable to open STIX report file " + reportPath);
            return;
        }
        
        // Load the STIX file
        STIXPackage stix = null;
        try{
            stix = loadSTIXFile(stixFile);
        }
        catch(TskCoreException ex){
            logger.log(Level.SEVERE, "Unable to load STIX file " + stixFile);
            return;
        }
        
        // Save any observables listed up front
        processObservables(stix);

        // Process the indicators
        
        processIndicators(stix);
        
        progressPanel.increment();

        if(output != null){
            try{
                output.close();
            }
            catch(IOException ex){
                logger.log(Level.SEVERE, "Error closing STIX report file " + reportPath);
            }
        }
        progressPanel.complete();
        
        /*
        System.out.println("\nStored values");
        for(String s:idToResult.keySet()){
            if(idToResult.get(s).isTrue()){
                System.out.println("  " + s + "  " + idToResult.get(s).getDescription());
            }
            else if(idToResult.get(s).isFalse()){
                System.out.println("  " + s + "  False");
            }
            else{
                System.out.println("  " + s + "  Indeterminate");
            }
        }*/
        
    }
    
    /**
     * Load a STIX-formatted XML file.
     * @param stixFileName Name of the STIX file to unmarshal
     * @return Unmarshalled file contents
     * @throws TskCoreException 
     */
    private STIXPackage loadSTIXFile(String stixFileName) throws TskCoreException{
        try {
            // Create STIXPackage object from xml.
            File file = new File(stixFileName);
            JAXBContext jaxbContext = JAXBContext.newInstance("org.mitre.stix.stix_1:org.mitre.stix.common_1:org.mitre.stix.indicator_2:" +
                            "org.mitre.cybox.objects:org.mitre.cybox.cybox_2:org.mitre.cybox.common_2");
            Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            STIXPackage stix = (STIXPackage) jaxbUnmarshaller.unmarshal(file);
            return stix;
        }
        catch(JAXBException ex){
            System.out.println("Exception: " + ex.getLocalizedMessage());
            logger.log(Level.SEVERE, "Unable to load STIX file " + stixFileName + ": " + ex.getLocalizedMessage());
            throw new TskCoreException("Error loading STIX file (" + ex.getLocalizedMessage() + ")");
        }        
    }
    
    /**
     * Process the list of observables.
     * For each observable, save it in a map using the ID as key.
     * @param stix STIXPackage 
     */
    
    private void processObservables(STIXPackage stix){
        if(stix.getObservables() != null){
            List<Observable> obs = stix.getObservables().getObservables();
            for(Observable o:obs){
                if(o.getId() != null){
                    saveToObjectMap(o);
                }
            }
        }
    }
    
    /**
     * 
     * @param stix STIXPackage
     */
    
    private void processIndicators(STIXPackage stix){
        if(stix.getIndicators() != null){
            List<IndicatorBaseType> s = stix.getIndicators().getIndicators();
            for(IndicatorBaseType t:s){
                if(t instanceof Indicator){
                    if(debugPrint){
                        System.out.print("\nIndicator");
                    }
                    Indicator ind = (Indicator)t;
                    if(debugPrint){
                        if(ind.getTitle() != null){
                            System.out.println(" - " + ind.getTitle());
                        }
                        else{
                            System.out.println("");
                        }

                        if(ind.getDescription() != null){
                            String desc = ind.getDescription().getValue();
                            desc = desc.trim();
                            System.out.println(desc);
                        }
                    }
                    if(ind.getObservable() != null) {
                        if(ind.getObservable().getObject() != null){
                            //System.out.println("  Object");
                            //processObject(ind.getObservable().getObject(), "  ");
                            //ind.getObservable().getObject().
                            System.out.println("single observable");
                            try{
                                ObservableResult result = evaluateSingleObservable(ind.getObservable(), "");
                                if(result.isTrue()){
                                    printResults(ind, result.getDescription());
                                }
                            }
                            catch (TskCoreException ex){
                                System.out.println("Exception: " + ex.getLocalizedMessage());
                            }
                        }
                        else if(ind.getObservable().getObservableComposition() != null){
                            //processComp(ind.getObservable().getObservableComposition(), "  ");
                            try{
                                ObservableResult result = evaluateObservableComposition(ind.getObservable().getObservableComposition(), "  ");
                                
                                //if(result.isTrue()){
                                    printResults(ind, result.getDescription());
                                //}
                            }
                            catch (TskCoreException ex){
                                System.out.println("Exception: " + ex.getLocalizedMessage());
                            }
                        }
                        //processObservable(ind.getObservable(), "  ");
                    }
                }
                else{
                    if(debugPrint){
                        System.out.println("Not an indicator");
                    }
                }
            }
        }        
    }
    
    private void printResults(Indicator ind, String resultStr){
        boolean printToScreen = false;
        if(output != null){
            try{
                if(printToScreen){
                    System.out.println("################\nFound indicator:\n");
                }
                output.write("################\r\nFound indicator:\r\n");
                if(ind.getTitle() != null){
                    if(printToScreen){
                        System.out.println(ind.getTitle());
                    }
                    output.write(ind.getTitle() + "\r\n");
                }
                else{
                    if(printToScreen){
                        System.out.println("");
                    }
                    output.write("\r\n");
                }

                if(ind.getDescription() != null){
                    String desc = ind.getDescription().getValue();
                    desc = desc.trim();
                    if(printToScreen){
                        System.out.println(desc);
                    }
                    output.write(desc + "\r\n");
                }
                if(printToScreen){
                    System.out.println("\nObservables found:\n" + resultStr + "\n");
                }
                output.write("\r\nObservables found:\r\n" + resultStr + "\r\n\r\n");
            }
            catch(IOException ex){
                logger.log(Level.SEVERE, "Error writing to STIX report file " + reportPath);
            }
        }        
    }
    
    private String makeMapKey(Observable obs){
        QName idQ;
        if(obs.getId() != null){
            idQ = obs.getId();
        }
        else if(obs.getIdref() != null){
            idQ = obs.getIdref();
        }
        else{
            return "";
        }
        
        return idQ.getLocalPart();
    }
    
    private void saveToObjectMap(Observable obs){

        if(obs.getObject() != null){
            idToObjectMap.put(makeMapKey(obs), obs.getObject());
        }
    }
     
    private ObservableResult evaluateObservableComposition(ObservableCompositionType comp, String spacing) throws TskCoreException{
        if(comp.getOperator() == null){
            throw new TskCoreException("No operator found in composition");
        }
        
        if(debugPrint){
            System.out.println(spacing + "Composition (" + comp.getOperator().value() + ")");
        }
        
        if(comp.getObservables() != null){
            List<Observable> obsList = comp.getObservables();
        
            if(comp.getOperator() == OperatorTypeEnum.AND){
                ObservableResult result = new ObservableResult(OperatorTypeEnum.AND, spacing);
                for(Observable o:obsList){
                    
                    ObservableResult newResult;
                    if(o.getObservableComposition() != null){
                        newResult = evaluateObservableComposition(o.getObservableComposition(), spacing + "  ");
                        if(result == null){
                            result = newResult;
                        }
                        else{
                            result.addResult(newResult, OperatorTypeEnum.AND);
                        }
                    }
                    else{
                        newResult = evaluateSingleObservable(o, spacing + "  ");
                        if(result == null){
                            result = newResult;
                        }
                        else{
                            result.addResult(newResult, OperatorTypeEnum.AND);
                        }                    
                    }
                    
                    if((! skipShortCircuit) && !result.isFalse()){
                        // For testing purposes, may not want to short-circuit
                        if(debugPrint){
                            System.out.println(spacing + "AND composition result: false");
                        }
                        return result;
                    }
                }
                // At this point, all comparisions should have been true (or indeterminate)
                if(result == null){
                    // This really shouldn't happen, but if we have an empty composition,
                    // indeterminate seems like a reasonable result
                    return new ObservableResult("", "", spacing, ObservableResult.ObservableState.INDETERMINATE);
                }
                if(result.isTrue()){
                    if(debugPrint){
                        System.out.println(spacing + "AND composition result: true");
                    }
                    return result;
                }
                else{
                    if(debugPrint){
                        System.out.println(spacing + "AND composition result: false/indeterminate");
                    }
                    return result;
                }
            }
            else{
                ObservableResult result = new ObservableResult(OperatorTypeEnum.OR, spacing);
                for(Observable o:obsList){

                    ObservableResult newResult;
                    if(o.getObservableComposition() != null){
                        newResult = evaluateObservableComposition(o.getObservableComposition(), spacing + "  ");
                        if(result == null){
                            result = newResult;
                        }
                        else{
                            result.addResult(newResult, OperatorTypeEnum.OR);
                        }
                    }
                    else{
                        newResult = evaluateSingleObservable(o, spacing + "  ");
                        if(result == null){
                            result = newResult;
                        }
                        else{
                            result.addResult(newResult, OperatorTypeEnum.OR);
                        }
                    }
                    
                    if((! skipShortCircuit) && result.isTrue()){
                        // For testing, may not want to short-circuit
                        if(debugPrint){
                            System.out.println(spacing + "OR composition result: true");
                        }
                        return result;
                    }
                }
                // At this point, all comparisions were false (or indeterminate)
                if(result == null){
                    // This really shouldn't happen, but if we have an empty composition,
                    // indeterminate seems like a reasonable result
                    return new ObservableResult("", "", spacing, ObservableResult.ObservableState.INDETERMINATE);                   
                }
                if(result.isTrue()){
                    if(debugPrint){
                        System.out.println(spacing + "OR composition result: true");
                    }
                    return result;
                }
                else{
                    if(debugPrint){
                        System.out.println(spacing + "OR composition result: false/indeterminate");
                    }
                    return result;
                }
            }
        }
        else{
            throw new TskCoreException("No observables found in list");
        }
    }
    
    private ObservableResult evaluateSingleObservable(Observable obs, String spacing) throws TskCoreException{
        if(debugPrint){
            System.out.println(spacing + makeMapKey(obs));
        }
        
        // If we've already calculated this one, return the saved value
        if(idToResult.containsKey(makeMapKey(obs))){
            return idToResult.get(makeMapKey(obs));
        }
        
        if(obs.getIdref() == null){
            // We should have the object data right here. Save it to the map.
            if(obs.getId() != null){
                saveToObjectMap(obs);
            }
            
            if(obs.getObject() != null){
                
                ObservableResult result = evaluateObject(obs.getObject(), spacing, makeMapKey(obs));
                idToResult.put(makeMapKey(obs), result);
                return result;
            }
        }
        
        if(idToObjectMap.containsKey(makeMapKey(obs))){
            ObservableResult result = evaluateObject(idToObjectMap.get(makeMapKey(obs)), spacing, makeMapKey(obs));
            idToResult.put(makeMapKey(obs), result);
            return result;
        }
        
        throw new TskCoreException("Error loading/finding object for observable " + obs.getIdref());
    }
    
    /**
     * 
     * @param obj
     * @param spacing
     * @return 
     */
    private ObservableResult evaluateObject(ObjectType obj, String spacing, String id){
        
        EvaluatableObject evalObj = null;
       
        if(obj.getProperties() instanceof FileObjectType){
            evalObj = new EvalFileObj((FileObjectType)obj.getProperties(), id, spacing);
        }
        else{
            // Try to get the object type as a string
            String type = obj.getProperties().toString();
            type = type.substring(0, type.indexOf("@"));
            if((type.lastIndexOf(".") + 1) < type.length()){
                type = type.substring(type.lastIndexOf(".") + 1);
            }
            return new ObservableResult(id, "No parser for object type " + type, 
                    spacing, ObservableResult.ObservableState.INDETERMINATE);
        }
        
        if(evalObj != null){
            return evalObj.evaluate();
        }
        else{
            return new ObservableResult(id, "", spacing, 
                    ObservableResult.ObservableState.INDETERMINATE);
        }
        
        /*
        // Testing
        int x = random.nextInt();
        if((x % 4) == 0){
            if(debugPrint){
                System.out.println(spacing + "true");
            }
            String resultStr = id + "\r\n" + "Random number " + x + " => true\r\n";
            return new ObservableResult(resultStr, ObservableResult.ObservableState.TRUE);
        }
        else if((x % 4) == 1){
            if(debugPrint){
                System.out.println(spacing + "indeterminate\n");
            }
            return new ObservableResult("", ObservableResult.ObservableState.INDETERMINATE);
        }
        else{
            if(debugPrint){
                System.out.println(spacing + "false\n");
            }
            return new ObservableResult("", ObservableResult.ObservableState.FALSE);
        }*/
    }
    
    /*
        private void processObservable(Observable obs, String spacing){
            //System.out.println(spacing + "Observable");
            if(obs.getIdref() != null){
                //System.out.println(spacing + "Looking for " + obs.getIdref().getLocalPart());
                if(idToObjectMap.containsKey(obs.getIdref().getLocalPart())){
                    if(! processObject(idToObjectMap.get(obs.getIdref().getLocalPart()), spacing)){
                        System.out.println(spacing + "    No data for id: " + obs.getIdref().getLocalPart());
                    }
                }
                else{
                    System.out.println(spacing + "Could not find ID " + obs.getIdref().getLocalPart());
                }
            }
        }
        
        private void processComp(ObservableCompositionType comp, String spacing){
            if(debugPrint){
                System.out.print(spacing + "Composition");
            }
            if(comp.getOperator() != null){
                System.out.println(" (" + comp.getOperator().value() + ")");
            }
            
            if(comp.getObservables() != null){
                List<Observable> obsList = comp.getObservables();
                for(Observable o:obsList){
                    if(o.getObservableComposition() != null){
                        processComp(o.getObservableComposition(), spacing + "  ");
                    }
                    else if(o.getObject() != null){
                        //System.out.println(spacing + "  Object");
                        processObject(o.getObject(), spacing + "  ");
                    }
                    else{
                        processObservable(o, spacing + "  ");
                    }
                }
            }
        }    
        
        static boolean processObject(ObjectType o, String spacing){
            
            return(StixPrinter.printObject(o, spacing));

         
        }*/
    
    @Override
    public String getName() {
        String name = NbBundle.getMessage(this.getClass(), "STIXReportModule.getName.text");
        return name;
    }

    /*
    @Override
    public String getRelativeFilePath() {
        return "ReportKML.kml";
    }*/
    @Override
    public String getFilePath(){
        return "stix.txt";
    }
    
    @Override
    public String getExtension(){
        return "txt";
    }

    @Override
    public String getDescription() {
        String desc = NbBundle.getMessage(this.getClass(), "STIXReportModule.getDesc.text");
        return desc;
    }

    @Override
    public JPanel getConfigurationPanel() {
        return null; // No configuration panel
    }
    
}
