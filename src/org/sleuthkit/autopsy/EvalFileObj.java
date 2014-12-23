/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy;

import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;

import java.util.List;
import java.util.ArrayList;
import java.util.Date;
import java.util.TimeZone;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import org.mitre.cybox.common_2.ConditionApplicationEnum;

import org.mitre.cybox.objects.FileObjectType;
import org.mitre.cybox.objects.WindowsExecutableFileObjectType;
import org.mitre.cybox.common_2.ConditionTypeEnum;
import org.mitre.cybox.common_2.DatatypeEnum;
import org.mitre.cybox.common_2.HashType;
import org.mitre.cybox.common_2.DateTimeObjectPropertyType;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.UnsignedLongObjectPropertyType;

/**
 *
 */

public class EvalFileObj extends EvaluatableObject {

    private final FileObjectType obj;

    public EvalFileObj(FileObjectType a_obj, String a_id, String a_spacing) {
        obj = a_obj;
        id = a_id;
        spacing = a_spacing;
    }

    @Override
    public synchronized ObservableResult evaluate() {

        Case case1 = Case.getCurrentCase();
        SleuthkitCase sleuthkitCase = case1.getSleuthkitCase();

        setWarnings("");
        String whereClause = "";

        if (obj.getSizeInBytes() != null) {
            try {
                String newClause = processULongObject(obj.getSizeInBytes(), "size");
                whereClause = addClause(whereClause, newClause);
            } catch (TskCoreException ex) {
                addWarning(ex.getLocalizedMessage());
            }
        }

        if (obj.getFileName() != null) {
            try {
                String newClause = processStringObject(obj.getFileName(), "name");
                whereClause = addClause(whereClause, newClause);
            } catch (TskCoreException ex) {
                addWarning(ex.getLocalizedMessage());
            }
        }

        if (obj.getFileExtension() != null) {
            if ((obj.getFileExtension().getCondition() == null)
                    || (obj.getFileExtension().getCondition() == ConditionTypeEnum.EQUALS)) {
                String newClause = "name LIKE \'%" + obj.getFileExtension().getValue() + "\'";
                whereClause = addClause(whereClause, newClause);
            } else {
                addWarning(
                        "Could not process condition " + obj.getFileExtension().getCondition().value() + " on file extension");
            }
        }

        if (obj.getFilePath() != null) {
            try {
                String newClause = processStringObject(obj.getFilePath(), "parent_path");
                whereClause = addClause(whereClause, newClause);
            } catch (TskCoreException ex) {
                addWarning(ex.getLocalizedMessage());
            }
        }

        if (obj.getCreatedTime() != null) {
            try {
                String newClause = processTimestampObject(obj.getCreatedTime(), "crtime");
                whereClause = addClause(whereClause, newClause);
            } catch (TskCoreException ex) {
                addWarning(ex.getLocalizedMessage());
            }
        }

        if (obj.getModifiedTime() != null) {
            try {
                String newClause = processTimestampObject(obj.getModifiedTime(), "mtime");
                whereClause = addClause(whereClause, newClause);
            } catch (TskCoreException ex) {
                addWarning(ex.getLocalizedMessage());
            }
        }

        if (obj.getAccessedTime() != null) {
            try {
                String newClause = processTimestampObject(obj.getAccessedTime(), "atime");
                whereClause = addClause(whereClause, newClause);
            } catch (TskCoreException ex) {
                addWarning(ex.getLocalizedMessage());
            }
        }

        if (obj.getHashes() != null) {
            for (HashType h : obj.getHashes().getHashes()) {
                if (h.getSimpleHashValue() != null) {
                    if (h.getType().getValue().equals("MD5")) {
                        String newClause = "md5=\'" + h.getSimpleHashValue().getValue() + "\'";
                        whereClause = addClause(whereClause, newClause);
                    } else {
                        addWarning("Could not process hash type " + h.getType());
                    }
                } else {
                    addWarning("Could not process non-simple hash value");
                }
            }
        }

        if (obj instanceof WindowsExecutableFileObjectType) {
            WindowsExecutableFileObjectType winExe = (WindowsExecutableFileObjectType) obj;
            if (winExe.getHeaders() != null) {
                if (winExe.getHeaders().getFileHeader() != null) {
                    if (winExe.getHeaders().getFileHeader().getTimeDateStamp() != null) {
                        try {
                            String result = convertTimestampString(winExe.getHeaders().getFileHeader().getTimeDateStamp().getValue().toString());
                            String newClause = processNumericFields(result,
                                    winExe.getHeaders().getFileHeader().getTimeDateStamp().getCondition(),
                                    winExe.getHeaders().getFileHeader().getTimeDateStamp().getApplyCondition(),
                                    "crtime");
                            whereClause = addClause(whereClause, newClause);
                        } catch (TskCoreException ex) {
                            addWarning(ex.getLocalizedMessage());
                        }
                    }
                }
            }
        }

        String unsupportedFields = listUnsupportedFields();
        if (!unsupportedFields.isEmpty()) {
            addWarning("Unsupported fields: " + unsupportedFields);
        }

        String warningsToPrint = getPrintableWarnings();

        if (whereClause.length() > 0) {
            try {
                List<AbstractFile> matchingFiles = sleuthkitCase.findAllFilesWhere(whereClause);

                if (!matchingFiles.isEmpty()) {

                    if (listSecondaryFields().isEmpty()) {

                        List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                        for (AbstractFile a : matchingFiles) {
                            artData.add(new StixArtifactData(a, id, "FileObject"));
                        }

                        return new ObservableResult(id, "FileObject: Found " + matchingFiles.size() + " matches for " + whereClause + warningsToPrint,
                                spacing, ObservableResult.ObservableState.TRUE, artData);
                    } else {

                        // At some point we may want to tag the matching files in Autopsy, so keep track of them
                        List<AbstractFile> secondaryHits = new ArrayList<AbstractFile>();

                        for (AbstractFile file : matchingFiles) {
                            boolean passedTests = true;

                            if (obj.isIsMasqueraded() != null) {
                                List<BlackboardArtifact> arts = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_EXT_MISMATCH_DETECTED);
                                boolean isMasq = false;
                                if (!arts.isEmpty()) {
                                    isMasq = true;
                                }

                                if (obj.isIsMasqueraded() != isMasq) {
                                    passedTests = false;
                                }

                            }

                            if (obj.getFileFormat() != null) {

                                boolean foundMatch = false;
                                List<BlackboardArtifact> arts = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_GEN_INFO);
                                for (BlackboardArtifact artifact : arts) {
                                    for (BlackboardAttribute attr : artifact.getAttributes()) {
                                        if (attr.getAttributeTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_FILE_TYPE_SIG.getTypeID()) {
                                            if (attr.getValueString().equalsIgnoreCase(obj.getFileFormat().getValue().toString())) {
                                                foundMatch = true;
                                            }
                                        }
                                    }
                                }

                                if (!foundMatch) {
                                    passedTests = false;
                                }
                            }

                            if (passedTests) {
                                secondaryHits.add(file);
                            }
                        }

                        if (secondaryHits.isEmpty()) {

                            return new ObservableResult(id, "FileObject: Found " + matchingFiles.size() + " matches for " + whereClause
                                    + " but none for secondary tests on " + listSecondaryFields() + warningsToPrint,
                                    spacing, ObservableResult.ObservableState.FALSE, null);
                        } else {
                            List<StixArtifactData> artData = new ArrayList<StixArtifactData>();
                            for (AbstractFile a : secondaryHits) {
                                artData.add(new StixArtifactData(a, id, "FileObject"));
                            }
                            return new ObservableResult(id, "FileObject: Found " + secondaryHits.size() + " matches for " + whereClause
                                    + " and secondary tests on " + listSecondaryFields() + warningsToPrint,
                                    spacing, ObservableResult.ObservableState.TRUE, artData);
                        }
                    }
                } else {
                    return new ObservableResult(id, "FileObject: Found no matches for " + whereClause + warningsToPrint,
                            spacing, ObservableResult.ObservableState.FALSE, null);
                }
            } catch (TskCoreException ex) {
                return new ObservableResult(id, "FileObject: Exception during evaluation: " + ex.getLocalizedMessage(),
                        spacing, ObservableResult.ObservableState.INDETERMINATE, null);
            }
        } else {

        }

        return new ObservableResult(id, "FileObject: No evaluatable fields " + warningsToPrint, spacing,
                ObservableResult.ObservableState.INDETERMINATE, null);
    }

    private String listSecondaryFields() {
        String secondaryFields = "";

        if (obj.isIsMasqueraded() != null) {
            secondaryFields += "is_masqueraded ";
        }

        if (obj.getFileFormat() != null) {
            secondaryFields += "File_Format ";
        }

        return secondaryFields;
    }

    private String listUnsupportedFields() {
        String unsupportedFields = "";

        if (obj.isIsPacked() != null) {
            unsupportedFields += "is_packed ";
        }
        if (obj.getDevicePath() != null) {
            unsupportedFields += "Device_Path ";
        }
        if (obj.getFullPath() != null) {
            unsupportedFields += "Full_Path ";
        }
        if (obj.getMagicNumber() != null) {
            unsupportedFields += "Magic_Number ";
        }
        if (obj.getDigitalSignatures() != null) {
            unsupportedFields += "Digital_Signatures ";
        }
        if (obj.getFileAttributesList() != null) {
            unsupportedFields += "File_Attributes_List ";
        }
        if (obj.getPermissions() != null) {
            unsupportedFields += "Permissions ";
        }
        if (obj.getUserOwner() != null) {
            unsupportedFields += "User_Owner ";
        }
        if (obj.getPackerList() != null) {
            unsupportedFields += "Packer_List ";
        }
        if (obj.getPeakEntropy() != null) {
            unsupportedFields += "Peak_Entropy ";
        }
        if (obj.getSymLinks() != null) {
            unsupportedFields += "Sym_Links ";
        }
        if (obj.getByteRuns() != null) {
            unsupportedFields += "Bytes_Runs ";
        }
        if (obj.getExtractedFeatures() != null) {
            unsupportedFields += "Extracted_Features ";
        }
        if (obj.getEncryptionAlgorithm() != null) {
            unsupportedFields += "Encryption_Algorithm ";
        }
        if (obj.getDecryptionKey() != null) {
            unsupportedFields += "Decryption_Key ";
        }
        if (obj.getCompressionMethod() != null) {
            unsupportedFields += "Compression_Method ";
        }
        if (obj.getCompressionVersion() != null) {
            unsupportedFields += "Compression_Version ";
        }
        if (obj.getCompressionComment() != null) {
            unsupportedFields += "Compression_Comment ";
        }

        return unsupportedFields;
    }

    private static long convertTimestamp(String timeStr) throws ParseException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        Date parsedDate = dateFormat.parse(timeStr);

        Long unixTime = parsedDate.getTime() / 1000;

        return unixTime;
    }

    private static String processULongObject(UnsignedLongObjectPropertyType longObj, String fieldName)
            throws TskCoreException {

        return processNumericFields(longObj.getValue().toString(), longObj.getCondition(),
                longObj.getApplyCondition(), fieldName);
    }

    private static String processNumericFields(String valueStr, ConditionTypeEnum typeCondition,
            ConditionApplicationEnum applyCondition, String fieldName)
            throws TskCoreException {

        if ((typeCondition == null)
                || ((typeCondition != ConditionTypeEnum.INCLUSIVE_BETWEEN)
                && (typeCondition != ConditionTypeEnum.EXCLUSIVE_BETWEEN))) {

            String fullClause = "";

            if (valueStr.isEmpty()) {
                throw new TskCoreException("Empty value field");
            }

            String[] parts = valueStr.split("##comma##");

            for (String valuePart : parts) {
                String partialClause;

                if ((typeCondition == null)
                        || (typeCondition == ConditionTypeEnum.EQUALS)) {

                    partialClause = fieldName + "=" + valuePart;
                } else if (typeCondition == ConditionTypeEnum.DOES_NOT_EQUAL) {
                    partialClause = fieldName + "!=" + valuePart;
                } else if (typeCondition == ConditionTypeEnum.GREATER_THAN) {
                    partialClause = fieldName + ">" + valuePart;
                } else if (typeCondition == ConditionTypeEnum.GREATER_THAN_OR_EQUAL) {
                    partialClause = fieldName + ">=" + valuePart;
                } else if (typeCondition == ConditionTypeEnum.LESS_THAN) {
                    partialClause = fieldName + "<" + valuePart;
                } else if (typeCondition == ConditionTypeEnum.LESS_THAN_OR_EQUAL) {
                    partialClause = fieldName + "<=" + valuePart;
                } else {
                    throw new TskCoreException("Could not process condition " + typeCondition.value() + " on " + fieldName);
                }

                if (fullClause.isEmpty()) {

                    if (parts.length > 1) {
                        fullClause += "( ";
                    }
                    if (applyCondition == ConditionApplicationEnum.NONE) {
                        fullClause += " NOT ";
                    }
                    fullClause += partialClause;
                } else {
                    if (applyCondition == ConditionApplicationEnum.ALL) {
                        fullClause += " AND " + partialClause;
                    } else if (applyCondition == ConditionApplicationEnum.NONE) {
                        fullClause += " AND NOT " + partialClause;
                    } else {
                        fullClause += " OR " + partialClause;
                    }
                }
            }

            if (parts.length > 1) {
                fullClause += " )";
            }

            return fullClause;
        } else {
            // I don't think apply conditions make sense for these two.
            if (typeCondition == ConditionTypeEnum.INCLUSIVE_BETWEEN) {
                String[] parts = valueStr.split("##comma##");
                if (parts.length != 2) {
                    throw new TskCoreException("Unexpected number of arguments in INCLUSIVE_BETWEEN on " + fieldName
                            + "(" + valueStr + ")");
                }
                return (fieldName + ">=" + parts[0] + " AND " + fieldName + "<=" + parts[1]);
            } else {
                String[] parts = valueStr.split("##comma##");
                if (parts.length != 2) {
                    throw new TskCoreException("Unexpected number of arguments in EXCLUSIVE_BETWEEN on " + fieldName
                            + "(" + valueStr + ")");
                }
                return (fieldName + ">" + parts[0] + " AND " + fieldName + "<" + parts[1]);
            }
        }
    }

    private static String processStringObject(StringObjectPropertyType stringObj, String fieldName)
            throws TskCoreException {

        String fullClause = "";

        if (stringObj.getValue().toString().isEmpty()) {
            throw new TskCoreException("Empty value field");
        }

        String[] parts = stringObj.getValue().toString().split("##comma##");

        for (String value : parts) {
            String partialClause;
            if ((stringObj.getCondition() == null)
                    || (stringObj.getCondition() == ConditionTypeEnum.EQUALS)) {
                partialClause = fieldName + "=\'" + value + "\'";
            } else if (stringObj.getCondition() == ConditionTypeEnum.DOES_NOT_EQUAL) {
                partialClause = fieldName + " !=\'%" + value + "%\'";
            } else if (stringObj.getCondition() == ConditionTypeEnum.CONTAINS) {
                partialClause = fieldName + " LIKE \'%" + value + "%\'";
            } else if (stringObj.getCondition() == ConditionTypeEnum.DOES_NOT_CONTAIN) {
                partialClause = fieldName + " NOT LIKE \'%" + value + "%\'";
            } else if (stringObj.getCondition() == ConditionTypeEnum.STARTS_WITH) {
                partialClause = fieldName + " LIKE \'" + value + "%\'";
            } else if (stringObj.getCondition() == ConditionTypeEnum.ENDS_WITH) {
                partialClause = fieldName + " LIKE \'%" + value + "\'";
            } else {
                throw new TskCoreException("Could not process condition " + stringObj.getCondition().value() + " on " + fieldName);
            }

            if (fullClause.isEmpty()) {

                if (parts.length > 1) {
                    fullClause += "( ";
                }
                if (stringObj.getApplyCondition() == ConditionApplicationEnum.NONE) {
                    fullClause += " NOT ";
                }
                fullClause += partialClause;
            } else {
                if (stringObj.getApplyCondition() == ConditionApplicationEnum.ALL) {
                    fullClause += " AND " + partialClause;
                } else if (stringObj.getApplyCondition() == ConditionApplicationEnum.NONE) {
                    fullClause += " AND NOT " + partialClause;
                } else {
                    fullClause += " OR " + partialClause;
                }
            }
        }

        if (parts.length > 1) {
            fullClause += " )";
        }

        return fullClause;
    }

    private static String processTimestampObject(DateTimeObjectPropertyType dateObj, String fieldName)
            throws TskCoreException {

        if (DatatypeEnum.DATE_TIME == dateObj.getDatatype()) {

            // Change the string into unix timestamps
            String result = convertTimestampString(dateObj.getValue().toString());
            return processNumericFields(result, dateObj.getCondition(), dateObj.getApplyCondition(), fieldName);

        } else {
            throw new TskCoreException("Found non DATE_TIME field on " + fieldName);
        }
    }

    private static String convertTimestampString(String timestampStr)
            throws TskCoreException {
        try {
            String result = "";
            if (timestampStr.length() > 0) {
                String[] parts = timestampStr.split("##comma##");

                for (int i = 0; i < parts.length - 1; i++) {
                    long unixTime = convertTimestamp(parts[i]);
                    result += unixTime + "##comma##";
                }
                result += convertTimestamp(parts[parts.length - 1]);
            }
            return result;
        } catch (java.text.ParseException ex) {
            throw new TskCoreException("Error parsing timestamp string " + timestampStr);
        }

    }

    private static String addClause(String a_clause, String a_newClause) {

        if ((a_clause == null) || a_clause.isEmpty()) {
            return a_newClause;
        }

        return (a_clause + " AND " + a_newClause);
    }

    private static String addWarning(String a_warnings, String a_newWarning) {
        if ((a_warnings == null) || a_warnings.isEmpty()) {
            return a_newWarning;
        }
        return a_warnings + ", " + a_newWarning;
    }
}
