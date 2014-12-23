/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy;

import org.mitre.stix.indicator_2.*;
import org.mitre.stix.stix_1.*;
import org.mitre.cybox.common_2.*;
import org.mitre.stix.common_1.*;
import org.mitre.cybox.objects.*;
import org.mitre.cybox.cybox_2.*;

/**
 *
 */
public class StixPrinter {

    public StixPrinter() {

    }

    public static boolean printObject(ObjectType o, String spacing) {
        boolean printed = false;
        //System.out.println(spacing + "Object");
        if (o.getProperties() != null) {
            String type = o.getProperties().toString();
            type = type.substring(0, type.indexOf("@"));
            if ((type.lastIndexOf(".") + 1) < type.length()) {
                type = type.substring(type.lastIndexOf(".") + 1);
            }
            System.out.println(spacing + type);
        }

        if (o.getProperties() instanceof FileObjectType) {
            if (printFile((FileObjectType) o.getProperties(), spacing + "  ")) {
                printed = true;
            }
        }

        if (o.getProperties() instanceof WindowsRegistryKey) {
            if (printWindowsRegistryKey((WindowsRegistryKey) o.getProperties(), spacing + "  ")) {
                printed = true;
            }
        }

        if (o.getProperties() instanceof WindowsProcessObjectType) {
            if (printWindowsProcessObjectType((WindowsProcessObjectType) o.getProperties(), spacing + "  ")) {
                printed = true;
            }
        }

        if (o.getProperties() instanceof WindowsService) {
            if (printWindowsService((WindowsService) o.getProperties(), spacing + "  ")) {
                printed = true;
            }
        }

        return printed;
    }

    public static boolean printWindowsService(WindowsService o, String spacing) {
        boolean printed = false;

        if (o.getServiceName() != null) {
            if (o.getServiceName().getCondition() != null) {
                System.out.println(spacing + "Service name: " + o.getServiceName().getValue() + " ("
                        + o.getServiceName().getCondition().value() + ")");
                printed = true;
            } else {
                System.out.println(spacing + "Service name: " + o.getServiceName().getValue());
                printed = true;
            }
        }

        if (o.getDescriptionList() != null) {
            for (StringObjectPropertyType s : o.getDescriptionList().getDescriptions()) {
                System.out.println(spacing + "Description: " + s.getValue());
                printed = true;
            }
        }

        return printed;
    }

    public static boolean printWindowsProcessObjectType(WindowsProcessObjectType o, String spacing) {
        boolean printed = false;
        if (o.getHandleList() != null) {
            for (WindowsHandle h : o.getHandleList().getHandles()) {
                if (h.getName() != null) {
                    if (h.getName().getCondition() != null) {
                        System.out.println(spacing + "Handle name: " + h.getName().getValue() + " ("
                                + h.getName().getCondition().value() + ")");
                        printed = true;
                    } else {
                        System.out.println(spacing + "Handle name: " + h.getName().getValue());
                        printed = true;
                    }
                }
            }
        }
        return printed;
    }

    public static boolean printWindowsRegistryKey(WindowsRegistryKey o, String spacing) {
        boolean printed = false;
        if (o.getKey() != null) {
            if (o.getKey().getCondition() != null) {
                System.out.println(spacing + "Key: " + o.getKey().getValue() + " ("
                        + o.getKey().getCondition().value() + ")");
                printed = true;
            } else {
                System.out.println(spacing + "Key: " + o.getKey().getValue());
                printed = true;
            }
        }

        if (o.getHive() != null) {
            System.out.println(spacing + "Hive: " + o.getHive().getValue());
            printed = true;
        }

        if (o.getValues() != null) {
            for (RegistryValueType v : o.getValues().getValues()) {
                if (v.getData() != null) {
                    if (v.getData().getCondition() != null) {
                        System.out.println(spacing + "Value data: " + v.getData().getValue() + " ("
                                + v.getData().getCondition().value() + ")");
                        printed = true;
                    } else {
                        System.out.println(spacing + "Value data: " + v.getData().getValue());
                        printed = true;
                    }
                }
                if (v.getName() != null) {
                    if (v.getName().getCondition() != null) {
                        System.out.println(spacing + "Value name: " + v.getName().getValue() + " ("
                                + v.getName().getCondition().value() + ")");
                        printed = true;
                    } else {
                        System.out.println(spacing + "Value name: " + v.getName().getValue());
                        printed = true;
                    }
                }
            }
        }
        return printed;
    }

    public static boolean printFile(FileObjectType o, String spacing) {

        boolean printed = false;
        if (o.getFileName() != null) {
            if (o.getFileName().getCondition() != null) {
                System.out.println(spacing + "File name: " + o.getFileName().getValue()
                        + " (" + o.getFileName().getCondition().value() + ")");
                printed = true;
            } else {
                System.out.println(spacing + "File name: " + o.getFileName().getValue());
                printed = true;
            }
        }
        if (o.getFilePath() != null) {
            if (o.getFilePath().getCondition() != null) {
                System.out.println(spacing + "File path: " + o.getFilePath().getValue()
                        + " (" + o.getFilePath().getCondition().value() + ")");
                printed = true;
            } else {
                System.out.println(spacing + "File path: " + o.getFilePath().getValue());
                printed = true;
            }
        }
        if (o.getSizeInBytes() != null) {
            if (o.getSizeInBytes().getCondition() != null) {
                System.out.println(spacing + "File size: " + o.getSizeInBytes().getValue()
                        + " (" + o.getSizeInBytes().getCondition().value() + ")");
                printed = true;
            } else {
                System.out.println(spacing + "File size: " + o.getSizeInBytes().getValue());
                printed = true;
            }
        }
        if (o.getHashes() != null) {
            if (printHashes(o.getHashes(), spacing)) {
                printed = true;
            }
        }

        if (o instanceof WindowsExecutableFileObjectType) {
            if (printWindowsExecutableFileObjectType((WindowsExecutableFileObjectType) o, spacing)) {
                printed = true;
            }
        }
        return printed;
    }

    public static boolean printWindowsExecutableFileObjectType(WindowsExecutableFileObjectType o, String spacing) {
        boolean printed = false;
        if (o.getHeaders() != null) {
            if (o.getHeaders().getFileHeader() != null) {
                if (o.getHeaders().getFileHeader().getTimeDateStamp() != null) {
                    if (o.getHeaders().getFileHeader().getTimeDateStamp().getCondition() != null) {
                        System.out.println(spacing + "TimeDateStamp: " + o.getHeaders().getFileHeader().getTimeDateStamp().getValue() + " ("
                                + o.getHeaders().getFileHeader().getTimeDateStamp().getCondition().value() + ")");
                        printed = true;
                    } else {
                        System.out.println(spacing + "TimeDateStamp: " + o.getHeaders().getFileHeader().getTimeDateStamp().getValue());
                        printed = true;
                    }
                }
            }
        }

        if (o.getExports() != null) {
            if (o.getExports().getExportedFunctions() != null) {
                for (PEExportedFunctionType e : o.getExports().getExportedFunctions().getExportedFunctions()) {
                    if (e.getFunctionName() != null) {
                        if (e.getFunctionName().getCondition() != null) {
                            System.out.println(spacing + "Function name: " + e.getFunctionName().getValue() + " ("
                                    + e.getFunctionName().getCondition().value() + ")");
                            printed = true;
                        } else {
                            System.out.println(spacing + "Function name: " + e.getFunctionName().getValue());
                            printed = true;
                        }
                    }
                }
            }
        }

        return printed;
    }

    public static boolean printHashes(HashListType hList, String spacing) {
        boolean printed = false;
        for (HashType h : hList.getHashes()) {
            if (h.getSimpleHashValue() != null) {
                System.out.print(spacing + "Hash: " + h.getSimpleHashValue().getValue());
                System.out.println(" (" + h.getType().getValue() + ")");
                printed = true;
            }
        }
        return printed;
    }
}
