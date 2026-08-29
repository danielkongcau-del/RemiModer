// Targeted, read-only evidence exporter for UnifiedCapture P1.
// @category UnifiedCapture

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ExportProbeTargets extends GhidraScript {
    private static String bytesHex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte value : bytes) out.append(String.format("%02x", value & 0xff));
        return out.toString();
    }

    private static String joinAddresses(Address[] addresses, Address imageBase) {
        StringBuilder out = new StringBuilder();
        for (Address address : addresses) {
            if (out.length() != 0) out.append(',');
            out.append(address.subtract(imageBase));
        }
        return out.toString();
    }

    private String incoming(Address address, Address imageBase) {
        StringBuilder out = new StringBuilder();
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(address);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (!ref.getFromAddress().isMemoryAddress()) continue;
            if (out.length() != 0) out.append(',');
            out.append(ref.getFromAddress().subtract(imageBase));
        }
        return out.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("targets.tsv output.tsv module-alias required");
        File input = new File(args[0]);
        File output = new File(args[1]);
        String wantedModule = args[2];
        Address imageBase = currentProgram.getImageBase();
        List<String[]> targets = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(input))) {
            String line;
            boolean header = true;
            while ((line = reader.readLine()) != null) {
                if (header) { header = false; continue; }
                String[] fields = line.split("\\t", -1);
                if (fields.length == 7 && fields[0].equals(wantedModule)) targets.add(fields);
            }
        }
        output.getParentFile().mkdirs();
        try (PrintWriter out = new PrintWriter(new FileWriter(output))) {
            out.println("#schema\tuc.ghidra-probe-export.v1");
            out.println("#program\t" + currentProgram.getName());
            out.println("#executable_sha256\t" + currentProgram.getExecutableSHA256());
            out.println("#image_base\t" + imageBase);
            out.println("module\tfunction_id_base64\tentry_rva\truntime_begin_rva\truntime_end_rva\trole_candidate\t"
                + "instruction_rva\tbytes\tmnemonic\tflow_type\tflow_rvas\tfallthrough_rva\tincoming_reference_rvas");
            for (String[] target : targets) {
                long beginRva = Long.parseUnsignedLong(target[3]);
                long endRva = Long.parseUnsignedLong(target[4]);
                Address begin = imageBase.add(beginRva);
                Address end = imageBase.add(endRva - 1);
                AddressSet restricted = new AddressSet(begin, end);
                for (String seedText : target[6].split(",")) {
                    Address seed = imageBase.add(Long.parseUnsignedLong(seedText));
                    if (currentProgram.getListing().getInstructionAt(seed) == null) {
                        DisassembleCommand command = new DisassembleCommand(seed, restricted, true);
                        if (!command.applyTo(currentProgram, monitor)) {
                            printerr("disassembly failed at " + seed + ": " + command.getStatusMsg());
                        }
                    }
                }
                InstructionIterator instructions = currentProgram.getListing().getInstructions(restricted, true);
                while (instructions.hasNext()) {
                    Instruction ins = instructions.next();
                    Address fallthrough = ins.getFallThrough();
                    out.print(target[0]); out.print('\t');
                    out.print(target[1]); out.print('\t');
                    out.print(target[2]); out.print('\t');
                    out.print(target[3]); out.print('\t');
                    out.print(target[4]); out.print('\t');
                    out.print(target[5]); out.print('\t');
                    out.print(ins.getAddress().subtract(imageBase)); out.print('\t');
                    out.print(bytesHex(ins.getBytes())); out.print('\t');
                    out.print(ins.getMnemonicString()); out.print('\t');
                    out.print(ins.getFlowType().toString().replace('\t', ' ')); out.print('\t');
                    out.print(joinAddresses(ins.getFlows(), imageBase)); out.print('\t');
                    out.print(fallthrough == null ? "" : Long.toUnsignedString(fallthrough.subtract(imageBase))); out.print('\t');
                    out.println(incoming(ins.getAddress(), imageBase));
                }
            }
        }
        println("ExportProbeTargets: " + targets.size() + " ranges -> " + output);
    }
}
