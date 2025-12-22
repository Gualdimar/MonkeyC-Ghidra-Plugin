/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package monkeyc;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class MonkeyCAnalyzer extends AbstractAnalyzer {

	private static final long DATA_BASE_ADDR = 0x0L;
	private static final long CODE_BASE_ADDR = 0x10000000L;
	private static final long EXTENDED_CODE_BASE_ADDR = 0x50000000L;

	private static final int DATA_STRING = 0x01;

	private static final int DATA_CONTAINER = 0x03;
	private static final long HASHMAP_MAGIC = 0xABCDABCDL;

	private static final int DATA_CLASS_V1 = 0xC1;
	private static final int DATA_CLASS_V2 = 0xC2;

	private static final long STATICS_ID = 0x800002L;

	private Map<Long, String> apiSymbolMap = new HashMap<>();

	private Map<Long, SymbolInfo> symbolIdToSymbolInfoMap = new HashMap<>();
	private Map<Long, SymbolInfo> offsetToSymbolInfoMap = new HashMap<>();

	private Namespace globalSymbolsNamespace = null;

	private int dataEtnryCount = 0;
	private int symbolCount = 0;
	private int classCount = 0;
	private int moduleCount = 0;
	private int funcCount = 0;
	private int varCount = 0;
	private int stringCount = 0;
	private int containerCount = 0;

	public MonkeyCAnalyzer() {

		// Name the analyzer and give it a description.

		super("MonkeyC Analyzer", "Analyze PRG file structures", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);

		setDefaultEnablement(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Examine 'program' to determine of this analyzer should analyze it. Return
		// true
		// if it can.

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// If this analyzer has custom options, register them here

		// options.registerOption("Option name goes here", false, null, "Option
		// description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Perform analysis when things get added to the 'program'. Return true if the
		// analysis succeeded.

		registerFieldTypeEnum(program);
		loadApiSymbols(program, log);
		disassembleAllCode(program, monitor, CODE_BASE_ADDR);
		disassembleAllCode(program, monitor, EXTENDED_CODE_BASE_ADDR);
		parseDataSection(program, monitor, log);
		analyzeCodeReferences(program, monitor, CODE_BASE_ADDR);
		analyzeCodeReferences(program, monitor, EXTENDED_CODE_BASE_ADDR);

		return true;
	}

	private void registerFieldTypeEnum(Program program) {
		DataTypeManager dtm = program.getDataTypeManager();

		EnumDataType typeEnum = new EnumDataType("VM_FieldType", 1);

		typeEnum.add("TYPE_NULL", 0);
		typeEnum.add("TYPE_INT", 1);
		typeEnum.add("TYPE_FLOAT", 2);
		typeEnum.add("TYPE_STRING", 3);
		typeEnum.add("TYPE_OBJECT", 4);
		typeEnum.add("TYPE_ARRAY", 5);
		typeEnum.add("TYPE_METHOD", 6);
		typeEnum.add("TYPE_CLASS", 7);
		typeEnum.add("TYPE_SYMBOL", 8);
		typeEnum.add("TYPE_BOOLEAN", 9);
		typeEnum.add("TYPE_MODULE", 10);
		typeEnum.add("TYPE_HASH", 11);
		typeEnum.add("TYPE_LONG", 14);
		typeEnum.add("TYPE_DOUBLE", 15);
		typeEnum.add("TYPE_CHAR", 19);
		typeEnum.add("TYPE_BYTEARRAY", 20);

		dtm.addDataType(typeEnum, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private void loadApiSymbols(Program program, MessageLog log) {
		apiSymbolMap.clear();

		try {
			File apiFile = Application.getModuleDataFile("MonkeyC", "api.symbols").getFile(false);
			if (!apiFile.exists()) {
				log.appendMsg("Error: api.symbols not found in data directory.");
				return;
			}

			DataTypeManager dtm = program.getDataTypeManager();
			EnumDataType apiSymbolEnum = new EnumDataType("VM_Symbols", 4);

			List<String> lines = Files.readAllLines(apiFile.toPath());

			for (int i = 1; i < lines.size(); i++) {
				String line = lines.get(i).trim();
				if (line.isEmpty()) {
					continue;
				}

				String[] parts = line.split("=");

				if (parts.length >= 2) {
					String idStr = parts[0];
					String rawName = parts[1];

					try {
						long id = Long.decode(idStr);
						String sanitizedName = rawName.replace("<", "_").replace(">", "_");
						String enumName = "API_" + sanitizedName;
						apiSymbolMap.put(id, rawName);
						apiSymbolEnum.add(enumName, id);
					} catch (NumberFormatException e) {
						log.appendMsg("Skipping incalid ID on line " + (i + 1) + ": " + idStr);
					}
				}
			}

			dtm.addDataType(apiSymbolEnum, DataTypeConflictHandler.REPLACE_HANDLER);

			log.appendMsg("Loaded " + apiSymbolMap.size() + " API symbols");
		} catch (Exception e) {
			log.appendMsg("Exception loading api.symbols: " + e.getMessage());
			Msg.error(this, "Failed to load api.symbols", e);
		}
	}

	private void disassembleAllCode(Program program, TaskMonitor monitor, long baseAddr) {
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address codeStart = defaultSpace.getAddress(baseAddr);

		MemoryBlock codeBlock = program.getMemory().getBlock(codeStart);

		if (codeBlock == null) {
			return;
		}

		Address currentAddr = codeBlock.getStart();
		Address endAddr = codeBlock.getEnd();

		monitor.setMessage("Disassembling Code Section...");

		while (currentAddr.compareTo(endAddr) < 0) {
			if (monitor.isCancelled()) {
				break;
			}

			if (program.getListing().getInstructionAt(currentAddr) == null) {
				DisassembleCommand disCmd = new DisassembleCommand(currentAddr, null, true);
				disCmd.applyTo(program, monitor);
			}

			ghidra.program.model.listing.Instruction instr = program.getListing().getInstructionAt(currentAddr);
			if (instr != null) {
				currentAddr = currentAddr.add(instr.getLength());
			} else {
				currentAddr = currentAddr.add(1);
			}
		}
	}

	private void parseDataSection(Program program, TaskMonitor monitor, MessageLog log) {
		Memory mem = program.getMemory();
		Address dataBaseAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(DATA_BASE_ADDR);
		MemoryBlock dataBlock = mem.getBlock(dataBaseAddr);

		if (dataBlock == null) {
			log.appendMsg("Error: Data block not found at " + dataBaseAddr);
			return;
		}

		try {
			globalSymbolsNamespace = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(),
					"_GlobalSymbols", SourceType.ANALYSIS);

			MemoryByteProvider provider = new MemoryByteProvider(mem, dataBlock.getStart());
			BinaryReader reader = new BinaryReader(provider, false);

			long limit = dataBlock.getSize();
			long currentOffset = 0;

			monitor.setMessage("Parsing Data Section...");

			while (currentOffset < limit) {
				if (monitor.isCancelled()) {
					break;
				}

				int tag = reader.readUnsignedByte(currentOffset);
				long entryStartOffset = currentOffset;
				Address tagAddr = dataBaseAddr.add(entryStartOffset);

				currentOffset += 1;

				if (tag == DATA_STRING) {
					int len = reader.readUnsignedShort(currentOffset);

					Address lenAddr = dataBaseAddr.add(entryStartOffset + 1);
					program.getListing().createData(tagAddr, new ByteDataType(), 1);
					program.getListing().setComment(tagAddr, CommentType.EOL, "String");
					program.getListing().createData(lenAddr, new ShortDataType(), 2);
					program.getListing().setComment(lenAddr, CommentType.EOL, "Length");

					currentOffset += 2;

					String symbolName = "s_" + Long.toHexString(entryStartOffset);
					program.getSymbolTable().createLabel(tagAddr, symbolName, SourceType.ANALYSIS);

					Address strAddr = dataBaseAddr.add(currentOffset);
					DataType strType = new TerminatedStringDataType();
					program.getListing().createData(strAddr, strType, len + 1);

					currentOffset += len + 1;
					stringCount++;
				} else if (tag == DATA_CONTAINER) {
					program.getListing().createData(tagAddr, new ByteDataType(), 1);
					program.getListing().setComment(tagAddr, CommentType.EOL, "Container");
					long totalLen = reader.readUnsignedInt(currentOffset);
					Address totalLenAddr = dataBaseAddr.add(currentOffset);
					program.getListing().createData(totalLenAddr, new DWordDataType(), 4);
					program.getListing().setComment(totalLenAddr, CommentType.EOL, "Length");
					currentOffset += 4;

					long endOfContainerOffset = entryStartOffset + 1 + 4 + totalLen;

					long magic = reader.readUnsignedInt(currentOffset);
					Address magicAddr = dataBaseAddr.add(currentOffset);
					program.getListing().createData(magicAddr, new DWordDataType(), 4);
					program.getListing().setComment(magicAddr, CommentType.EOL, "Magic");
					currentOffset += 4;

					if (magic == HASHMAP_MAGIC) {
						String symbolName = "Hashmap_" + Long.toHexString(entryStartOffset);
						program.getSymbolTable().createLabel(tagAddr, symbolName, SourceType.ANALYSIS);

						long strPortionLen = reader.readUnsignedInt(currentOffset);
						program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
						program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL,
								"String array length");
						currentOffset += 4;

						long endOfStrings = currentOffset + strPortionLen;

						while (currentOffset < endOfStrings) {
							int sLen = reader.readUnsignedShort(currentOffset);
							program.getListing().createData(dataBaseAddr.add(currentOffset), new ShortDataType(), 2);
							program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL,
									"Sting length");
							currentOffset += 2;

							Address strAddr = dataBaseAddr.add(currentOffset);
							DataType strType = new TerminatedStringDataType();
							program.getListing().createData(strAddr, strType);

							currentOffset += sLen;
						}
					} else {
						program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
						program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL,
								"Array length");
						currentOffset += 4;

						int arrayType = reader.readByte(currentOffset);
						Address typeAddr = dataBaseAddr.add(currentOffset);

						DataType fieldTypeEnum = program.getDataTypeManager().getDataType(CategoryPath.ROOT,
								"VM_FieldType");
						if (fieldTypeEnum != null) {
							program.getListing().createData(typeAddr, fieldTypeEnum, 1);
						} else {
							program.getListing().createData(typeAddr, new ByteDataType(), 1);
						}

						program.getListing().setComment(typeAddr, CommentType.EOL, "Array type");

						String typeName = getTypeName(arrayType);

						program.getSymbolTable().createLabel(tagAddr,
								"Array_" + typeName + "_" + Long.toHexString(entryStartOffset), SourceType.ANALYSIS);
						currentOffset += 1;
					}

					currentOffset = endOfContainerOffset + 1;
					containerCount++;
				} else if (tag == DATA_CLASS_V1 || tag == DATA_CLASS_V2) {
					currentOffset = parseClassDefinition(program, monitor, reader, entryStartOffset, tag);
					classCount++;
				} else {
					log.appendMsg("Unknown Tag " + Integer.toHexString(tag) + " at offset "
							+ Long.toHexString(currentOffset));
					break;
				}

				dataEtnryCount++;
			}

			log.appendMsg("Found  " + dataEtnryCount + " entries in Data Section:");
			log.appendMsg("\t* " + symbolCount + " symbols");
			log.appendMsg("\t* " + classCount + " classes");
			log.appendMsg("\t* " + moduleCount + " modules");
			log.appendMsg("\t* " + funcCount + " functions");
			log.appendMsg("\t* " + varCount + " variables");
			log.appendMsg("\t* " + stringCount + " strings");
			log.appendMsg("\t* " + containerCount + " containers");
		} catch (Exception e) {
			log.appendMsg("Error parsing Data Section: " + e.getMessage());
			e.printStackTrace();
		}
	}

	private long parseClassDefinition(Program program, TaskMonitor monitor, BinaryReader reader, long startOffset,
			int tag) throws Exception {
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address dataBaseAddr = defaultSpace.getAddress(DATA_BASE_ADDR);
		long currentOffset = startOffset;

		Address magicAddr = dataBaseAddr.add(currentOffset);
		program.getListing().createData(magicAddr, new DWordDataType(), 4);
		currentOffset += 4;

		long moduleId = 0;
		long parentModuleId = 0;
		int fieldsCount = 0;

		if (tag == DATA_CLASS_V1) {
			program.getListing().setComment(magicAddr, CommentType.EOL, "Magic V1");

			// extendsOffset
			program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "extendsOffset");
			currentOffset += 4;

			// staticsOffset
			program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "staticsOffset");
			currentOffset += 4;

			// parentModuleId
			parentModuleId = reader.readUnsignedInt(currentOffset);
			program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "parentModuleId");
			currentOffset += 4;

			// moduleId
			moduleId = reader.readUnsignedInt(currentOffset);
			program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "moduleId");
			currentOffset += 4;

			// appType
			program.getListing().createData(dataBaseAddr.add(currentOffset), new WordDataType(), 2);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "appType");
			currentOffset += 2;

			// fieldsCount
			fieldsCount = reader.readUnsignedByte(currentOffset);
			program.getListing().createData(dataBaseAddr.add(currentOffset), new ByteDataType(), 1);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "fieldsCount");
			currentOffset += 1;
		} else {
			program.getListing().setComment(magicAddr, CommentType.EOL, "Magic V2");

			int flags = reader.readUnsignedByte(currentOffset);
			program.getListing().createData(dataBaseAddr.add(currentOffset), new ByteDataType(), 1);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "flags");
			currentOffset += 1;

			if ((flags & 1) != 0) {
				// extendsOffset
				program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
				program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "extendsOffset");
				currentOffset += 4;
			}

			if ((flags & 2) != 0) {
				// staticsOffset
				program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
				program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "staticsOffset");
				currentOffset += 4;
			}

			if ((flags & 4) != 0) {
				// parentModuleId
				parentModuleId = reader.readUnsignedInt(currentOffset);
				program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
				program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "parentModuleId");
				currentOffset += 4;
			}

			if ((flags & 8) != 0) {
				// moduleId
				moduleId = reader.readUnsignedInt(currentOffset);
				program.getListing().createData(dataBaseAddr.add(currentOffset), new DWordDataType(), 4);
				program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "moduleId");
				currentOffset += 4;
			}

			// appType
			program.getListing().createData(dataBaseAddr.add(currentOffset), new WordDataType(), 2);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "appType");
			currentOffset += 2;

			// fieldsCount
			fieldsCount = reader.readUnsignedShort(currentOffset);
			program.getListing().createData(dataBaseAddr.add(currentOffset), new WordDataType(), 2);
			program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL, "fieldsCount");
			currentOffset += 2;
		}

		GhidraClass currentClass;
		SymbolInfo symbolInfo;

		if (offsetToSymbolInfoMap.containsKey(startOffset)) {
			symbolInfo = offsetToSymbolInfoMap.get(startOffset);
		} else {
			symbolInfo = new SymbolInfo(moduleId, startOffset);
		}

		symbolInfo.moduleId = moduleId;
		symbolInfo.parentId = parentModuleId;

		if (symbolInfo.ghidraClass != null) {
			currentClass = symbolInfo.ghidraClass;
		} else {
			String className;
			if (symbolInfo.symbolId != 0) {
				className = resolveSymbolName(symbolInfo.symbolId, "Class_" + Long.toHexString(symbolInfo.symbolId));
			} else if (moduleId != 0) {
				className = resolveSymbolName(moduleId, "Class_" + Long.toHexString(moduleId));
				symbolInfo.symbolId = moduleId;
			} else {
				className = "Class_at_" + Long.toHexString(startOffset);
			}

			currentClass = program.getSymbolTable().createClass(null, className, SourceType.ANALYSIS);
			symbolInfo.name = className;
			symbolInfo.ghidraClass = currentClass;
		}

		for (int i = 0; i < fieldsCount; i++) {
			long fieldKey = reader.readUnsignedInt(currentOffset);
			long symbolVal = (fieldKey >> 8) & 0xFFFFFF;
			Address keyAddr = dataBaseAddr.add(currentOffset);
			program.getListing().createData(keyAddr, new DWordDataType(), 4);
			program.getListing().setComment(keyAddr, CommentType.EOL, "Symbol: " + Long.toHexString(symbolVal));
			currentOffset += 4;

			int fieldType = 0;
			long fieldValue = 0;
			Address valueAddr = dataBaseAddr.add(currentOffset);

			if (tag == DATA_CLASS_V1) {
				fieldType = (int) (fieldKey & 0xF);

				fieldValue = reader.readUnsignedInt(currentOffset);
			} else {
				fieldType = reader.readUnsignedByte(currentOffset);
				program.getListing().createData(dataBaseAddr.add(currentOffset), new ByteDataType(), 1);
				program.getListing().setComment(dataBaseAddr.add(currentOffset), CommentType.EOL,
						"Type: " + getTypeName(fieldType));
				currentOffset += 1;

				valueAddr = dataBaseAddr.add(currentOffset);
				fieldValue = reader.readUnsignedInt(currentOffset);
			}

			DataType specificType = new DWordDataType();

			switch (fieldType) {
			case 1: // int
			case 8: // symbol
				specificType = new IntegerDataType();
				break;
			case 2: // float
				specificType = new FloatDataType();
				break;
			case 9: // boolean
				valueAddr = dataBaseAddr.add(currentOffset + 3);
				specificType = new BooleanDataType();
				break;
			case 19: // char
				specificType = new IntegerDataType();
				break;
			case 6: // method
			case 7: // class
			case 10: // module
			case 3: // string
			case 5: // array
			case 20: // bytearray
			case 11: // hash
				specificType = new DWordDataType();
				break;
			case 14: // long
			case 15: // double
				specificType = new DWordDataType();
				break;
			}

			program.getListing().createData(valueAddr, specificType, 4);
			program.getListing().setComment(valueAddr, CommentType.EOL, "Value: " + Long.toHexString(fieldValue));
			currentOffset += 4;

			String prefix = "var_";
			switch (fieldType) {
			case 1: // int
				prefix = "int_";
				break;
			case 2: // float
				prefix = "float_";
				break;
			case 8: // symbol
				prefix = "symbol_";
				break;
			case 9: // boolean
				prefix = "bool_";
				break;
			case 19: // char
				prefix = "char_";
				break;
			case 6: // method
				prefix = "func_";
				break;
			case 7: // class
				prefix = "Class_";
				break;
			case 10: // module
				prefix = "Module_";
				break;
			case 3: // string
				prefix = "str_";
				break;
			case 5: // array
				prefix = "array_";
				break;
			case 20: // bytearray
				prefix = "bytearray_";
				break;
			case 11: // hash
				prefix = "hash_";
				break;
			case 14: // long
				prefix = "long_";
				break;
			case 15: // double
				prefix = "double_";
				break;
			}

			String memberName = prefix + resolveSymbolName(symbolVal, Long.toHexString(symbolVal));
			SymbolInfo fieldlInfo = new SymbolInfo(symbolVal, fieldValue);
			fieldlInfo.name = memberName;

			if (fieldType == 7 || fieldType == 10) {
				long targetOffset = fieldValue;
				Address targetAddr = dataBaseAddr.add(targetOffset);
				Address staticsAddr = null;
				GhidraClass childClass = null;
				Symbol referenceName = null;

				if (moduleId != STATICS_ID) {
					if (fieldType == 10) {
						targetOffset = symbolIdToSymbolInfoMap.get(fieldValue).offset;
						targetAddr = dataBaseAddr.add(targetOffset);
						moduleCount++;
					}

					childClass = program.getSymbolTable().createClass(currentClass, memberName, SourceType.ANALYSIS);
					referenceName = program.getSymbolTable().createLabel(targetAddr, "_def", childClass,
							SourceType.ANALYSIS);
					program.getSymbolTable().createLabel(keyAddr, "_ref_" + currentClass.getName(), childClass,
							SourceType.ANALYSIS);

					if (offsetToSymbolInfoMap.containsKey(targetOffset)) {
						SymbolInfo staticClass = offsetToSymbolInfoMap.get(targetOffset);
						if (staticClass.staticsAddr != null) {
							program.getSymbolTable().createLabel(staticClass.staticsAddr, "_ref_statics", childClass,
									SourceType.ANALYSIS);
						}
					}
				} else {
					referenceName = program.getSymbolTable().createLabel(targetAddr, memberName, currentClass,
							SourceType.ANALYSIS);
					staticsAddr = keyAddr;
				}

				fieldlInfo.staticsAddr = staticsAddr;
				fieldlInfo.ghidraClass = childClass;
				fieldlInfo.offset = targetOffset;

				Reference ref = program.getReferenceManager().addMemoryReference(valueAddr, targetAddr, RefType.DATA,
						SourceType.ANALYSIS, 0);
				program.getReferenceManager().setAssociation(referenceName, ref);
			} else if (fieldType == 6) {
				Address funcAddr = defaultSpace.getAddress(fieldValue);

				ghidra.program.model.listing.Function existingFunc = program.getFunctionManager()
						.getFunctionAt(funcAddr);
				if (existingFunc == null) {
					if (program.getMemory().getBlock(funcAddr) != null) {
						program.getFunctionManager().createFunction(memberName, currentClass, funcAddr,
								new AddressSet(funcAddr), SourceType.ANALYSIS);
					} else {
						program.getSymbolTable().createLabel(keyAddr, memberName, currentClass, SourceType.ANALYSIS);
					}
				} else {
					try {
						program.getSymbolTable().createLabel(funcAddr, memberName, currentClass, SourceType.ANALYSIS);
					} catch (Exception e) {
					}
				}
				program.getReferenceManager().addMemoryReference(valueAddr, funcAddr, RefType.DATA, SourceType.ANALYSIS,
						0);
				funcCount++;
			} else {
				program.getSymbolTable().createLabel(keyAddr, memberName, currentClass, SourceType.ANALYSIS);
				fieldlInfo.offset = keyAddr.getOffset();
				varCount++;
			}

			symbolIdToSymbolInfoMap.put(fieldlInfo.symbolId, fieldlInfo);
			offsetToSymbolInfoMap.put(fieldlInfo.offset, fieldlInfo);

			program.getSymbolTable().createLabel(keyAddr, "sym_" + Long.toHexString(symbolVal) + "_" + memberName,
					globalSymbolsNamespace, SourceType.ANALYSIS);

			symbolCount++;
		}

		return currentOffset;
	}

	private void analyzeCodeReferences(Program program, TaskMonitor monitor, long baseAddr) {
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address codeStart = defaultSpace.getAddress(baseAddr);
		Address dataStart = defaultSpace.getAddress(DATA_BASE_ADDR);
		EquateTable equateTable = program.getEquateTable();
		InstructionIterator instructions = program.getListing().getInstructions(codeStart, true);

		monitor.setMessage("Analyzing Code References...");

		while (instructions.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			Instruction instr = instructions.next();
			String mnemonic = instr.getMnemonicString().toUpperCase();

			if (mnemonic.equals("SPUSH") || mnemonic.equals("GETSELFV") || mnemonic.equals("GETMV")
					|| mnemonic.equals("GETLOCALV") || mnemonic.equals("GETSV")) {
				for (int i = 0; i < instr.getNumOperands(); i++) {
					if (mnemonic.equals("GETLOCALV") && i == 0) {
						continue;
					}

					boolean createRef = !(mnemonic.equals("GETMV") && i == 0);

					long symbolId = instr.getScalar(i).getValue();
					String symName = null;
					boolean isLocal = symbolIdToSymbolInfoMap.containsKey(symbolId);
					boolean isApi = apiSymbolMap.containsKey(symbolId);

					if (isLocal) {
						SymbolInfo symbolInfo = symbolIdToSymbolInfoMap.get(symbolId);
						symName = symbolInfo.name;

						if (!isApi && createRef) {
							Address refAddr = defaultSpace.getAddress(symbolInfo.offset);
							program.getReferenceManager().addMemoryReference(instr.getAddress(), refAddr, RefType.DATA,
									SourceType.ANALYSIS, i);
						}
					} else if (isApi) {
						symName = apiSymbolMap.get(symbolId);
					}

					if (symName != null) {
						try {
							Equate eq = equateTable.getEquate(symName);
							if (eq == null) {
								eq = equateTable.createEquate(symName, symbolId);
							}
							eq.addReference(instr.getAddress(), i);
						} catch (Exception e) {
						}
					}
				}
			} else if (mnemonic.equals("APUSH") || mnemonic.equals("BAPUSH") || mnemonic.equals("HPUSH")
					|| mnemonic.equals("NEWS")) {
				long offset = instr.getScalar(0).getValue();
				Address targetAddr = dataStart.add(offset);

				program.getReferenceManager().addMemoryReference(instr.getAddress(), targetAddr, RefType.DATA,
						SourceType.ANALYSIS, 0);

				if (mnemonic.equals("NEWS")) {
					Data data = program.getListing().getDataAt(targetAddr.add(3));
					String strContent = (String) data.getValue();

					if (strContent != null) {
						instr.setComment(CommentType.EOL, "String: \"" + strContent + "\"");
					}
				}
			}
		}
	}

	private String resolveSymbolName(long id, String defaultName) {
		if (apiSymbolMap.containsKey(id)) {
			return apiSymbolMap.get(id);
		}
		return defaultName;
	}

	private String getTypeName(int typeId) {
		switch (typeId) {
		case 0:
			return "NULL";
		case 1:
			return "INT";
		case 2:
			return "FLOAT";
		case 3:
			return "STRING";
		case 5:
			return "ARRAY";
		case 6:
			return "METHOD";
		case 7:
			return "CLASS";
		case 8:
			return "SYMBOL";
		case 9:
			return "BOOL";
		case 10:
			return "MODULE";
		case 11:
			return "HASH";
		case 14:
			return "LONG";
		case 15:
			return "DOUBLE";
		case 19:
			return "CHAR";
		case 20:
			return "BYTEARRAY";
		default:
			return "Type_" + typeId;
		}
	}

	private static class SymbolInfo {
		long symbolId;
		long offset;
		GhidraClass ghidraClass = null;
		Address staticsAddr = null;
		long moduleId = 0;
		long parentId = 0;
		String name = "";

		public SymbolInfo(long symbolId, long offset) {
			this.symbolId = symbolId;
			this.offset = offset;
		}
	}
}
