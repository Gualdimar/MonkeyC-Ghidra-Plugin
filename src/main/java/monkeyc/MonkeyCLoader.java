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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this loader does.
 */
public class MonkeyCLoader extends AbstractProgramWrapperLoader {

	private static final long SECTION_UUID = 0x0000001DL;
	private static final long SECTION_HEADER = 0xD000D000L;
	private static final long SECTION_HEADER_VERSIONED = 0xD000D00DL;
	private static final long SECTION_DATA = 0xDA7ABABEL;
	private static final long SECTION_CODE = 0xC0DEBABEL;
	private static final long SECTION_EXTENDED_CODE = 0xC0DE10ADL;

	private static final long DATA_BASE_ADDR = 0x0L;
	private static final long CODE_BASE_ADDR = 0x10000000L;
	private static final long EXTENDED_CODE_BASE_ADDR = 0x50000000L;

	private static final String MONKEYC_ID = "MonkeyC:BE:32:default";

	@Override
	public String getName() {

		// Name the loader. This name must match the name of the loader in the .opinion
		// files.

		return "MonkeyC Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Examine the bytes in 'provider' to determine if this loader can load it. If
		// it
		// can load it, return the appropriate load specifications.

		if (provider.length() < 8) {
			return loadSpecs;
		}

		BinaryReader reader = new BinaryReader(provider, false);

		try {
			long firstSectionType = reader.readUnsignedInt(0);
			if (firstSectionType == SECTION_UUID || firstSectionType == SECTION_HEADER
					|| firstSectionType == SECTION_HEADER_VERSIONED) {
				LanguageCompilerSpecPair pair = new LanguageCompilerSpecPair(MONKEYC_ID, "default");
				loadSpecs.add(new LoadSpec(this, 0, pair, true));
			}
		} catch (Exception e) {
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		// Load the bytes from 'provider' into the 'program'.

		BinaryReader reader = new BinaryReader(provider, false);
		long fileLength = provider.length();
		long currentOffset = 0;

		monitor.setMessage("Loding PRG Sections...");

		while (currentOffset < fileLength) {
			if (monitor.isCancelled() || currentOffset + 8 > fileLength) {
				break;
			}

			long sectionMagic = reader.readUnsignedInt(currentOffset);
			long sectionLength = reader.readUnsignedInt(currentOffset + 4);
			long payloadOffset = currentOffset + 8;

			try {
				if (sectionMagic == SECTION_DATA) {
					log.appendMsg("Found Data Section at " + Long.toHexString(payloadOffset));

					MemoryBlockUtils.createInitializedBlock(program, false, "data",
							program.getAddressFactory().getDefaultAddressSpace().getAddress(DATA_BASE_ADDR),
							provider.getInputStream(payloadOffset), sectionLength, "Data Section", "", true, false,
							true, log, monitor);
				} else if (sectionMagic == SECTION_CODE) {
					log.appendMsg("Found Code Section at " + Long.toHexString(payloadOffset));

					MemoryBlockUtils.createInitializedBlock(program, false, "code",
							program.getAddressFactory().getDefaultAddressSpace().getAddress(CODE_BASE_ADDR),
							provider.getInputStream(payloadOffset), sectionLength, "Code Section", "", true, false,
							true, log, monitor);
				} else if (sectionMagic == SECTION_EXTENDED_CODE) {
					log.appendMsg("Found Extended Code Section at " + Long.toHexString(payloadOffset));

					long pageSize = reader.readUnsignedInt(payloadOffset);
					payloadOffset += 4;
					long pageCount = reader.readUnsignedInt(payloadOffset);
					payloadOffset += 4;

					List<Long> pageActualSizes = new ArrayList<>();
					for (long i = 0; i < pageCount; i++) {
						long actualSize = reader.readUnsignedInt(payloadOffset);
						payloadOffset += 4;
						pageActualSizes.add(actualSize);
					}

					long paddingSize = reader.readUnsignedInt(payloadOffset);
					payloadOffset += 4 + paddingSize;

					long senctionEnd = currentOffset + sectionLength + 8;
					if (payloadOffset >= senctionEnd) {
						continue;
					}

					long payloadSize = pageSize * pageCount;

					Address baseAddr = program.getAddressFactory().getDefaultAddressSpace()
							.getAddress(EXTENDED_CODE_BASE_ADDR);

					MemoryBlockUtils.createInitializedBlock(program, false, "code_extended", baseAddr,
							provider.getInputStream(payloadOffset), payloadSize, "Extended Code Section", "", true,
							false, true, log, monitor);

					String comment = "Page size: " + Long.toHexString(pageSize);
					comment += "\nNumber of pages: " + Long.toHexString(pageCount);
					program.getListing().setComment(baseAddr, CommentType.PLATE, comment);

					for (int i = 0; i < pageCount; i++) {
						comment = "Page " + i + " start";
						comment += "\nPage " + i + " actual size: " + Long.toHexString(pageActualSizes.get(i));

						String labelName = "extCode_page" + i;

						Address pageAddr = baseAddr.add(pageSize * i);

						program.getListing().setComment(pageAddr, CommentType.PRE, comment);
						program.getSymbolTable().createLabel(pageAddr, labelName, SourceType.ANALYSIS);
					}
				}
			} catch (Exception ex) {
				log.appendMsg("Error creating memory block:  " + ex.getMessage());
			}

			currentOffset += 8 + sectionLength;
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// If this loader has custom options, validate them here. Not all options
		// require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
