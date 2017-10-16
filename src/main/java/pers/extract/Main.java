package pers.extract;

import java.io.IOException;

import org.pcap4j.core.PcapNativeException;

public class Main {
	final String BASE_PATH = "src/main/resources/";
	static final String INPUT_PATH = "rawData/";
	static final String OUTPUT_PATH = "results/";
	static int i = 1;

	public static void main(String[] args) throws IOException, PcapNativeException {
		new ExtractAll().goThroughFile(INPUT_PATH, OUTPUT_PATH);
	}

}
