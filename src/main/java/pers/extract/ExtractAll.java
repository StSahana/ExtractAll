package pers.extract;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.junit.Test;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;

import pers.extract.util.PcapMergeUtil;

public class ExtractAll {

	final String BASE_PATH = "src/main/resources/";
	static final String OUTPUT_FILE_TYPE = ".json";
	static final String INPUT_FILE_TYPE = ".pcap";

	public ExtractAll() {
		File file = new File("src/main/resources/log.txt");
		if (file.exists())
			file.delete();
	}

	/**
	 * 遍历文件下所有的pcap文件
	 * 
	 * @param inputPath
	 * @param outputPath
	 */
	public void goThroughFile(String inputPath, String outputPath) {
		File file = new File(BASE_PATH + inputPath);
		for (String s : file.list()) {
			if (new File(BASE_PATH + inputPath + s).isDirectory()) {
				if (!new File(BASE_PATH + outputPath + s + "/").exists()) {
					new File(BASE_PATH + outputPath + s + "/").mkdir();
				}
				goThroughFile(inputPath + s + "/", outputPath + s + "/");
			} else {
				String fileName = s.replace(".pcap", "");
				extractFromPcap(fileName, BASE_PATH + inputPath, BASE_PATH + outputPath);
			}
		}
		
	}

	/**
	 * 从pcap文件中提取数据
	 */
	public void extractFromPcap(String fileName, String inputPath, String outputPath) {
		PcapHandle handle = null;
		Packet packet;
		int count = 0;
		List<JSONObject> mapArray = new ArrayList<JSONObject>();
		try {
			Map<Integer, Integer> merge = new PcapMergeUtil().merge(inputPath + fileName + INPUT_FILE_TYPE);
			List<Integer>[] typeList = new List[new HashSet(merge.values()).size()];// 类型列表
			List<TcpPacket>[] payLoadList = new List[typeList.length];
			handle = Pcaps.openOffline(inputPath + fileName + INPUT_FILE_TYPE);
			while ((packet = handle.getNextPacket()) != null) {
				count++;
				if (!merge.keySet().contains(count)) {// merge中已进行了一次筛选，空数据被过滤
					continue;
				}
				TcpPacket tcpPacket = packet.get(TcpPacket.class);
				// if (tcpPacket != null && tcpPacket.getPayload() != null &&
				// tcpPacket.toString().contains("HTTP)")) {
				if (tcpPacket != null && tcpPacket.getPayload() != null) {
					int type = merge.get(count);
					if (typeList[type] == null)
						typeList[type] = new ArrayList<Integer>();
					typeList[type].add(count);
					if (payLoadList[type] == null)
						payLoadList[type] = new ArrayList<TcpPacket>();
					payLoadList[type].add(tcpPacket);
				}
			}

			for (int i = 0; i < payLoadList.length; i++) {

				payLoadList[i].sort(new Comparator<TcpPacket>() {
					@Override
					public int compare(TcpPacket o1, TcpPacket o2) {
						return o1.getHeader().getSequenceNumberAsLong() - o2.getHeader().getSequenceNumberAsLong() > 0
								? 1 : -1;
					}
				});
			}
			for (int i = 0; i < payLoadList.length; i++) {
				// 数据包整合
				byte[] payload = null;
				for (int m = 0; m < typeList[i].size(); m++) {
					payload = this.mergeByte(payload, payLoadList[i].get(m).getPayload().getRawData());
				}
				String payLoad = new String(payload, "UTF-8");
				JSONObject element = null;

				if (payLoad.contains("GET ")) {// get����
					element = extractFromGet(typeList[i].get(typeList[i].size() - 1), payLoad, typeList[i]);
				} else if (payLoad.contains("POST ")) {// POST����
					element = extractFromPost(typeList[i].get(typeList[i].size() - 1), payLoad, typeList[i]);
				} else if (payload.length > 4 && payLoad.substring(0, 4).equals("HTTP")) {
					// element =
					// extractFromResponse(typeList[i].get(typeList[i].size()-1),
					// payLoad,typeList[i]);
				} else {
					// element =
					// extractFromPayload(typeList[i].get(typeList[i].size()-1),
					// payLoad,typeList[i]);
				}
				if (element != null)
					mapArray.add(element);
			}

		} catch (NotOpenException e) {
			e.printStackTrace();
		} catch (PcapNativeException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch(Exception e){
			e.printStackTrace();
		}finally {
			System.out.println("已处理" + inputPath + fileName + INPUT_FILE_TYPE + "\t\t" + count + "条数据报");
			writeJson(mapArray, outputPath + fileName + "_result" + OUTPUT_FILE_TYPE);
			// writeJson(JSON.toJSONString(mapArray,true),outputPath+fileName+"_result"+OUTPUT_FILE_TYPE);
			if (handle != null)
				handle.close();
		}

	}

	/**
	 * 合并两个byte数组
	 * 
	 * @param rawData
	 * @param payload
	 * @return
	 */
	private byte[] mergeByte(byte[] b1, byte[] b2) {
		if (b1 == null) {
			return b2;
		} else if (b2 == null) {
			return b1;
		}
		byte[] b3 = new byte[b1.length + b2.length];
		System.arraycopy(b1, 0, b3, 0, b1.length);
		System.arraycopy(b2, 0, b3, b1.length, b2.length);
		return b3;
	}

	/**
	 * 写入文件
	 */
	public void writeJson(List json, String filePath) {
		if (json.size() > 0) {
			File file = new File(filePath);
			BufferedWriter br = null;
			try {
				file.createNewFile();
				br = new BufferedWriter(new FileWriter(file));
				JSON.writeJSONString(br, json, SerializerFeature.PrettyFormat);
				// br.write(json);
				br.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

	/**
	 * 处理TCP传送的数据（非GET post response）
	 * 
	 * @param count
	 * @param payLoad
	 * @param typeList
	 * @param header
	 * @return
	 */
	JSONObject extractFromPayload(int count, String payLoad, List<Integer> typeList, JSONObject header) {
		String body = payLoad;
		JSONObject bodyJson = new JSONObject();
		try {
			bodyJson = JSON.parseObject(body);
		} catch (Exception e) {
			if (header != null && header.containsKey("Content-Type")) {
				String contentType = header.getString("Content-Type");
				if ("application/x-www-form-urlencoded".equals(contentType)) {
					for (String p : body.split("&")) {
						if (p.split("=").length > 1) {
							bodyJson.put(p.split("=")[0], p.split("=")[1]);
						}
					}
				} else if (contentType.contains("multipart/form-data")) {

					String boundary = "--" + contentType.split(";")[1].split("=")[1].replace("*", "\\*") + "\r\n";
					for (String block : body.split(boundary)) {
						// log(block);
						if (block.trim().equals("")) {
							continue;
						}
						JSONObject file = new JSONObject();
						String[] split = block.split("\r\n\r\n");
						String line = split[0];
						String key = "";
						if (line.contains("name")) {
							int index = line.indexOf("name") + 6;
							key = line.substring(index, line.indexOf("\"", index));
							if (line.contains("filename")) {
								index = line.indexOf("filename") + 10;
								file.put("filename", line.substring(index, line.indexOf("\"", index)));
							}
						}

						if (file.size() > 0) {
							file.put("data", split[1].trim());
							bodyJson.put(key, file);
						} else {
							bodyJson.put(key, split[1].trim());
						}
					}
				}
//				log(JSON.toJSONString(bodyJson, true));
			} else {
				for (String p : body.split("&")) {
					if (p.split("=").length > 1) {
						bodyJson.put(p.split("=")[0], p.split("=")[1]);
					}
				}

				if (bodyJson.size() == 0) {
					String log = "";
					log += "------------提取失败start------------\n";
					log += body + "\n";
					log += "-------------提取失败end-------------\n";
					this.log(log);
				}

			}
		}

		return bodyJson;
	}

	/**
	 * 写LOG
	 * 
	 * @param log
	 */
	private void log(String log) {
		File file = new File("src/main/resources/log.txt");
		BufferedWriter br = null;
		try {
			if (!file.exists())
				file.createNewFile();
			br = new BufferedWriter(new FileWriter(file, true));
			br.append(log + "\n");
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

	/**
	 * 处理HTTP RESPONSE
	 * 
	 * @param count
	 * @param payLoad
	 * @param typeList
	 * @return
	 */
	JSONObject extractFromResponse(int count, String payLoad, List<Integer> typeList) {
		return null;
	}

	/**
	 * 处理POST
	 * 
	 * @param count
	 * @param payLoad
	 * @param typeList
	 * @return
	 */
	JSONObject extractFromPost(int count, String payLoad, List<Integer> typeList) {
		JSONObject json = new JSONObject(true);
		payLoad = payLoad.substring(payLoad.indexOf("POST ") + 5);// 去除http体前的冗余信息
		JSONObject header = new JSONObject();
		String s = payLoad.substring(payLoad.indexOf("\r\n") + 2, payLoad.indexOf("\r\n\r\n")+4);
		for (String temp : s.split("\r\n")) {
			header.put(temp.substring(0, temp.indexOf(":")).toLowerCase(), temp.substring(temp.indexOf(":") + 2));
		}
		if(!header.containsKey("host")){
			return null;
		}
		if(header.getString("host").contains("pingma.qq.com")||header.getString("host").contains("sasdk.3g.qq.com")){
			System.out.println(count);
		}
		
		String url= header.getString("host") + payLoad.substring(0, payLoad.indexOf(" "));
		String body = payLoad.substring(payLoad.indexOf("\r\n\r\n") + 4);

		json.put("number", count);
		json.put("method", "GET");
		json.put("url", url);
		json.put("header", header);
		boolean flag = false;// 是否存在url参数或者body参数
		String temp = url.substring(url.indexOf("?") + 1);
		Map<String, String> urlParams = new HashMap<String, String>();
		for (String p : temp.split("&")) {
			if (p.split("=").length > 1) {
				urlParams.put(p.split("=")[0], p.split("=")[1]);
			}
		}
		if (urlParams.size() > 0) {
			flag = true;
			json.put("urlParams", urlParams);
		}

		JSONObject bodyJson = extractFromPayload(count, body, typeList, header);
		if (bodyJson!=null&&bodyJson.size() > 0) {
			flag = true;
			json.put("bodyParams", bodyJson);
		}

		return flag ? json : null;
	}

	/**
	 * 处理GET
	 * 
	 * @param count
	 * @param payLoad
	 * @param typeList
	 * @return
	 */
	JSONObject extractFromGet(int count, String payLoad, List<Integer> typeList) {
		payLoad = payLoad.substring(payLoad.indexOf("GET ") + 4);// 去除http体前的冗余信息
		JSONObject json = new JSONObject(true);
		String s = payLoad.substring(payLoad.indexOf("\r\n") + 2, payLoad.indexOf("\r\n\r\n")+4);
//		String s = payLoad.substring(payLoad.indexOf("\r\n") + 2, payLoad.indexOf("\r\n\r\n"));
		JSONObject header = new JSONObject();
		for (String temp : s.split("\r\n")) {
			header.put(temp.split(":")[0].toLowerCase(), temp.split(":")[1]);
		}
		if(!header.containsKey("host")){
			return null;
		}
		if(header.getString("host").contains("pingma.qq.com")||header.getString("host").contains("sasdk.3g.qq.com")){
			System.out.println(count);
		}
		
		String url = header.getString("host") + payLoad.substring(0, payLoad.indexOf(" "));
		String body = payLoad.substring(payLoad.indexOf("\r\n\r\n") + 4);

		json.put("number", count);
		json.put("method", "GET");
		json.put("url", url);
		json.put("header", header);
		String temp = url.substring(url.indexOf("?") + 1);
		Map<String, String> urlParams = new HashMap<String, String>();
		for (String p : temp.split("&")) {
			if (p.split("=").length > 1) {
				urlParams.put(p.split("=")[0], p.split("=")[1]);
			}
		}
		if (urlParams.size() > 0) {
			json.put("urlParams", urlParams);
			return json;
		} else {
			return null;
		}
	}

}
